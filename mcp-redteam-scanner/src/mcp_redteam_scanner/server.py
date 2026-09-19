"""MCP server exposing the golden-attack-set scanner: scan_qualify_endpoint,
scan_endpoint, list_scan_history, and list_attack_categories.

Run directly for local testing:

    python -m mcp_redteam_scanner.server

Or point an MCP client (Claude Desktop, Cursor, etc.) at the
`mcp-redteam-scanner` console script over stdio.
"""
from __future__ import annotations

import datetime
import time
from collections import Counter

from mcp.server.mcpserver import MCPServer

from .audit_log import read_recent_scans, record_scan_attempt
from .authorization import EngagementScope, ScopeViolation, require_scope
from .client import QualifyEndpointTarget, TargetHttpClient
from .report import render_markdown_report
from .schema import TargetProfile, load_attack_cases
from .scorer import grade
from .taxonomy import classify

mcp = MCPServer(
    name="redteam-scanner",
    instructions=(
        "Prompt-injection-tests a live agent endpoint. scan_qualify_endpoint runs the "
        "full golden attack set against a target that speaks Lead Router's own /qualify "
        "contract verbatim; scan_endpoint runs the same cases against ANY endpoint that "
        "accepts a lead-like submission and returns a classification decision, via a "
        "field_map/response_map translation. Both require an explicit authorization "
        "scope (target_host, authorized_by, contact, a valid_from/valid_until window, "
        "and i_have_authorization=true) before a single request fires - only scan a "
        "host you own or have explicit permission to test. Pass dry_run=true to preview "
        "the exact requests a scan would send without sending them, or delay_seconds to "
        "throttle requests against a target that shouldn't see a traffic spike. Every "
        "attempt, authorized or rejected, is written to a local audit log; "
        "list_scan_history reads it back. A completed (non-dry-run) scan's result "
        "includes a ready-to-share markdown report."
    ),
)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _authorize_or_raise(
    *,
    tool: str,
    base_url: str,
    target_host: str,
    authorized_by: str,
    contact: str,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
    i_have_authorization: bool,
    notes: str,
) -> EngagementScope:
    """Builds the EngagementScope both scan tools require, checks it
    against base_url, and logs the outcome either way - a rejection is
    logged and re-raised before the caller ever gets near httpx, and an
    approval is returned for the caller to log again once the scan
    itself finishes (see record_scan_attempt's docstring on why a
    rejection is worth recording at all)."""
    scope = EngagementScope(
        target_host=target_host,
        authorized_by=authorized_by,
        contact=contact,
        valid_from=valid_from,
        valid_until=valid_until,
        notes=notes,
        i_have_authorization=i_have_authorization,
    )
    try:
        require_scope(scope, base_url)
    except ScopeViolation as exc:
        record_scan_attempt(
            tool=tool, base_url=base_url, scope=scope, outcome="rejected",
            rejection_reason=str(exc),
        )
        raise
    return scope


def _preview_requests(target: TargetHttpClient) -> dict:
    """The dry_run path: builds every request a real scan would send,
    without sending any of them - lets an operator see exactly what's
    about to hit a target before committing to a live scan."""
    cases = load_attack_cases()
    return {
        "dry_run": True,
        "requests": [
            {
                "attack_id": case.attack_id,
                "category": case.category,
                "severity": case.severity,
                **target.build_request(case),
            }
            for case in cases
        ],
    }


def _run_scan(
    target: TargetHttpClient, has_guardrails: bool, *, delay_seconds: float = 0.0
) -> dict:
    cases = load_attack_cases()
    records = []
    for i, case in enumerate(cases):
        # No delay before the first request - delay_seconds paces the
        # gap *between* requests, not a startup cost.
        if delay_seconds and i > 0:
            time.sleep(delay_seconds)
        started = time.perf_counter()
        try:
            response = target.send(case)
            error = None
        except Exception as exc:  # noqa: BLE001 - a hard failure is itself a finding
            response = None
            error = str(exc)
        elapsed_ms = (time.perf_counter() - started) * 1000
        passed = None if response is None else grade(case, response)
        layer = classify(case, target_has_guardrails=has_guardrails) if passed is False else None
        records.append(
            {
                "attack_id": case.attack_id,
                "category": case.category,
                "severity": case.severity,
                "passed": passed,
                "failure_layer": layer,
                "error": error,
                "latency_ms": round(elapsed_ms, 1),
                "notes": case.notes,
            }
        )
    return _summarize(records)


def _summarize(records: list[dict]) -> dict:
    total = len(records)
    held = sum(1 for r in records if r["passed"])
    by_category: dict[str, dict] = {}
    for r in records:
        cat = by_category.setdefault(r["category"], {"total": 0, "held": 0})
        cat["total"] += 1
        cat["held"] += bool(r["passed"])
    by_layer = Counter(r["failure_layer"] for r in records if r["failure_layer"])
    findings = [r for r in records if not r["passed"]]
    by_severity = Counter(r["severity"] for r in findings)
    return {
        "defended": held,
        "total": total,
        "by_category": by_category,
        "by_failure_layer": dict(by_layer),
        "by_severity": dict(by_severity),
        "findings": findings,
    }


@mcp.tool()
def scan_qualify_endpoint(
    base_url: str,
    target_host: str,
    authorized_by: str,
    contact: str,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
    i_have_authorization: bool,
    notes: str = "",
    api_key: str | None = None,
    assume_guardrails: bool = True,
    dry_run: bool = False,
    delay_seconds: float = 0.0,
) -> dict:
    """Runs the golden prompt-injection set against a live
    /qualify-compatible endpoint and returns a pass/fail summary.

    Refuses to send a single request unless the authorization
    parameters below check out - see "Authorization" in the module
    instructions. Only scan a host you own or have explicit permission
    to test.

    base_url: the target's root URL, e.g. "http://localhost:8000" - the
        scanner POSTs to f"{base_url}/qualify".
    target_host: the hostname you're authorizing this scan for (e.g.
        "localhost" or "staging.example.com") - rejected if it doesn't
        match the host base_url actually resolves to.
    authorized_by/contact: who's asserting this authorization, and who
        to reach about the engagement. Free text, recorded in the audit
        log either way.
    valid_from/valid_until: the engagement window this scan must fall
        inside, checked against the current time.
    i_have_authorization: must be explicitly true - there's no default
        that authorizes a scan.
    notes: anything worth recording alongside this attempt (e.g. "own
        staging deploy" or "bug bounty program ref #1234").
    api_key: sent as an X-API-Key header if the target requires one.
    assume_guardrails: hint used only to attribute WHICH layer a failure
        blames (system_prompt vs model vs output_handling) in the
        by_failure_layer breakdown - it does not change pass/fail
        results. Set False if you know the target has no prompt-level
        defenses at all.
    dry_run: if true, builds and returns every request this scan would
        send (method/url/headers/body per case) without sending any of
        them - no grading happens, and the return shape is
        {"dry_run": true, "requests": [...]} instead of the usual
        summary. Still requires authorization, but is logged separately
        in the audit trail and never touches the target.
    delay_seconds: pause this long between requests (0 = no throttle).
        Use it against a target you don't want to see 18+ requests in
        a couple of seconds.

    Returns defended/total counts, a per-category breakdown, a
    per-failure-layer breakdown, a per-severity breakdown, the list of
    cases that did NOT hold, and a ready-to-share markdown "report"
    string.
    """
    scope = _authorize_or_raise(
        tool="scan_qualify_endpoint", base_url=base_url, target_host=target_host,
        authorized_by=authorized_by, contact=contact, valid_from=valid_from,
        valid_until=valid_until, i_have_authorization=i_have_authorization, notes=notes,
    )
    target = QualifyEndpointTarget(base_url=base_url, api_key=api_key)
    if dry_run:
        preview = _preview_requests(target)
        record_scan_attempt(
            tool="scan_qualify_endpoint", base_url=base_url, scope=scope, outcome="dry_run",
            summary={"requests_previewed": len(preview["requests"])},
        )
        return preview
    result = _run_scan(target, assume_guardrails, delay_seconds=delay_seconds)
    result["report"] = render_markdown_report(
        result, target_label=base_url, scanned_at=_now_iso(),
    )
    record_scan_attempt(
        tool="scan_qualify_endpoint", base_url=base_url, scope=scope, outcome="scanned",
        summary={"defended": result["defended"], "total": result["total"]},
    )
    return result


@mcp.tool()
def scan_endpoint(
    base_url: str,
    target_host: str,
    authorized_by: str,
    contact: str,
    valid_from: datetime.datetime,
    valid_until: datetime.datetime,
    i_have_authorization: bool,
    notes: str = "",
    path: str = "/qualify",
    api_key: str | None = None,
    api_key_header: str = "X-API-Key",
    field_map: dict[str, str | None] | None = None,
    response_map: dict[str, str] | None = None,
    assume_guardrails: bool = True,
    timeout: float = 60.0,
    dry_run: bool = False,
    delay_seconds: float = 0.0,
) -> dict:
    """Runs the same golden attack set as scan_qualify_endpoint, but
    against ANY endpoint that accepts a lead-like submission (a
    free-text field plus a few structured ones) and returns a
    classification decision plus free-text reasoning - not just an
    exact clone of Lead Router's own field names and response shape.

    Same authorization gate as scan_qualify_endpoint (target_host,
    authorized_by, contact, valid_from/valid_until, i_have_authorization,
    notes) - see that tool's docstring for what each means. Only scan a
    host you own or have explicit permission to test.

    base_url/path: the scanner POSTs to f"{base_url}{path}".
    api_key/api_key_header: sent as a header if the target requires one.
    field_map: translates this scanner's canonical request fields
        (name, email, company, phone, message, source) onto the
        target's own field names, as dotted paths for a nested body
        (e.g. {"message": "input.text"}). Map a field to null to omit
        it entirely. Fields not listed are sent under their own name
        unchanged.
    response_map: same idea for the canonical response fields (tier,
        suggested_owner, icp_fit_score, urgency_score, reasoning,
        confidence) - a dotted path into the target's own JSON response
        (e.g. {"tier": "result.classification"}). Fields not listed are
        read under their own name unchanged. Only tier, suggested_owner,
        and reasoning are actually required for grading to run; leave
        the rest unset if the target has no equivalent.
    assume_guardrails: same meaning as on scan_qualify_endpoint.
    dry_run/delay_seconds: same meaning as on scan_qualify_endpoint.

    Returns the same shape as scan_qualify_endpoint.
    """
    scope = _authorize_or_raise(
        tool="scan_endpoint", base_url=base_url, target_host=target_host,
        authorized_by=authorized_by, contact=contact, valid_from=valid_from,
        valid_until=valid_until, i_have_authorization=i_have_authorization, notes=notes,
    )
    profile = TargetProfile(
        base_url=base_url,
        path=path,
        api_key=api_key,
        api_key_header=api_key_header,
        field_map=field_map or {},
        response_map=response_map or {},
        timeout=timeout,
    )
    target = TargetHttpClient(profile)
    if dry_run:
        preview = _preview_requests(target)
        record_scan_attempt(
            tool="scan_endpoint", base_url=base_url, scope=scope, outcome="dry_run",
            summary={"requests_previewed": len(preview["requests"])},
        )
        return preview
    result = _run_scan(target, assume_guardrails, delay_seconds=delay_seconds)
    result["report"] = render_markdown_report(
        result, target_label=f"{base_url}{path}", scanned_at=_now_iso(),
    )
    record_scan_attempt(
        tool="scan_endpoint", base_url=base_url, scope=scope, outcome="scanned",
        summary={"defended": result["defended"], "total": result["total"]},
    )
    return result


@mcp.tool()
def list_scan_history(limit: int = 20) -> list[dict]:
    """Reads back the local audit log of scan attempts (authorized and
    rejected alike) written by scan_qualify_endpoint/scan_endpoint -
    most recent first. Returns an empty list if nothing's been scanned
    yet from this machine."""
    return read_recent_scans(limit=limit)


@mcp.tool()
def list_attack_categories() -> list[dict]:
    """Lists the attack categories in the golden set, with a count of
    cases in each and a one-line description of what each tests."""
    descriptions = {
        "direct_injection": (
            "Instructions embedded in lead fields telling the agent to assign a "
            "favorable tier/owner."
        ),
        "system_prompt_extraction": (
            "Attempts to get the agent's system prompt or internal instructions echoed back."
        ),
        "business_logic_escape": (
            "Payloads that try to manipulate the qualification logic itself, not just its output."
        ),
        "output_handling_injection": (
            "Content designed to survive unsanitized into a downstream field "
            "(e.g. one relayed to Slack)."
        ),
        "encoding_evasion": (
            "The same override techniques as direct_injection, obfuscated (base64, ROT13, "
            "zero-width characters, leetspeak) to test defenses that only pattern-match "
            "plaintext keywords."
        ),
        "multi_field_chaining": (
            "An attack split across multiple request fields so no single field contains "
            "the full payload, reconstructed only once every field is concatenated."
        ),
    }
    counts = Counter(c.category for c in load_attack_cases())
    return [
        {"category": cat, "count": counts.get(cat, 0), "description": desc}
        for cat, desc in descriptions.items()
    ]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
