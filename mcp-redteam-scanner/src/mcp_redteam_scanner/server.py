"""MCP server exposing the golden-attack-set scanner as two tools:
scan_qualify_endpoint and list_attack_categories.

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
from .schema import TargetProfile, load_attack_cases
from .scorer import grade
from .taxonomy import classify

mcp = MCPServer(
    name="redteam-scanner",
    instructions=(
        "Prompt-injection-tests a live agent endpoint. scan_qualify_endpoint runs the "
        "full 18-case golden attack set against a target that speaks Lead Router's own "
        "/qualify contract verbatim; scan_endpoint runs the same cases against ANY "
        "endpoint that accepts a lead-like submission and returns a classification "
        "decision, via a field_map/response_map translation. Both require an explicit "
        "authorization scope (target_host, authorized_by, contact, a valid_from/"
        "valid_until window, and i_have_authorization=true) before a single request "
        "fires - only scan a host you own or have explicit permission to test. Every "
        "attempt, authorized or rejected, is written to a local audit log; "
        "list_scan_history reads it back."
    ),
)


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


def _run_scan(target: TargetHttpClient, has_guardrails: bool) -> dict:
    cases = load_attack_cases()
    records = []
    for case in cases:
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
    return {
        "defended": held,
        "total": total,
        "by_category": by_category,
        "by_failure_layer": dict(by_layer),
        "findings": [r for r in records if not r["passed"]],
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
) -> dict:
    """Runs the 18-case golden prompt-injection set against a live
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

    Returns defended/total counts, a per-category breakdown, a
    per-failure-layer breakdown, and the list of cases that did NOT
    hold (each with its attack_id, category, and latency).
    """
    scope = _authorize_or_raise(
        tool="scan_qualify_endpoint", base_url=base_url, target_host=target_host,
        authorized_by=authorized_by, contact=contact, valid_from=valid_from,
        valid_until=valid_until, i_have_authorization=i_have_authorization, notes=notes,
    )
    result = _run_scan(QualifyEndpointTarget(base_url=base_url, api_key=api_key), assume_guardrails)
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
) -> dict:
    """Runs the same 18-case golden attack set as scan_qualify_endpoint,
    but against ANY endpoint that accepts a lead-like submission (a
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
    result = _run_scan(TargetHttpClient(profile), assume_guardrails)
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
    """Lists the four attack categories in the golden set, with a count
    of cases in each and a one-line description of what each tests."""
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
