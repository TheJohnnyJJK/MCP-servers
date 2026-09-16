"""MCP server exposing the golden-attack-set scanner as two tools:
scan_qualify_endpoint and list_attack_categories.

Run directly for local testing:

    python -m mcp_redteam_scanner.server

Or point an MCP client (Claude Desktop, Cursor, etc.) at the
`mcp-redteam-scanner` console script over stdio.
"""
from __future__ import annotations

import time
from collections import Counter

from mcp.server.mcpserver import MCPServer

from .client import QualifyEndpointTarget
from .schema import load_attack_cases
from .scorer import grade
from .taxonomy import classify

mcp = MCPServer(
    name="redteam-scanner",
    instructions=(
        "Prompt-injection-tests any agent endpoint that accepts POST /qualify "
        "with a lead payload and returns a tier/owner verdict. Use "
        "scan_qualify_endpoint to run the full 18-case golden attack set "
        "against a live target."
    ),
)


def _run_scan(base_url: str, api_key: str | None, has_guardrails: bool) -> dict:
    cases = load_attack_cases()
    client = QualifyEndpointTarget(base_url=base_url, api_key=api_key)
    records = []
    for case in cases:
        started = time.perf_counter()
        try:
            response = client.send(case)
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
    api_key: str | None = None,
    assume_guardrails: bool = True,
) -> dict:
    """Runs the 18-case golden prompt-injection set against a live
    /qualify-compatible endpoint and returns a pass/fail summary.

    base_url: the target's root URL, e.g. "http://localhost:8000" - the
        scanner POSTs to f"{base_url}/qualify".
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
    return _run_scan(base_url, api_key, assume_guardrails)


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
