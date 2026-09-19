"""Turns _summarize()'s scan JSON into a deterministic markdown report -
the same "grade with code, not vibes" discipline this whole portfolio
uses, applied to the report a human actually gets handed at the end of
an engagement instead of just the raw counts. No LLM paraphrasing: every
line here is templated straight from the scan result, so the same
result always produces the same report.
"""
from __future__ import annotations

from collections import Counter

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_RANKS = ("critical", "high", "medium", "low")


def render_markdown_report(result: dict, *, target_label: str, scanned_at: str) -> str:
    """`result` is _summarize()'s own return shape (defended/total,
    by_category, by_failure_layer, findings - each finding carrying a
    severity). Never called for a dry-run result, which has no findings
    to report on at all."""
    total = result["total"]
    defended = result["defended"]
    lines = [
        "# Prompt-Injection Scan Report",
        "",
        f"- **Target:** {target_label}",
        f"- **Scanned at:** {scanned_at}",
        f"- **Result:** {defended}/{total} cases defended ({_pct(defended, total)}% pass rate)",
        "",
        "## By category",
        "",
        "| Category | Held | Total |",
        "| --- | --- | --- |",
    ]
    for category, counts in result["by_category"].items():
        lines.append(f"| {category} | {counts['held']} | {counts['total']} |")

    findings = result["findings"]
    if not findings:
        lines += ["", "No findings - every case held."]
        return "\n".join(lines)

    by_severity = Counter(f.get("severity", "unknown") for f in findings)
    lines += ["", "## Findings by severity", "", "| Severity | Count |", "| --- | --- |"]
    for severity in (*_SEVERITY_RANKS, "unknown"):
        if by_severity.get(severity):
            lines.append(f"| {severity} | {by_severity[severity]} |")

    lines += ["", "## Findings", ""]
    ordered = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity", ""), 9))
    for finding in ordered:
        severity_label = finding.get("severity", "unknown").upper()
        lines += [
            f"### [{severity_label}] {finding['attack_id']} - {finding['category']}",
            "",
            f"- **Failure layer:** {finding.get('failure_layer') or 'n/a (request errored)'}",
            f"- **Latency:** {finding['latency_ms']} ms",
        ]
        if finding.get("error"):
            lines.append(f"- **Error:** {finding['error']}")
        lines += [f"- **Notes:** {finding['notes']}", ""]
    return "\n".join(lines)


def _pct(part: int, total: int) -> float:
    return round(100 * part / total, 1) if total else 0.0
