from __future__ import annotations

from mcp_redteam_scanner.report import render_markdown_report


def _result(findings: list[dict] | None = None) -> dict:
    findings = findings or []
    return {
        "defended": 26 - len(findings),
        "total": 26,
        "by_category": {
            "direct_injection": {"total": 6, "held": 6 - len(findings)},
        },
        "by_failure_layer": {},
        "by_severity": {},
        "findings": findings,
    }


def _finding(**overrides) -> dict:
    fields = {
        "attack_id": "di-01",
        "category": "direct_injection",
        "severity": "high",
        "passed": False,
        "failure_layer": "model",
        "error": None,
        "latency_ms": 12.3,
        "notes": "test finding",
    }
    fields.update(overrides)
    return fields


def test_report_with_no_findings_says_so():
    report = render_markdown_report(
        _result(), target_label="http://localhost:8000", scanned_at="2026-09-19T00:00:00Z"
    )
    assert "No findings - every case held." in report
    assert "http://localhost:8000" in report
    assert "26/26" in report


def test_report_includes_summary_and_category_table():
    report = render_markdown_report(
        _result(), target_label="http://localhost:8000", scanned_at="2026-09-19T00:00:00Z"
    )
    assert "# Prompt-Injection Scan Report" in report
    assert "## By category" in report
    assert "| direct_injection | 6 | 6 |" in report


def test_report_orders_findings_by_severity_critical_first():
    findings = [
        _finding(attack_id="low-01", severity="low"),
        _finding(attack_id="crit-01", severity="critical"),
        _finding(attack_id="med-01", severity="medium"),
        _finding(attack_id="high-01", severity="high"),
    ]
    report = render_markdown_report(
        _result(findings), target_label="t", scanned_at="now"
    )
    order = [
        report.index("crit-01"),
        report.index("high-01"),
        report.index("med-01"),
        report.index("low-01"),
    ]
    assert order == sorted(order)


def test_report_includes_severity_breakdown_table():
    findings = [_finding(severity="critical"), _finding(attack_id="di-02", severity="high")]
    report = render_markdown_report(_result(findings), target_label="t", scanned_at="now")
    assert "## Findings by severity" in report
    assert "| critical | 1 |" in report
    assert "| high | 1 |" in report


def test_report_includes_error_when_present():
    findings = [_finding(error="connection refused", passed=None, failure_layer=None)]
    report = render_markdown_report(_result(findings), target_label="t", scanned_at="now")
    assert "**Error:** connection refused" in report
    assert "n/a (request errored)" in report


def test_report_includes_notes_for_each_finding():
    findings = [_finding(notes="this is the finding explanation")]
    report = render_markdown_report(_result(findings), target_label="t", scanned_at="now")
    assert "this is the finding explanation" in report
