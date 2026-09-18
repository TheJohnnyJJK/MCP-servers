from __future__ import annotations

import datetime

from mcp_redteam_scanner.audit_log import read_recent_scans, record_scan_attempt
from mcp_redteam_scanner.authorization import EngagementScope


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("REDTEAM_SCANNER_AUDIT_LOG", str(tmp_path / "audit_log.jsonl"))


def _scope(**overrides) -> EngagementScope:
    now = datetime.datetime.now(datetime.timezone.utc)
    fields = {
        "target_host": "example.com",
        "authorized_by": "jane",
        "contact": "jane@example.com",
        "valid_from": now - datetime.timedelta(hours=1),
        "valid_until": now + datetime.timedelta(hours=1),
        "i_have_authorization": True,
    }
    fields.update(overrides)
    return EngagementScope(**fields)


def test_read_recent_scans_is_empty_before_anything_is_recorded(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert read_recent_scans() == []


def test_record_and_read_a_scan_attempt_round_trips(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record_scan_attempt(
        tool="scan_qualify_endpoint",
        base_url="https://example.com",
        scope=_scope(notes="own service"),
        outcome="scanned",
        summary={"defended": 18, "total": 18},
    )
    entries = read_recent_scans()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["tool"] == "scan_qualify_endpoint"
    assert entry["target_host"] == "example.com"
    assert entry["authorized_by"] == "jane"
    assert entry["outcome"] == "scanned"
    assert entry["summary"] == {"defended": 18, "total": 18}
    assert entry["rejection_reason"] is None


def test_a_rejection_is_recorded_with_its_reason(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record_scan_attempt(
        tool="scan_endpoint",
        base_url="https://not-authorized.com",
        scope=_scope(target_host="example.com"),
        outcome="rejected",
        rejection_reason="host mismatch",
    )
    entry = read_recent_scans()[0]
    assert entry["outcome"] == "rejected"
    assert entry["rejection_reason"] == "host mismatch"
    assert entry["summary"] is None


def test_read_recent_scans_returns_most_recent_first_and_respects_limit(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    for i in range(5):
        record_scan_attempt(
            tool="scan_qualify_endpoint",
            base_url="https://example.com",
            scope=_scope(notes=f"scan-{i}"),
            outcome="scanned",
            summary={"defended": i, "total": 18},
        )
    entries = read_recent_scans(limit=2)
    assert len(entries) == 2
    assert entries[0]["notes"] == "scan-4"
    assert entries[1]["notes"] == "scan-3"
