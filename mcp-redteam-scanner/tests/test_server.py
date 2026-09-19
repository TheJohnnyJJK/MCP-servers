from __future__ import annotations

import contextlib
import datetime

import httpx
import pytest

from mcp_redteam_scanner.authorization import ScopeViolation
from mcp_redteam_scanner.server import (
    list_attack_categories,
    list_scan_history,
    scan_endpoint,
    scan_qualify_endpoint,
)


@pytest.fixture(autouse=True)
def _isolated_audit_log(tmp_path, monkeypatch):
    """Every test gets its own audit log file - never the real one under
    the developer's home directory."""
    monkeypatch.setenv("REDTEAM_SCANNER_AUDIT_LOG", str(tmp_path / "audit_log.jsonl"))


def _valid_scope(**overrides) -> dict:
    """A scope that authorizes localhost right now - what every scan
    test needs before it can reach the actual HTTP-mocking logic. Tests
    that want to exercise a rejection override just the field that
    should fail."""
    now = datetime.datetime.now(datetime.timezone.utc)
    scope = {
        "target_host": "localhost",
        "authorized_by": "test-operator",
        "contact": "test-operator@example.com",
        "valid_from": now - datetime.timedelta(hours=1),
        "valid_until": now + datetime.timedelta(hours=1),
        "i_have_authorization": True,
        "notes": "unit test",
    }
    scope.update(overrides)
    return scope


def _always_defended_post(url, json=None, headers=None, timeout=None):  # noqa: A002
    return httpx.Response(
        200,
        request=httpx.Request("POST", url),
        json={
            "tier": "cold",
            "suggested_owner": "nurture",
            "icp_fit_score": 5,
            "urgency_score": 0,
            "reasoning": "inert, no signal in this content",
            "confidence": 0.4,
        },
    )


def test_scan_qualify_endpoint_reports_full_defense(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)

    result = scan_qualify_endpoint(base_url="http://localhost:9999", **_valid_scope())

    assert result["total"] == 26
    # every case's expected_safe_tier/owner in the fixture set isn't
    # actually "cold"/"nurture" for all of them, so a target that returns
    # the same inert verdict for every case will fail some cases whose
    # expected safe verdict differs - assert the shape and the
    # always-callable invariant, not a specific defended count here.
    assert set(result) == {
        "defended",
        "total",
        "by_category",
        "by_failure_layer",
        "by_severity",
        "findings",
        "report",
    }
    assert isinstance(result["findings"], list)
    assert isinstance(result["report"], str)
    assert "Prompt-Injection Scan Report" in result["report"]


def test_scan_qualify_endpoint_records_hard_errors_as_not_held(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        request = httpx.Request("POST", url)
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("boom", request=request, response=response)

    monkeypatch.setattr(httpx, "post", fake_post)

    result = scan_qualify_endpoint(base_url="http://localhost:9999", **_valid_scope())

    assert result["defended"] == 0
    assert result["total"] == 26
    assert all(f["error"] is not None for f in result["findings"])
    assert all("severity" in f for f in result["findings"])


def test_scan_qualify_endpoint_refuses_when_target_host_does_not_match_base_url(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)

    with pytest.raises(ScopeViolation, match="acme.example.com"):
        scan_qualify_endpoint(
            base_url="http://localhost:9999", **_valid_scope(target_host="acme.example.com")
        )


def test_scan_qualify_endpoint_refuses_outside_the_authorized_window(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)
    now = datetime.datetime.now(datetime.timezone.utc)

    with pytest.raises(ScopeViolation, match="outside the authorized window"):
        scan_qualify_endpoint(
            base_url="http://localhost:9999",
            **_valid_scope(
                valid_from=now - datetime.timedelta(days=2),
                valid_until=now - datetime.timedelta(days=1),
            ),
        )


def test_scan_qualify_endpoint_never_calls_the_target_when_scope_is_rejected(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):  # noqa: A002
        raise AssertionError("should never reach httpx when the scope is rejected")

    monkeypatch.setattr(httpx, "post", boom)

    with pytest.raises(ScopeViolation):
        scan_qualify_endpoint(
            base_url="http://localhost:9999", **_valid_scope(target_host="not-localhost")
        )


def test_scan_endpoint_works_against_a_differently_shaped_target(monkeypatch):
    """The whole point of scan_endpoint: a target that nests its decision
    under "result" and calls the free-text field "input" - not an exact
    Lead Router clone - still gets scanned via field_map/response_map,
    reusing the same golden attack set and the same grading logic."""
    captured_urls = []

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured_urls.append(url)
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"result": {"classification": "cold", "owner": "nurture"}, "explanation": "inert"},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    result = scan_endpoint(
        base_url="http://localhost:9999",
        path="/api/triage",
        field_map={"message": "input"},
        response_map={
            "tier": "result.classification",
            "suggested_owner": "result.owner",
            "reasoning": "explanation",
        },
        **_valid_scope(),
    )

    assert result["total"] == 26
    assert all(url == "http://localhost:9999/api/triage" for url in captured_urls)
    assert isinstance(result["findings"], list)
    assert isinstance(result["report"], str)


def test_scan_endpoint_refuses_without_authorization(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):  # noqa: A002
        raise AssertionError("should never reach httpx when the scope is rejected")

    monkeypatch.setattr(httpx, "post", boom)

    with pytest.raises(ScopeViolation):
        scan_endpoint(
            base_url="http://localhost:9999",
            **_valid_scope(target_host="someone-elses-host.com"),
        )


def test_scan_records_appear_in_scan_history(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)

    scan_qualify_endpoint(base_url="http://localhost:9999", **_valid_scope(notes="approved scan"))
    with contextlib.suppress(ScopeViolation):
        scan_qualify_endpoint(
            base_url="http://localhost:9999", **_valid_scope(target_host="rejected-host.com")
        )

    history = list_scan_history()
    assert len(history) == 2
    # most recent first
    assert history[0]["outcome"] == "rejected"
    assert history[0]["target_host"] == "rejected-host.com"
    assert history[1]["outcome"] == "scanned"
    assert history[1]["notes"] == "approved scan"
    assert history[1]["summary"]["total"] == 26


def test_scan_history_is_empty_with_no_prior_scans():
    assert list_scan_history() == []


def test_dry_run_previews_requests_without_calling_the_target(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):  # noqa: A002
        raise AssertionError("dry_run must never actually call the target")

    monkeypatch.setattr(httpx, "post", boom)

    result = scan_qualify_endpoint(
        base_url="http://localhost:9999", dry_run=True, **_valid_scope()
    )

    assert result["dry_run"] is True
    assert len(result["requests"]) == 26
    first = result["requests"][0]
    assert first["url"] == "http://localhost:9999/qualify"
    assert first["method"] == "POST"
    assert "body" in first
    assert "severity" in first


def test_dry_run_still_requires_authorization(monkeypatch):
    def boom(url, json=None, headers=None, timeout=None):  # noqa: A002
        raise AssertionError("should never reach httpx")

    monkeypatch.setattr(httpx, "post", boom)

    with pytest.raises(ScopeViolation):
        scan_qualify_endpoint(
            base_url="http://localhost:9999",
            dry_run=True,
            **_valid_scope(target_host="not-localhost"),
        )


def test_dry_run_is_logged_separately_in_scan_history(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))

    scan_qualify_endpoint(base_url="http://localhost:9999", dry_run=True, **_valid_scope())

    history = list_scan_history()
    assert len(history) == 1
    assert history[0]["outcome"] == "dry_run"
    assert history[0]["summary"] == {"requests_previewed": 26}


def test_delay_seconds_sleeps_between_requests_but_not_before_the_first(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)
    sleeps = []
    monkeypatch.setattr("mcp_redteam_scanner.server.time.sleep", sleeps.append)

    scan_qualify_endpoint(
        base_url="http://localhost:9999", delay_seconds=0.25, **_valid_scope()
    )

    assert sleeps == [0.25] * 25


def test_delay_seconds_zero_never_sleeps(monkeypatch):
    monkeypatch.setattr(httpx, "post", _always_defended_post)
    monkeypatch.setattr(
        "mcp_redteam_scanner.server.time.sleep",
        lambda *_: (_ for _ in ()).throw(AssertionError("should not sleep at delay_seconds=0")),
    )

    scan_qualify_endpoint(base_url="http://localhost:9999", **_valid_scope())


def test_list_attack_categories_covers_all_cases():
    categories = list_attack_categories()
    assert sum(c["count"] for c in categories) == 26
    assert {c["category"] for c in categories} == {
        "direct_injection",
        "system_prompt_extraction",
        "business_logic_escape",
        "output_handling_injection",
        "encoding_evasion",
        "multi_field_chaining",
    }
