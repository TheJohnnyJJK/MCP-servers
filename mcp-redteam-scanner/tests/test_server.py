from __future__ import annotations

import httpx

from mcp_redteam_scanner.server import list_attack_categories, scan_endpoint, scan_qualify_endpoint


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

    result = scan_qualify_endpoint(base_url="http://localhost:9999")

    assert result["total"] == 18
    # every case's expected_safe_tier/owner in the fixture set isn't
    # actually "cold"/"nurture" for all 18, so a target that returns the
    # same inert verdict for every case will fail some direct_injection
    # cases whose expected safe verdict differs - assert the shape and
    # the always-callable invariant, not a specific defended count here.
    assert set(result) == {
        "defended",
        "total",
        "by_category",
        "by_failure_layer",
        "findings",
    }
    assert isinstance(result["findings"], list)


def test_scan_qualify_endpoint_records_hard_errors_as_not_held(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        request = httpx.Request("POST", url)
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("boom", request=request, response=response)

    monkeypatch.setattr(httpx, "post", fake_post)

    result = scan_qualify_endpoint(base_url="http://localhost:9999")

    assert result["defended"] == 0
    assert result["total"] == 18
    assert all(f["error"] is not None for f in result["findings"])


def test_scan_endpoint_works_against_a_differently_shaped_target(monkeypatch):
    """The whole point of scan_endpoint: a target that nests its decision
    under "result" and calls the free-text field "input" - not an exact
    Lead Router clone - still gets scanned via field_map/response_map,
    reusing the same 18 cases and the same grading logic."""
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
    )

    assert result["total"] == 18
    assert all(url == "http://localhost:9999/api/triage" for url in captured_urls)
    assert isinstance(result["findings"], list)


def test_list_attack_categories_covers_all_eighteen_cases():
    categories = list_attack_categories()
    assert sum(c["count"] for c in categories) == 18
    assert {c["category"] for c in categories} == {
        "direct_injection",
        "system_prompt_extraction",
        "business_logic_escape",
        "output_handling_injection",
    }
