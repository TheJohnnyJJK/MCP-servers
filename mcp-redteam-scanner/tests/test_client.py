from __future__ import annotations

import httpx
import pytest

from mcp_redteam_scanner.client import QualifyEndpointTarget, TargetHttpClient
from mcp_redteam_scanner.schema import TargetProfile, load_attack_cases


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def test_send_posts_qualify_with_lead_json_and_api_key_header(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakeResponse(
            {
                "tier": "cold",
                "suggested_owner": "nurture",
                "icp_fit_score": 10,
                "urgency_score": 0,
                "reasoning": "no signal",
                "confidence": 0.5,
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    target = QualifyEndpointTarget(base_url="http://localhost:8000/", api_key="secret")
    response = target.send(case)

    assert captured["url"] == "http://localhost:8000/qualify"
    assert captured["headers"] == {"X-API-Key": "secret"}
    assert response.tier == "cold"


def test_send_without_api_key_sends_no_auth_header(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured["headers"] = headers
        return _FakeResponse(
            {
                "tier": "spam",
                "suggested_owner": "discard",
                "icp_fit_score": 0,
                "urgency_score": 0,
                "reasoning": "spam",
                "confidence": 0.7,
            }
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    QualifyEndpointTarget(base_url="http://localhost:8001").send(case)

    assert captured["headers"] == {}


def test_send_raises_on_http_error(monkeypatch):
    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        request = httpx.Request("POST", url)
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("server error", request=request, response=response)

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    target = QualifyEndpointTarget(base_url="http://localhost:8000")
    with pytest.raises(httpx.HTTPStatusError):
        target.send(case)


def test_build_request_does_not_call_httpx(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("build_request must never make a network call")

    monkeypatch.setattr(httpx, "post", boom)

    case = load_attack_cases()[0]
    target = QualifyEndpointTarget(base_url="http://localhost:8000", api_key="secret")
    request = target.build_request(case)

    assert request["method"] == "POST"
    assert request["url"] == "http://localhost:8000/qualify"
    assert request["headers"] == {"X-API-Key": "secret"}
    assert request["body"]["message"] == case.lead.message


def test_send_uses_build_request_under_the_hood(monkeypatch):
    """send() shouldn't duplicate build_request()'s translation logic -
    changing field_map should be visible through both."""
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"tier": "cold", "suggested_owner": "nurture", "reasoning": "ok"},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    profile = TargetProfile(base_url="http://localhost:9000", field_map={"message": "text"})
    target = TargetHttpClient(profile)
    built = target.build_request(case)
    target.send(case)

    assert captured["url"] == built["url"]
    assert captured["json"] == built["body"]
    assert "text" in captured["json"]


def test_target_http_client_translates_request_fields_via_field_map(monkeypatch):
    """A third-party endpoint that calls the free-text field "input" and
    nests everything under "lead" instead of Lead Router's own flat
    name/email/message shape - field_map should reach that without
    touching the attack content itself."""
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"tier": "cold", "suggested_owner": "nurture", "reasoning": "inert"},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    profile = TargetProfile(
        base_url="http://localhost:9000",
        path="/api/triage",
        field_map={"message": "lead.input", "name": "lead.full_name"},
    )
    TargetHttpClient(profile).send(case)

    assert captured["url"] == "http://localhost:9000/api/triage"
    assert captured["json"]["lead"]["input"] == case.lead.message
    assert captured["json"]["lead"]["full_name"] == case.lead.name
    # Fields with no field_map entry still go through under their own name.
    assert captured["json"]["email"] == case.lead.email


def test_target_http_client_field_map_can_drop_a_field(monkeypatch):
    captured = {}

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        captured["json"] = json
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"tier": "cold", "suggested_owner": "nurture", "reasoning": "inert"},
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    profile = TargetProfile(base_url="http://localhost:9000", field_map={"source": None})
    TargetHttpClient(profile).send(case)

    assert "source" not in captured["json"]


def test_target_http_client_translates_response_fields_via_response_map(monkeypatch):
    """A target that nests its decision under "result" instead of
    returning tier/suggested_owner/reasoning at the top level."""

    def fake_post(url, json=None, headers=None, timeout=None):  # noqa: A002
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "result": {"classification": "hot", "owner": "sales-enterprise"},
                "explanation": "looked legitimate",
            },
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    case = load_attack_cases()[0]
    profile = TargetProfile(
        base_url="http://localhost:9000",
        response_map={
            "tier": "result.classification",
            "suggested_owner": "result.owner",
            "reasoning": "explanation",
        },
    )
    response = TargetHttpClient(profile).send(case)

    assert response.tier == "hot"
    assert response.suggested_owner == "sales-enterprise"
    assert response.reasoning == "looked legitimate"
    # Unmapped optional fields default to None rather than erroring.
    assert response.icp_fit_score is None
