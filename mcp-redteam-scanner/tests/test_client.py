from __future__ import annotations

import httpx
import pytest

from mcp_redteam_scanner.client import QualifyEndpointTarget
from mcp_redteam_scanner.schema import load_attack_cases


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
