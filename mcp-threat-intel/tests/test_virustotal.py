from __future__ import annotations

import httpx

from mcp_threat_intel.virustotal import VirusTotalClient


def test_domain_report_sends_api_key_header_and_normalizes_response(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 1,
                            "harmless": 70,
                            "undetected": 10,
                        },
                        "reputation": -15,
                        "categories": {"vendor": "phishing"},
                    }
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    client = VirusTotalClient(api_key="secret")
    result = client.domain_report("evil.example")

    assert captured["url"] == "https://www.virustotal.com/api/v3/domains/evil.example"
    assert captured["headers"]["x-apikey"] == "secret"
    assert result["malicious"] == 3
    assert result["reputation"] == -15
    assert result["categories"] == {"vendor": "phishing"}


def test_file_report_normalizes_response(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 60,
                            "undetected": 20,
                        },
                        "reputation": 5,
                        "type_description": "PDF document",
                        "meaningful_name": "invoice.pdf",
                    }
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = VirusTotalClient(api_key="secret").file_report("deadbeef")

    assert result["malicious"] == 0
    assert result["type_description"] == "PDF document"
    assert result["meaningful_name"] == "invoice.pdf"


def test_domain_report_escapes_path_traversal_in_the_domain_argument(monkeypatch):
    captured = {}

    def fake_get(url, headers=None, timeout=None):
        captured["url"] = str(url)
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"attributes": {}}},
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    VirusTotalClient(api_key="secret").domain_report("../files/deadbeef")

    assert captured["url"] == (
        "https://www.virustotal.com/api/v3/domains/..%2Ffiles%2Fdeadbeef"
    ), "an unescaped '../' would make httpx route this to the files endpoint instead"


def test_missing_stats_default_to_zero(monkeypatch):
    def fake_get(url, headers=None, timeout=None):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={"data": {"attributes": {}}},
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = VirusTotalClient(api_key="secret").domain_report("blank.example")

    assert result["malicious"] == 0
    assert result["reputation"] == 0
    assert result["categories"] == {}
