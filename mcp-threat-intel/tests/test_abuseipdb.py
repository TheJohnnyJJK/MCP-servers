from __future__ import annotations

import httpx

from mcp_threat_intel.abuseipdb import AbuseIPDBClient


def test_check_ip_sends_key_header_and_normalizes_response(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["params"] = params
        captured["headers"] = headers
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 87,
                    "totalReports": 12,
                    "numDistinctUsers": 5,
                    "countryCode": "US",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "isp": "Example ISP",
                    "isPublic": True,
                    "isWhitelisted": False,
                    "lastReportedAt": "2026-09-01T00:00:00+00:00",
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    client = AbuseIPDBClient(api_key="secret")
    result = client.check_ip("1.2.3.4")

    assert captured["url"] == "https://api.abuseipdb.com/api/v2/check"
    assert captured["params"] == {"ipAddress": "1.2.3.4", "maxAgeInDays": 90}
    assert captured["headers"]["Key"] == "secret"
    assert result["abuse_confidence_score"] == 87
    assert result["total_reports"] == 12
    assert result["country_code"] == "US"


def test_check_ip_passes_through_max_age_days(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["params"] = params
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    AbuseIPDBClient(api_key="secret").check_ip("1.2.3.4", max_age_days=30)

    assert captured["params"]["maxAgeInDays"] == 30
