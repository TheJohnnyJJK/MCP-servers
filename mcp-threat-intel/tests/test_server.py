from __future__ import annotations

import httpx
import pytest

from mcp_threat_intel import server


def test_check_ip_reputation_raises_clear_error_without_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    with pytest.raises(server.MissingApiKeyError, match="ABUSEIPDB_API_KEY"):
        server.check_ip_reputation("1.2.3.4")


def test_check_domain_reputation_raises_clear_error_without_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    with pytest.raises(server.MissingApiKeyError, match="VIRUSTOTAL_API_KEY"):
        server.check_domain_reputation("example.com")


def test_check_ip_reputation_attaches_verdict(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "secret")

    def fake_get(url, params=None, headers=None, timeout=None):
        return httpx.Response(
            200,
            request=httpx.Request("GET", url),
            json={
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 90,
                    "totalReports": 20,
                    "numDistinctUsers": 8,
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = server.check_ip_reputation("1.2.3.4")
    assert result["verdict"] == "malicious"


def test_check_domain_reputation_attaches_clean_verdict(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "secret")

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
                            "harmless": 80,
                            "undetected": 5,
                        },
                        "reputation": 20,
                        "categories": {},
                    }
                }
            },
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    result = server.check_domain_reputation("safe.example")
    assert result["verdict"] == "clean"


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "clean"),
        (24, "clean"),
        (25, "suspicious"),
        (74, "suspicious"),
        (75, "malicious"),
        (100, "malicious"),
    ],
)
def test_ip_verdict_thresholds(score, expected):
    assert server._ip_verdict(score) == expected


@pytest.mark.parametrize(
    ("malicious", "suspicious", "expected"),
    [(0, 0, "clean"), (0, 1, "suspicious"), (1, 0, "malicious"), (1, 1, "malicious")],
)
def test_vt_verdict_thresholds(malicious, suspicious, expected):
    assert server._vt_verdict(malicious, suspicious) == expected
