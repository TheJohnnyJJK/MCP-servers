"""Thin client for AbuseIPDB's /check endpoint - IP reputation only.

Response is normalized down to the fields worth putting in front of an
agent: raw AbuseIPDB payloads carry a handful of nested identifiers
(reporter IDs, etc.) that add noise without adding signal here.
"""
from __future__ import annotations

import httpx

_BASE_URL = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    def __init__(self, api_key: str, timeout: float = 15.0) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def check_ip(self, ip: str, max_age_days: int = 90) -> dict:
        response = httpx.get(
            f"{_BASE_URL}/check",
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            headers={"Key": self._api_key, "Accept": "application/json"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "ip": data["ipAddress"],
            "abuse_confidence_score": data["abuseConfidenceScore"],
            "total_reports": data["totalReports"],
            "distinct_reporters": data["numDistinctUsers"],
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "last_reported_at": data.get("lastReportedAt"),
        }
