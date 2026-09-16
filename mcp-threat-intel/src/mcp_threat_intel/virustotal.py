"""Thin client for VirusTotal API v3 - domain and file-hash reports.

Normalizes each response down to the vendor-verdict counts and a
handful of identifying fields. A raw VT response nests dozens of
per-engine verdicts and metadata fields an agent doesn't need to see
to answer "is this reputation good or bad."
"""
from __future__ import annotations

from urllib.parse import quote

import httpx

_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: str, timeout: float = 15.0) -> None:
        self._headers = {"x-apikey": api_key}
        self._timeout = timeout

    def _get(self, path: str) -> dict:
        response = httpx.get(f"{_BASE_URL}{path}", headers=self._headers, timeout=self._timeout)
        response.raise_for_status()
        return response.json()["data"]

    def domain_report(self, domain: str) -> dict:
        # quote() with safe="" so a domain/hash containing "../" can't
        # redirect this request to a different VT API path (httpx
        # normalizes dot-segments client-side before the request goes out).
        data = self._get(f"/domains/{quote(domain, safe='')}")
        attrs = data["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "categories": attrs.get("categories", {}),
        }

    def file_report(self, file_hash: str) -> dict:
        data = self._get(f"/files/{quote(file_hash, safe='')}")
        attrs = data["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
        }
