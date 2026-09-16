"""MCP server exposing IP/domain/file-hash reputation lookups.

IP checks go to AbuseIPDB; domain and file-hash checks go to
VirusTotal - each vendor is used for what it's actually good at rather
than forcing one API to cover all three lookup types.

Run directly for local testing:

    python -m mcp_threat_intel.server

Requires ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY in the
environment - see .env.example. Only the key(s) needed for the tool
you actually call have to be set.
"""
from __future__ import annotations

import os

from mcp.server.mcpserver import MCPServer

from .abuseipdb import AbuseIPDBClient
from .virustotal import VirusTotalClient

mcp = MCPServer(
    name="threat-intel",
    instructions=(
        "Looks up reputation for an IP (AbuseIPDB), a domain, or a file "
        "hash (VirusTotal) and returns a normalized verdict."
    ),
)


class MissingApiKeyError(RuntimeError):
    pass


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise MissingApiKeyError(f"{name} is not set - see .env.example")
    return value


def _ip_verdict(score: int) -> str:
    if score >= 75:
        return "malicious"
    if score >= 25:
        return "suspicious"
    return "clean"


def _vt_verdict(malicious: int, suspicious: int) -> str:
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"


@mcp.tool()
def check_ip_reputation(ip: str, max_age_days: int = 90) -> dict:
    """Looks up an IP address's abuse reports via AbuseIPDB.

    ip: the IPv4 or IPv6 address to check.
    max_age_days: only count reports from the last N days (default 90).

    Returns abuse_confidence_score (0-100), report counts, ISP/country
    metadata, and a normalized verdict: "clean" (<25), "suspicious"
    (25-74), or "malicious" (>=75).
    """
    client = AbuseIPDBClient(api_key=_require_env("ABUSEIPDB_API_KEY"))
    result = client.check_ip(ip, max_age_days=max_age_days)
    result["verdict"] = _ip_verdict(result["abuse_confidence_score"])
    return result


@mcp.tool()
def check_domain_reputation(domain: str) -> dict:
    """Looks up a domain's reputation via VirusTotal.

    domain: the domain name to check, e.g. "example.com".

    Returns vendor verdict counts (malicious/suspicious/harmless/
    undetected out of ~90 scanning engines), VT's reputation score,
    category tags, and a normalized verdict: "malicious" if any engine
    flags it malicious, "suspicious" if any flag it suspicious, else
    "clean".
    """
    client = VirusTotalClient(api_key=_require_env("VIRUSTOTAL_API_KEY"))
    result = client.domain_report(domain)
    result["verdict"] = _vt_verdict(result["malicious"], result["suspicious"])
    return result


@mcp.tool()
def check_file_hash(file_hash: str) -> dict:
    """Looks up a file's reputation via VirusTotal by hash.

    file_hash: an MD5, SHA-1, or SHA-256 hash of the file.

    Returns vendor verdict counts, VT's reputation score, the file
    type/name VT has on record, and a normalized verdict the same way
    check_domain_reputation does.
    """
    client = VirusTotalClient(api_key=_require_env("VIRUSTOTAL_API_KEY"))
    result = client.file_report(file_hash)
    result["verdict"] = _vt_verdict(result["malicious"], result["suspicious"])
    return result


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
