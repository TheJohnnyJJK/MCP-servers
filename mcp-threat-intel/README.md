# Reputation lookups your MCP client can call

## In plain terms

An MCP server with three tools: check whether an IP address has abuse
reports, whether a domain has a bad reputation, or whether a file hash
is known malware - all from inside Claude Desktop, Cursor, or any other
MCP client, without you having to open a browser tab to a threat-intel
dashboard. IP lookups go to AbuseIPDB; domain and file-hash lookups go
to VirusTotal - each vendor covers what it's actually good at, rather
than forcing one API to answer all three question types.

## Tools

- **`check_ip_reputation(ip, max_age_days=90)`** - AbuseIPDB abuse
  reports for an address: confidence score, report count, ISP/country,
  and a normalized verdict (`clean` / `suspicious` / `malicious`).
- **`check_domain_reputation(domain)`** - VirusTotal's ~90-engine
  verdict counts for a domain, its reputation score, category tags,
  and the same normalized verdict.
- **`check_file_hash(file_hash)`** - the same, for an MD5/SHA-1/SHA-256
  file hash, plus whatever file type/name VirusTotal has on record.

Every response is normalized down to the fields that actually answer
"is this bad" - a raw VirusTotal domain report nests dozens of
per-engine verdicts and metadata fields an agent doesn't need to see
just to act on a verdict.

## Install

```bash
pip install mcp-threat-intel
```

Get free API keys - [AbuseIPDB](https://www.abuseipdb.com/account/api)
(1,000 checks/day) and [VirusTotal](https://www.virustotal.com/gui/my-apikey)
(4 requests/min, 500/day) - then point your MCP client at the server
with both keys in its environment:

```json
{
  "mcpServers": {
    "threat-intel": {
      "command": "mcp-threat-intel",
      "env": {
        "ABUSEIPDB_API_KEY": "your-key-here",
        "VIRUSTOTAL_API_KEY": "your-key-here"
      }
    }
  }
}
```

You only need the key for whichever tool you actually call - asking
for an IP check without `VIRUSTOTAL_API_KEY` set works fine, and vice
versa. A tool called without its required key fails with a clear
`ABUSEIPDB_API_KEY is not set` / `VIRUSTOTAL_API_KEY is not set` error
rather than a confusing HTTP failure.

## Example

> Is `185.220.101.1` a known bad actor?

The client calls `check_ip_reputation(ip="185.220.101.1")` and gets
back something like:

```json
{
  "ip": "185.220.101.1",
  "abuse_confidence_score": 100,
  "total_reports": 342,
  "distinct_reporters": 88,
  "country_code": "DE",
  "usage_type": "Data Center/Web Hosting/Transit",
  "verdict": "malicious"
}
```

## Development

```bash
uv venv .venv
uv pip install -e . --python .venv
uv pip install pytest ruff --python .venv
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check src tests
```

19 offline tests, all HTTP calls mocked - no API keys needed to run
the suite. `.env.example` documents the two keys the server itself
needs at runtime.
