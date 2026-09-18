# MCP servers

Three small [Model Context Protocol](https://modelcontextprotocol.io)
servers, each independently installable and each doing one real job for
an AI assistant (Claude Desktop, Cursor, Claude Code, or anything else
that speaks MCP). They live in one repo for convenience - each ships
and installs as its own package, with its own tests, its own README,
and its own install count.

- **[mcp-redteam-scanner](mcp-redteam-scanner/)** - prompt-injection-tests
  a live agent endpoint using the same 18-case golden attack set built
  for [agent-red-team](https://github.com/TheJohnnyJJK/Agent-Red-Team) -
  `scan_qualify_endpoint` for a target that speaks Lead Router's own
  `/qualify` contract verbatim, `scan_endpoint` for any lead-in/
  decision-out agent via a configurable field mapping.
- **[mcp-threat-intel](mcp-threat-intel/)** - IP, domain, and file-hash
  reputation lookups via AbuseIPDB and VirusTotal.
- **[mcp-cve-feed](mcp-cve-feed/)** - search and lookup against the
  public NVD CVE feed.

`mcp-threat-intel` and `mcp-cve-feed` also get real use as library
dependencies inside [soc-analyst](https://github.com/TheJohnnyJJK/soc-analyst),
a separate project that imports their tool functions directly rather
than reimplementing the same API clients a third time.

Each subdirectory is a complete, independent Python package - see its
own README for what it does, how to install it, and how to run its
tests.
