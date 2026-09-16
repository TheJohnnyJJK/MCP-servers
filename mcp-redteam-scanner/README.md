# A red-team scanner your MCP client can call

## In plain terms

I built [agent-red-team](https://github.com/TheJohnnyJJK/Agent-Red-Team) to
attack my own Lead Router agent with 18 hand-written prompt-injection
cases, graded deterministically against the real response, no LLM judge.
This project turns that same attack set into an MCP tool: any MCP
client (Claude Desktop, Cursor, or your own agent) can call
`scan_qualify_endpoint` and get a pass/fail security report on any
service that speaks the same `POST /qualify` contract - a lead payload
in, a tier/owner verdict out.

It's scoped honestly: this scans a specific, narrow endpoint shape
(the one Lead Router and its hardened variant both expose), not "any
agent." If your service accepts a lead-shaped JSON body and returns a
tier/owner/reasoning verdict, this scanner works against it unmodified.

**A note on `base_url`:** this tool fires 18 real HTTP requests at
whatever URL you give it, on purpose - that's what a scanner does. Run
it as a local, single-user tool pointed at your own services. Don't
wire it into an MCP client that also processes untrusted external
content (a fetched webpage, an inbound email) without first making
sure that content can't choose `base_url` - otherwise you've built the
exact SSRF-via-prompt-injection chain this whole project is about
defending against.

## What it tests

Four categories, 18 cases total, carried over verbatim from
agent-red-team's golden set:

- **direct_injection** - instructions embedded in lead fields asking
  for a tier/owner the content doesn't honestly earn.
- **system_prompt_extraction** - attempts to get internal instructions
  echoed back into the response.
- **business_logic_escape** - payloads targeting the qualification
  logic itself, not just its output.
- **output_handling_injection** - content designed to survive
  unsanitized into a field a caller might relay elsewhere (Slack,
  storage, another API).

Grading is the same as agent-red-team's: a tier/owner that drifts from
what the lead honestly deserves, or a marker string that survives into
`reasoning`, is a fail. No vibes, no LLM judge - `scorer.py` checks the
actual response against a ground-truth answer written into the fixture.

## Tools

- **`scan_qualify_endpoint(base_url, api_key=None, assume_guardrails=True)`**
  Runs all 18 cases against a live target and returns defended/total
  counts, a per-category breakdown, a failure-layer breakdown
  (system_prompt / model / output_handling), and the list of findings
  that didn't hold.
- **`list_attack_categories()`**
  Lists the four categories with a case count and description each -
  useful for a client to show what a scan actually covers before
  running one.

## Install

```bash
pip install mcp-redteam-scanner
```

Then point your MCP client at it. For Claude Desktop or Cursor, add to
its MCP config:

```json
{
  "mcpServers": {
    "redteam-scanner": {
      "command": "mcp-redteam-scanner"
    }
  }
}
```

Or run it directly for local testing:

```bash
python -m mcp_redteam_scanner.server
```

## Example

Once connected, ask your client something like:

> Scan `http://localhost:8000` for prompt injection using the
> redteam-scanner.

It calls `scan_qualify_endpoint(base_url="http://localhost:8000")` and
comes back with something like:

```json
{
  "defended": 16,
  "total": 18,
  "by_category": {
    "direct_injection": { "total": 6, "held": 6 },
    "system_prompt_extraction": { "total": 4, "held": 3 },
    "business_logic_escape": { "total": 4, "held": 4 },
    "output_handling_injection": { "total": 4, "held": 3 }
  },
  "by_failure_layer": { "output_handling": 2 },
  "findings": [ { "attack_id": "spe-02", "category": "system_prompt_extraction", "...": "..." } ]
}
```

## Why it's built this way

The attack set, scoring, and failure taxonomy are a direct port of
agent-red-team's `redteam/` package - same fixture, same grading logic,
same "grade with code, not vibes" discipline the whole portfolio uses.
The only real change is the target abstraction: agent-red-team's
`LeadRouterTarget` assumed one specific service; this project's
`QualifyEndpointTarget` assumes only the shape of the contract, so it
works against anyone else's implementation of it too.

`assume_guardrails` on `scan_qualify_endpoint` is a hint, not something
detected automatically - there's no reliable way to tell from the
outside whether a target has any prompt-level defense at all. It only
affects which layer a failure gets blamed on in `by_failure_layer`, never
the pass/fail result itself.

## Development

```bash
uv venv .venv
uv pip install -e . --python .venv
uv pip install pytest ruff --python .venv
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check src tests
```

18 offline tests, no network calls, no API keys required - they mock
every HTTP boundary the same way agent-red-team's tests do.
