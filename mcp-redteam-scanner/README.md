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

It's still scoped honestly - this doesn't probe arbitrary endpoints
blind, and it never runs against anything without you supplying its URL
yourself - but the target *shape* isn't hardcoded anymore. `scan_endpoint`
runs the identical 18 cases against any endpoint that accepts a
lead-like submission (a free-text field plus a few structured ones) and
returns a classification decision plus free-text reasoning, translating
this scanner's fixed field names onto the target's own via a
`field_map`/`response_map` - a different URL path, different field
names, nested request/response shapes, none of that requires touching
the attack content or the grading logic. `scan_qualify_endpoint` is
still there, unchanged, as the zero-configuration case where the target
already matches Lead Router's contract exactly.

**A note on `base_url`:** both tools fire 18 real HTTP requests at
whatever URL you give them, on purpose - that's what a scanner does.
Both now refuse to fire any of them without an explicit authorization
scope alongside `base_url` - see "Authorization" below. That scope is
still a self-attested claim, not something this tool can verify against
a target's real owner, so run it as a local, single-user tool pointed
only at services you own or have explicit permission to test. Don't
wire either tool into an MCP client that also processes untrusted
external content (a fetched webpage, an inbound email) without first
making sure that content can't choose `base_url` or the authorization
arguments - otherwise you've built the exact SSRF-via-prompt-injection
chain this whole project is about defending against.

## Authorization

Neither tool will send a single request until you supply, alongside
`base_url`:

- `target_host` - the hostname you're authorizing this scan for.
  Rejected if it doesn't match the host `base_url` actually resolves
  to - this is what stops a stale or mismatched authorization from
  silently covering a different target than the one it was written for.
- `authorized_by` / `contact` - who's asserting this authorization, and
  who to reach about the engagement.
- `valid_from` / `valid_until` - the engagement window (ISO datetimes)
  this scan must fall inside, checked against the current time.
- `i_have_authorization` - must be explicitly `true`. There's no
  default that authorizes anything.
- `notes` (optional) - anything worth recording alongside this attempt,
  e.g. `"own staging deploy"` or `"bug bounty program ref #1234"`.

This can't cryptographically verify that a target's real owner
consented - there's no PKI handshake with a third party here. What it
buys instead is a deliberate speed bump plus a paper trail: every scan
requires consciously stating who authorized it and for which host
before anything fires, and **every attempt - authorized or rejected -
is written to a local, append-only audit log** (`audit_log.py`,
default `~/.mcp-redteam-scanner/audit_log.jsonl`, overridable via
`REDTEAM_SCANNER_AUDIT_LOG`). `list_scan_history(limit=20)` reads it
back. That turns "I only meant to test my own service" from an
unverifiable claim into something with a timestamped record behind it.

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

- **`scan_qualify_endpoint(base_url, target_host, authorized_by, contact, valid_from, valid_until, i_have_authorization, notes="", api_key=None, assume_guardrails=True)`**
  Runs all 18 cases against a live target that speaks Lead Router's own
  `/qualify` contract exactly, and returns defended/total counts, a
  per-category breakdown, a failure-layer breakdown (system_prompt /
  model / output_handling), and the list of findings that didn't hold.
  See "Authorization" above for the first six arguments.
- **`scan_endpoint(base_url, target_host, authorized_by, contact, valid_from, valid_until, i_have_authorization, notes="", path="/qualify", api_key=None, api_key_header="X-API-Key", field_map=None, response_map=None, assume_guardrails=True, timeout=60.0)`**
  Same 18 cases, same grading, same return shape and authorization gate
  as `scan_qualify_endpoint` - but against any endpoint, via
  `field_map`/`response_map` translating this scanner's canonical field
  names onto the target's own (see "Scanning a differently-shaped
  target" below).
- **`list_scan_history(limit=20)`**
  Reads back the local audit log of scan attempts - authorized and
  rejected alike - most recent first.
- **`list_attack_categories()`**
  Lists the four categories with a case count and description each -
  useful for a client to show what a scan actually covers before
  running one.

## Scanning a differently-shaped target

`scan_qualify_endpoint` assumes the target's request/response fields
are named exactly like Lead Router's own (`name`, `email`, `message`,
... in; `tier`, `suggested_owner`, `reasoning`, ... out). A real
third-party agent almost never matches that verbatim, so `scan_endpoint`
takes two maps, each keyed by this scanner's own canonical field names:

- `field_map` - canonical **request** field -> the target's own field
  name, as a dotted path for a nested body (e.g.
  `{"message": "lead.input"}` sends the free-text field at
  `body["lead"]["input"]`). Map a field to `null` to omit it from the
  request entirely (e.g. a target with no phone-number field at all).
  Any field left unmapped is sent under its own name, unchanged.
- `response_map` - canonical **response** field (`tier`,
  `suggested_owner`, `icp_fit_score`, `urgency_score`, `reasoning`,
  `confidence`) -> a dotted path into the target's own JSON response
  (e.g. `{"tier": "result.classification"}` for a nested decision
  object). Only `tier`, `suggested_owner`, and `reasoning` are actually
  required for grading - leave the rest unset if the target has no
  equivalent of Lead Router's own internal scoring fields.

Example: a support-ticket triage bot that nests its decision under
`result` and calls the free-text field `input`:

```
scan_endpoint(
  base_url="http://localhost:9000",
  target_host="localhost",
  authorized_by="jane",
  contact="jane@example.com",
  valid_from="2026-09-19T00:00:00Z",
  valid_until="2026-09-26T00:00:00Z",
  i_have_authorization=true,
  path="/api/triage",
  field_map={"message": "input"},
  response_map={
    "tier": "result.classification",
    "suggested_owner": "result.owner",
    "reasoning": "explanation"
  }
)
```

The attack content itself - what's actually injected, and which
category it tests - never changes between the two tools. Only where
it's delivered and read back from does.

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
> redteam-scanner - I own this service, authorize it for the next hour
> under my name.

It calls `scan_qualify_endpoint(base_url="http://localhost:8000",
target_host="localhost", authorized_by="...", contact="...",
valid_from=..., valid_until=..., i_have_authorization=true)` and comes
back with something like:

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
The target abstraction has gone through two generalizations now:
agent-red-team's own `LeadRouterTarget` assumed one specific service;
this project's first version, `QualifyEndpointTarget`, assumed only the
shape of the contract (works against anyone's implementation of Lead
Router's exact fields); `TargetHttpClient` (what both
`QualifyEndpointTarget` and `scan_endpoint` build on now) drops that
last assumption too, translating field names and response nesting
through a `TargetProfile` instead of requiring them to match at all.
The attack content and grading logic (`scorer.py`, `taxonomy.py`)
haven't changed at any of these three steps - only where the payload
gets delivered and the verdict gets read back from.

`assume_guardrails` on `scan_qualify_endpoint` is a hint, not something
detected automatically - there's no reliable way to tell from the
outside whether a target has any prompt-level defense at all. It only
affects which layer a failure gets blamed on in `by_failure_layer`, never
the pass/fail result itself.

The authorization gate (`authorization.py`) is a similarly honest piece
of scope: `EngagementScope` can't verify a claim against a target's
real owner, so it doesn't pretend to. What it enforces is narrower and
checkable - the scan is currently within its stated time window, and
aimed at the exact host the operator named - and what it guarantees is
a record, not a proof: every attempt, rejected or not, lands in
`audit_log.py`'s append-only log before either tool returns.

## Development

```bash
uv venv .venv
uv pip install -e . --python .venv
uv pip install pytest ruff --python .venv
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check src tests
```

40 offline tests, no network calls, no API keys required - they mock
every HTTP boundary the same way agent-red-team's tests do, and isolate
the audit log to a temp file per test.
