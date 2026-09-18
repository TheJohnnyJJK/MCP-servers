"""Append-only local record of every scan attempt - authorized and
rejected alike - so an operator running this tool against a third
party's endpoint has a paper trail of what they scanned, who they
claimed authorized it, and when. Same discipline as this portfolio's
soc-analyst audit trail, sized for a stateless MCP tool instead of a
running service: one JSON line per attempt, no database to provision.

REDTEAM_SCANNER_AUDIT_LOG overrides the log's path (read fresh on every
call, the same "tests can monkeypatch the env var" reasoning as
soc-analyst's SOC_STORE_DB) - defaults to a file under the user's home
directory so a pip-installed console script has somewhere sensible to
write without any setup.
"""
from __future__ import annotations

import datetime
import json
import os
from pathlib import Path

from .authorization import EngagementScope

_DEFAULT_LOG_PATH = Path.home() / ".mcp-redteam-scanner" / "audit_log.jsonl"


def _log_path() -> Path:
    override = os.environ.get("REDTEAM_SCANNER_AUDIT_LOG")
    return Path(override) if override else _DEFAULT_LOG_PATH


def record_scan_attempt(
    *,
    tool: str,
    base_url: str,
    scope: EngagementScope,
    outcome: str,
    summary: dict | None = None,
    rejection_reason: str | None = None,
) -> None:
    """Writes one line, always - called for a rejected scope exactly as
    for a completed scan, since the point of this log is "what was
    attempted," not just "what succeeded." `scope` is still logged on a
    rejection: the mismatch between what was claimed and what actually
    happened is the whole finding."""
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": tool,
        "base_url": base_url,
        "target_host": scope.target_host,
        "authorized_by": scope.authorized_by,
        "contact": scope.contact,
        "notes": scope.notes,
        "outcome": outcome,  # "scanned" | "rejected"
        "rejection_reason": rejection_reason,
        "summary": summary,
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_recent_scans(limit: int = 20) -> list[dict]:
    """Most recent attempts first. Returns an empty list rather than
    erroring when nothing's been logged yet - a fresh install with no
    scan history is the expected state, not a fault."""
    path = _log_path()
    if not path.exists():
        return []
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in reversed(lines[-limit:])]
