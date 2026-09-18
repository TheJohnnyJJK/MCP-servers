"""The gate every scan tool must pass before firing a single HTTP
request at a live target.

There's no PKI handshake with a third party here - this tool has no
way to cryptographically verify that whoever's calling it actually has
a target owner's permission. What EngagementScope buys instead is a
deliberate speed bump: every scan requires consciously stating who
authorized it, for which specific host, and until when, before any
request goes out - and that statement gets written to a local audit
log (see audit_log.py) regardless of whether the scan proceeds. That
turns "I meant to only test my own service" from an unverifiable claim
into something with a timestamped paper trail behind it.

`target_host` is checked against the actual host `base_url` resolves
to - not just recorded - specifically to catch the case this project's
own README already warns about: an MCP client that lets untrusted
content (a fetched page, an inbound email) influence `base_url` between
when a human authorized a scan and when it actually fires. A scope
naming "acme-support.example.com" never silently covers a request that
ends up going to a different host.
"""
from __future__ import annotations

import datetime
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class ScopeViolation(ValueError):
    """Raised by require_scope() - callers must catch this before ever
    constructing an httpx request, not after."""


class EngagementScope(BaseModel):
    """One operator's self-attested statement of authorization to scan
    one specific host, for a bounded time window. Not proof - a record."""

    target_host: str = Field(min_length=1, max_length=253)
    # Who's asserting this authorization exists, and who to reach about
    # the engagement - free text, since this project has no identity
    # system of its own to validate either against.
    authorized_by: str = Field(min_length=1, max_length=200)
    contact: str = Field(min_length=1, max_length=200)
    valid_from: datetime.datetime
    valid_until: datetime.datetime
    notes: str = Field(default="", max_length=1_000)
    # A deliberate friction field, not documentation: Literal[True] means
    # this must be explicitly passed true on every call. There's no
    # default that silently authorizes anything, and an MCP client can't
    # satisfy this by just omitting the argument.
    i_have_authorization: Literal[True]

    @field_validator("valid_from", "valid_until")
    @classmethod
    def _normalize_to_utc(cls, value: datetime.datetime) -> datetime.datetime:
        """A naive datetime is assumed UTC rather than rejected - the
        common case for a human typing "2026-01-01T00:00:00" without
        thinking about offsets - so require_scope() can always compare
        against an aware datetime.now(UTC) without a TypeError."""
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.timezone.utc)
        return value.astimezone(datetime.timezone.utc)

    @model_validator(mode="after")
    def _window_is_ordered(self) -> EngagementScope:
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self


def require_scope(scope: EngagementScope, base_url: str) -> None:
    """Raises ScopeViolation if `scope` doesn't actually cover a request
    about to be sent to `base_url` right now. Checked fresh on every
    call (not cached) - an engagement window that was valid a minute ago
    can expire mid-session."""
    host = (urlparse(base_url).hostname or "").lower()
    if host != scope.target_host.lower():
        raise ScopeViolation(
            f"scope authorizes host {scope.target_host!r}, but base_url resolves to "
            f"host {host!r} - refusing to scan a host this scope wasn't written for"
        )
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (scope.valid_from <= now <= scope.valid_until):
        raise ScopeViolation(
            f"current time {now.isoformat()} is outside the authorized window "
            f"{scope.valid_from.isoformat()} to {scope.valid_until.isoformat()}"
        )
