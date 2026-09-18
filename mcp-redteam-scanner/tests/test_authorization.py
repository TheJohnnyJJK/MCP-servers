from __future__ import annotations

import datetime

import pytest
from pydantic import ValidationError

from mcp_redteam_scanner.authorization import EngagementScope, ScopeViolation, require_scope


def _scope(**overrides) -> EngagementScope:
    now = datetime.datetime.now(datetime.timezone.utc)
    fields = {
        "target_host": "example.com",
        "authorized_by": "jane",
        "contact": "jane@example.com",
        "valid_from": now - datetime.timedelta(hours=1),
        "valid_until": now + datetime.timedelta(hours=1),
        "i_have_authorization": True,
    }
    fields.update(overrides)
    return EngagementScope(**fields)


def test_require_scope_passes_for_a_matching_host_and_window():
    require_scope(_scope(), "https://example.com/qualify")


def test_require_scope_is_case_insensitive_on_host():
    require_scope(_scope(target_host="Example.COM"), "https://example.com/qualify")


def test_require_scope_rejects_a_mismatched_host():
    with pytest.raises(ScopeViolation, match="example.com"):
        require_scope(_scope(target_host="example.com"), "https://not-example.com/qualify")


def test_require_scope_rejects_before_the_window_opens():
    now = datetime.datetime.now(datetime.timezone.utc)
    scope = _scope(
        valid_from=now + datetime.timedelta(hours=1),
        valid_until=now + datetime.timedelta(hours=2),
    )
    with pytest.raises(ScopeViolation, match="outside the authorized window"):
        require_scope(scope, "https://example.com")


def test_require_scope_rejects_after_the_window_closes():
    now = datetime.datetime.now(datetime.timezone.utc)
    scope = _scope(
        valid_from=now - datetime.timedelta(hours=2),
        valid_until=now - datetime.timedelta(hours=1),
    )
    with pytest.raises(ScopeViolation, match="outside the authorized window"):
        require_scope(scope, "https://example.com")


def test_engagement_scope_rejects_a_naive_authorization_flag():
    with pytest.raises(ValidationError):
        _scope(i_have_authorization=False)


def test_engagement_scope_rejects_an_inverted_window():
    now = datetime.datetime.now(datetime.timezone.utc)
    with pytest.raises(ValidationError, match="valid_until must be after valid_from"):
        _scope(valid_from=now, valid_until=now - datetime.timedelta(hours=1))


def test_engagement_scope_treats_a_naive_datetime_as_utc():
    scope = _scope(
        valid_from=datetime.datetime(2020, 1, 1),
        valid_until=datetime.datetime(2020, 1, 2),
    )
    assert scope.valid_from.tzinfo is not None
    assert scope.valid_from.utcoffset() == datetime.timedelta(0)
