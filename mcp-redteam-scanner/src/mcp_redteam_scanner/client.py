"""HTTP client for a live target, generalized behind TargetProfile.

TargetHttpClient is the real implementation: it builds a request body
from an attack case's canonical LeadPayload fields, translates field
names/nesting and response paths through a TargetProfile, and validates
whatever comes back into a QualifyResponse. QualifyEndpointTarget is
just that with an identity-mapped profile baked in - Lead Router's own
/qualify contract IS the canonical shape, so it needs no translation at
all, which is why the scanner's original zero-configuration tool
(scan_qualify_endpoint) still works unchanged against it.
"""
from __future__ import annotations

import httpx

from .schema import AttackCase, QualifyResponse, TargetProfile

_RESPONSE_FIELDS = (
    "tier",
    "suggested_owner",
    "icp_fit_score",
    "urgency_score",
    "reasoning",
    "confidence",
)


def _set_path(body: dict, dotted_path: str, value: object) -> None:
    """Writes `value` into `body` at a dotted path, creating
    intermediate dicts as needed - lets field_map point a canonical
    field at a nested location (e.g. "lead.message") on a target that
    doesn't use LeadPayload's own flat shape."""
    *parents, leaf = dotted_path.split(".")
    node = body
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def _get_path(data: object, dotted_path: str) -> object:
    """Reads a dotted path back out of a target's JSON response - the
    read-side counterpart to _set_path. Returns None for any missing or
    non-dict intermediate rather than raising: a target under active
    attack, or one whose response_map is slightly wrong, is exactly the
    case where a hard KeyError would hide a gradable (likely failing)
    result behind a confusing crash instead."""
    node = data
    for part in dotted_path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


class TargetHttpClient:
    """POSTs an attack case's lead payload to a live endpoint, using a
    TargetProfile to translate between this scanner's fixed canonical
    fields and whatever field names, nesting, and response shape the
    actual target uses."""

    def __init__(self, profile: TargetProfile) -> None:
        self.profile = profile
        self._headers = (
            {profile.api_key_header: profile.api_key} if profile.api_key else {}
        )

    def send(self, case: AttackCase) -> QualifyResponse:
        body: dict = {}
        for canonical_field, value in case.lead.model_dump(exclude_none=True).items():
            target_field = self.profile.field_map.get(canonical_field, canonical_field)
            if target_field is None:  # explicitly dropped - this target has no such field
                continue
            _set_path(body, target_field, value)
        response = httpx.post(
            f"{self.profile.base_url.rstrip('/')}{self.profile.path}",
            json=body,
            headers=self._headers,
            timeout=self.profile.timeout,
        )
        # Raises httpx.HTTPStatusError on a 4xx/5xx - deliberately NOT
        # caught here. server.py's _run_scan() is the layer that decides
        # a failed request is itself a result worth recording.
        response.raise_for_status()
        raw = response.json()
        mapped = {
            field: _get_path(raw, self.profile.response_map.get(field, field))
            for field in _RESPONSE_FIELDS
        }
        return QualifyResponse.model_validate(mapped)


class QualifyEndpointTarget(TargetHttpClient):
    """The scanner's original, zero-configuration target: assumes the
    live endpoint speaks Lead Router's own /qualify contract exactly,
    with no field translation needed."""

    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 60.0) -> None:
        super().__init__(TargetProfile(base_url=base_url, api_key=api_key, timeout=timeout))
