"""Data contracts for one attack case and the response it's graded against.

Both models are deliberately loose on the response side: a target under
active attack is exactly the case where you don't want your own model
rejecting its output before the scorer gets a chance to grade it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, model_validator

Category = Literal[
    "direct_injection",
    "system_prompt_extraction",
    "business_logic_escape",
    "output_handling_injection",
]
Tier = Literal["hot", "warm", "cold", "spam"]
Owner = Literal["sales-enterprise", "sales-smb", "nurture", "discard"]
Source = Literal["web_form", "referral", "cold_email", "content_download"]

_ATTACK_ID_MAX = 40
_NOTES_MAX = 600


class LeadPayload(BaseModel):
    """The request body every case sends to POST /qualify."""

    name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    company: str | None = Field(default=None, max_length=300)
    phone: str | None = Field(default=None, max_length=50)
    message: str = Field(min_length=1, max_length=5_000)
    source: Source = "web_form"


class AttackCase(BaseModel):
    """One red-team payload plus the ground truth it's graded against.

    expected_safe_tier/owner is what the lead honestly deserves if the
    injected content is read as inert data, not what an attacker wants.
    """

    attack_id: str = Field(min_length=1, max_length=_ATTACK_ID_MAX)
    category: Category
    lead: LeadPayload
    expected_safe_tier: Tier
    expected_safe_owner: Owner
    leak_markers: list[str] | None = None
    injected_marker: str | None = None
    notes: str = Field(min_length=1, max_length=_NOTES_MAX)

    @model_validator(mode="after")
    def _category_has_its_required_fields(self) -> AttackCase:
        if self.category == "system_prompt_extraction" and not self.leak_markers:
            raise ValueError("system_prompt_extraction requires a non-empty leak_markers list")
        if self.category == "output_handling_injection" and not self.injected_marker:
            raise ValueError("output_handling_injection requires injected_marker")
        return self


class QualifyResponse(BaseModel):
    """Subset of a /qualify response a verdict actually needs. Extra
    fields a target returns (id, created_at, email, ...) are ignored
    rather than modeled, so this stays valid against any target that
    speaks the same contract.

    icp_fit_score/urgency_score/confidence are optional: scorer.py never
    reads them (only tier/suggested_owner/reasoning decide a verdict),
    and a third-party target scanned via TargetProfile has no reason to
    expose Lead Router's own internal scoring fields at all."""

    tier: str
    suggested_owner: str
    icp_fit_score: int | None = None
    urgency_score: int | None = None
    reasoning: str = Field(max_length=4_000)
    confidence: float | None = None


class TargetProfile(BaseModel):
    """Everything needed to point the fixed 18-case attack set at a
    target that doesn't share Lead Router's own /qualify contract
    verbatim - a different URL path, different field names, extra
    request nesting, or a differently-shaped response. The attack
    content itself (what's actually injected, and into which conceptual
    field) never changes; only where it's delivered and read back from.

    Both maps are keyed by this scanner's canonical field names -
    LeadPayload's own (name/email/company/phone/message/source) for
    field_map, QualifyResponse's own (tier/suggested_owner/
    icp_fit_score/urgency_score/reasoning/confidence) for response_map -
    and a canonical field with no entry is sent/read under its own name,
    unchanged. Lead Router's real contract IS that identity mapping, so
    QualifyEndpointTarget (client.py) uses an empty TargetProfile."""

    base_url: str
    path: str = "/qualify"
    api_key: str | None = None
    api_key_header: str = "X-API-Key"
    # Canonical request field -> this target's own field name, as a
    # dotted path for a nested body (e.g. "lead.message"). Mapped to
    # None, a field is omitted from the request entirely - useful for a
    # target with no equivalent of e.g. "phone".
    field_map: dict[str, str | None] = Field(default_factory=dict)
    # Canonical response field -> a dotted path into this target's own
    # JSON response (e.g. "result.tier" for a nested decision object).
    response_map: dict[str, str] = Field(default_factory=dict)
    timeout: float = 60.0


_CASES_PATH = Path(__file__).resolve().parent / "golden_attacks.json"


def load_attack_cases(path: Path | None = None) -> list[AttackCase]:
    """Loads and validates the golden attack set (or `path`, for tests
    that want to feed in a fixture)."""
    raw = json.loads((path or _CASES_PATH).read_text(encoding="utf-8"))
    return [AttackCase(**entry) for entry in raw]
