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
    speaks the same contract."""

    tier: str
    suggested_owner: str
    icp_fit_score: int
    urgency_score: int
    reasoning: str = Field(max_length=4_000)
    confidence: float


_CASES_PATH = Path(__file__).resolve().parent / "golden_attacks.json"


def load_attack_cases(path: Path | None = None) -> list[AttackCase]:
    """Loads and validates the golden attack set (or `path`, for tests
    that want to feed in a fixture)."""
    raw = json.loads((path or _CASES_PATH).read_text(encoding="utf-8"))
    return [AttackCase(**entry) for entry in raw]
