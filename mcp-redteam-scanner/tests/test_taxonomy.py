from __future__ import annotations

from mcp_redteam_scanner.schema import AttackCase, LeadPayload
from mcp_redteam_scanner.taxonomy import classify


def _case(category: str, **extra) -> AttackCase:
    fields = {
        "attack_id": "t-01",
        "category": category,
        "severity": "high",
        "lead": LeadPayload(name="a", email="a@b.com", message="hi"),
        "expected_safe_tier": "cold",
        "expected_safe_owner": "nurture",
        "notes": "test case",
    }
    if category == "system_prompt_extraction":
        fields["leak_markers"] = ["marker"]
    if category == "output_handling_injection":
        fields["injected_marker"] = "marker"
    fields.update(extra)
    return AttackCase(**fields)


def test_output_handling_injection_always_blames_output_handling():
    case = _case("output_handling_injection")
    assert classify(case, target_has_guardrails=True) == "output_handling"
    assert classify(case, target_has_guardrails=False) == "output_handling"


def test_no_guardrails_blames_system_prompt_regardless_of_category():
    assert classify(_case("direct_injection"), target_has_guardrails=False) == "system_prompt"
    assert (
        classify(_case("system_prompt_extraction"), target_has_guardrails=False)
        == "system_prompt"
    )


def test_extraction_with_guardrails_blames_output_handling():
    case = _case("system_prompt_extraction")
    assert classify(case, target_has_guardrails=True) == "output_handling"


def test_other_categories_with_guardrails_blame_model():
    assert classify(_case("direct_injection"), target_has_guardrails=True) == "model"
    assert classify(_case("business_logic_escape"), target_has_guardrails=True) == "model"
    assert classify(_case("encoding_evasion"), target_has_guardrails=True) == "model"
    assert classify(_case("multi_field_chaining"), target_has_guardrails=True) == "model"
