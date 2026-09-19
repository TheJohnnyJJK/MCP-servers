from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_redteam_scanner.schema import AttackCase, LeadPayload, load_attack_cases


def test_golden_attack_set_loads_and_has_twentysix_cases():
    cases = load_attack_cases()
    assert len(cases) == 26
    assert len({c.attack_id for c in cases}) == 26, "attack_ids must be unique"


def test_all_six_categories_present():
    cases = load_attack_cases()
    categories = {c.category for c in cases}
    assert categories == {
        "direct_injection",
        "system_prompt_extraction",
        "business_logic_escape",
        "output_handling_injection",
        "encoding_evasion",
        "multi_field_chaining",
    }


def test_every_case_has_a_severity():
    cases = load_attack_cases()
    assert all(c.severity in ("critical", "high", "medium", "low") for c in cases)


def test_attack_case_requires_severity():
    with pytest.raises(ValidationError, match="severity"):
        AttackCase(
            attack_id="bad-03",
            category="direct_injection",
            lead=LeadPayload(name="a", email="a@b.com", message="hi"),
            expected_safe_tier="cold",
            expected_safe_owner="nurture",
            notes="missing severity",
        )


def test_system_prompt_extraction_requires_leak_markers():
    with pytest.raises(ValidationError, match="leak_markers"):
        AttackCase(
            attack_id="bad-01",
            category="system_prompt_extraction",
            severity="medium",
            lead=LeadPayload(name="a", email="a@b.com", message="hi"),
            expected_safe_tier="cold",
            expected_safe_owner="nurture",
            notes="missing leak_markers",
        )


def test_output_handling_injection_requires_injected_marker():
    with pytest.raises(ValidationError, match="injected_marker"):
        AttackCase(
            attack_id="bad-02",
            category="output_handling_injection",
            severity="high",
            lead=LeadPayload(name="a", email="a@b.com", message="hi"),
            expected_safe_tier="cold",
            expected_safe_owner="nurture",
            notes="missing injected_marker",
        )
