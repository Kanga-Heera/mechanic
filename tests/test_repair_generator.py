"""Stage 3 Phase 3, Part 1: generator unit tests - no network, no RSigma.

Covers prompt construction (reusing the existing fragility diagnosis, never
re-deriving it), defensive response parsing, the refuse-loud contract when
no LLM call can be made, and - the anti-circularity claim this whole phase
depends on - a structural (not just textual) check that no benign-event or
evasion data is even reachable from this module's functions.
"""

import inspect

import pytest

from mechanic import llm_client, repair_generator as rg

R5_ORIGINAL = """
title: Known Malicious C2 IP Contacted (single hardcoded IOC, no behavioral fallback)
id: c46a099c-2a31-401d-9ed1-e4be17ac0a7b
status: test
logsource: {category: network_connection, product: windows}
detection:
    selection:
        DestinationIp: '203.0.113.77'
    condition: selection
level: critical
tags: [attack.command-and-control]
"""

REGISTRY_AUTORUN_RULE = """
title: mechanic test - registry autorun (protected literal)
id: 1a2b3c4d-5e6f-7a8b-9c0d-1a2b3c4d5e6f
status: test
logsource: {category: registry_add, product: windows}
detection:
    selection:
        TargetObject|contains: 'CurrentVersion\\\\Run\\\\'
    condition: selection
tags: [attack.persistence, attack.t1547.001]
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


# ---------------------------------------------------------------------------
# Anti-circularity: STRUCTURAL check, not just "the prompt doesn't mention
# it" - assert the actual function signatures have no parameter through
# which benign events, evasion variants, or a gate result could arrive.
# See docs/stage3-phase3-independence.md for the full by-inspection audit.
# ---------------------------------------------------------------------------

_FORBIDDEN_PARAM_SUBSTRINGS = ("benign", "evasion", "gate", "fp", "false_positive")


def test_build_diagnosis_signature_has_no_forbidden_parameters():
    params = list(inspect.signature(rg.build_diagnosis).parameters)
    assert params == ["rule_path"]


def test_build_prompt_signature_has_no_forbidden_parameters():
    params = list(inspect.signature(rg.build_prompt).parameters)
    assert params == ["diagnosis"]
    for p in params:
        assert not any(bad in p.lower() for bad in _FORBIDDEN_PARAM_SUBSTRINGS)


def test_generate_repair_signature_has_no_forbidden_parameters():
    params = list(inspect.signature(rg.generate_repair).parameters)
    for p in params:
        assert not any(bad in p.lower() for bad in _FORBIDDEN_PARAM_SUBSTRINGS), p


def test_repair_diagnosis_dataclass_has_no_forbidden_fields():
    field_names = list(rg.RepairDiagnosis.__dataclass_fields__)
    for f in field_names:
        assert not any(bad in f.lower() for bad in _FORBIDDEN_PARAM_SUBSTRINGS), f


# ---------------------------------------------------------------------------
# Diagnosis reuse - fragility.classify_rule via evasion.fragile_atoms_for_rule,
# never re-derived.
# ---------------------------------------------------------------------------


def test_build_diagnosis_reuses_the_existing_fragility_classifier(tmp_path):
    rule = _write(tmp_path, "r5.yml", R5_ORIGINAL)
    diagnosis = rg.build_diagnosis(rule)
    assert diagnosis.tier == "IOC"
    assert len(diagnosis.fragile_atoms) == 1
    assert diagnosis.fragile_atoms[0]["field"] == "DestinationIp"
    assert diagnosis.fragile_atoms[0]["value"] == "203.0.113.77"
    assert diagnosis.rule_id == "c46a099c-2a31-401d-9ed1-e4be17ac0a7b"
    assert "DestinationIp" in diagnosis.rule_text


def test_build_diagnosis_zero_candidates_for_protected_literal_reflected_honestly(tmp_path):
    """Not this module's job to generate evasions - but the diagnosis it
    hands the LLM should still show the SAME atom mechanic.evasion would
    find zero mechanical evasions for, so the model is working from the
    same information the gate will ultimately check it against."""
    rule = _write(tmp_path, "registry.yml", REGISTRY_AUTORUN_RULE)
    diagnosis = rg.build_diagnosis(rule)
    assert diagnosis.tier == "TTP"  # protected literal -> TTP per fragility.protected_literals
    assert diagnosis.fragile_atoms[0]["field"] == "TargetObject"


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


def test_build_prompt_contains_rule_text_tier_and_atoms(tmp_path):
    rule = _write(tmp_path, "r5.yml", R5_ORIGINAL)
    diagnosis = rg.build_diagnosis(rule)
    messages = rg.build_prompt(diagnosis)
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    user_text = messages[1]["content"]
    assert "DestinationIp" in user_text
    assert "203.0.113.77" in user_text
    assert "tier=IOC" in user_text
    assert rg.NO_REPAIR_SENTINEL in messages[0]["content"]


def test_build_prompt_tells_model_not_to_self_assess():
    diagnosis = rg.RepairDiagnosis(
        rule_path="x.yml", rule_id="id", title="t", rule_text="detection: {}", tier="Tool", fragile_atoms=[]
    )
    messages = rg.build_prompt(diagnosis)
    system_text = messages[0]["content"].lower()
    assert "not being asked to judge" in system_text or "not asked to judge" in system_text


# ---------------------------------------------------------------------------
# Defensive response parsing
# ---------------------------------------------------------------------------


def test_extract_response_parses_fenced_yaml():
    text = "Here you go:\n```yaml\ntitle: x\ndetection: {}\n```"
    proposed, no_repair, note = rg._extract_response(text)
    assert proposed == "title: x\ndetection: {}"
    assert no_repair is False
    assert note is None


def test_extract_response_parses_bare_sentinel():
    proposed, no_repair, note = rg._extract_response("  NO_LOGIC_REPAIR_POSSIBLE.  ")
    assert proposed is None
    assert no_repair is True
    assert note is None


def test_extract_response_rejects_sentinel_buried_in_prose():
    text = "I think NO_LOGIC_REPAIR_POSSIBLE is likely but let me explain why at length."
    proposed, no_repair, note = rg._extract_response(text)
    assert proposed is None
    assert no_repair is False
    assert note is not None


def test_extract_response_flags_off_contract_response():
    proposed, no_repair, note = rg._extract_response("I'm not sure how to help with that.")
    assert proposed is None
    assert no_repair is False
    assert "neither" in note


def test_extract_response_prefers_fence_over_incidental_sentinel_text():
    text = "```yaml\ntitle: x\n```\nNO_LOGIC_REPAIR_POSSIBLE mentioned here too"
    proposed, no_repair, note = rg._extract_response(text)
    assert proposed == "title: x"
    assert no_repair is False


# ---------------------------------------------------------------------------
# Refuse-loud: never fabricate a repair without a real model call
# ---------------------------------------------------------------------------


def test_generate_repair_propagates_config_error_without_fabricating(tmp_path, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_REPO_ROOT", tmp_path)
    rule = _write(tmp_path, "r5.yml", R5_ORIGINAL)
    with pytest.raises(llm_client.LLMConfigError):
        rg.generate_repair(rule)
