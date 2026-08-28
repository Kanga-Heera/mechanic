"""Stage 3 Phase 2, Part 3: multi-record EVTX per-record accounting.

Phase 1 left this as a stated gap: any EVTX file with more than one record
came back as a single UNVERIFIABLE aggregate, since there was no way to
correlate a firing match back to which specific record produced it.

The fixture here (tests/fixtures/evtx/multi_record_application_markers.evtx)
is a GENUINE, independently-verifiable multi-record EVTX file, not a
synthetic/hand-built one: 5 records written to this machine's own Windows
Application event log (PowerShell `Write-EventLog`, event ID 9911, source
"Application Error") and exported via `wevtutil epl` - the same real
Windows event-export path any forensic capture goes through. Ground truth
(3 "MALICIOUS" markers at positions 0/2/4, 2 "benign" markers at 1/3) was
read back with `wevtutil qe` - a tool with nothing to do with RSigma or
mechanic - before this file was ever handed to the harness, exactly the
"independently-sourced known answer" discipline test_verify.py's SigmaHQ
fixtures already follow.

Building this fixture also surfaced a third instance of the project's
running silent-zero-shaped-bug theme: this event source uses classic,
non-manifested Windows Event Log <Data> elements (no Name attribute at
all, unlike Sysmon's named EventData), which RSigma reports at a path
ending in `.../Data/#text` rather than `.../Data` - see verify.py's
`_match_key` and its module docstring, finding #3.
"""

from pathlib import Path

import pytest

from mechanic import verify

try:
    verify.find_rsigma_binary()
    _RSIGMA_AVAILABLE = True
    _RSIGMA_SKIP_REASON = ""
except verify.VerifyError as e:
    _RSIGMA_AVAILABLE = False
    _RSIGMA_SKIP_REASON = str(e)

pytestmark = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)

FIXTURE = Path(__file__).parent / "fixtures" / "evtx" / "multi_record_application_markers.evtx"

# Ground truth, independently read via `wevtutil qe Application
# "/q:*[System[(EventID=9911)]]" /f:xml` at fixture-creation time - NOT
# derived from mechanic or RSigma. File order == write order == ascending
# EventRecordID (339051..339055).
_EXPECTED_FIRED_BY_POSITION = [True, False, True, False, True]  # case=1,2,3,4,5

MALICIOUS_RULE = """
title: mechanic test - MALICIOUS marker (multi-record accounting fixture)
id: 5a1a6b3a-6b8a-4b7a-9b8a-5a1a6b3a6b8a
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Data|contains: 'MALICIOUS'
    condition: selection
"""

BENIGN_RULE = """
title: mechanic test - benign marker (multi-record accounting fixture, complementary check)
id: 6b2b7c4b-7c9b-5c8b-ac9b-6b2b7c4b7c9b
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Data|contains: 'benign'
    condition: selection
"""

# References a field this event source never has - whole-file schema
# problem, must poison every record's outcome, not just some.
FIELD_MISMATCH_RULE = """
title: mechanic test - field mismatch (multi-record accounting fixture)
id: 7c3c8d5c-8dac-6d9c-bdac-7c3c8d5c8dac
status: test
logsource: {category: process_creation, product: windows}
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text)
    return p


def test_multirecord_fixture_exists_and_has_five_records():
    assert FIXTURE.exists(), f"multi-record fixture missing: {FIXTURE}"


def test_multi_record_known_composition_malicious_rule(tmp_path):
    rule = _write(tmp_path, "malicious.yml", MALICIOUS_RULE)
    report = verify.evaluate(rule, FIXTURE)
    assert len(report.outcomes) == 5, report.to_dict()
    assert report.any_unverifiable is False, report.to_dict()
    assert [o.fired for o in report.outcomes] == _EXPECTED_FIRED_BY_POSITION, report.to_dict()
    assert report.trusted_fired_count == 3
    assert report.trusted_no_fire_count == 2
    assert all(o.status == "trusted" for o in report.outcomes)


def test_multi_record_known_composition_benign_rule_is_the_exact_complement(tmp_path):
    """Independent cross-check with a second rule keyed on the OTHER
    marker text - if this doesn't come back as the exact complement of the
    malicious-rule result, per-record correlation is broken somewhere."""
    rule = _write(tmp_path, "benign.yml", BENIGN_RULE)
    report = verify.evaluate(rule, FIXTURE)
    assert len(report.outcomes) == 5
    assert report.any_unverifiable is False
    assert [o.fired for o in report.outcomes] == [not x for x in _EXPECTED_FIRED_BY_POSITION]


def test_multi_record_field_mismatch_poisons_every_record_not_silently_some(tmp_path):
    rule = _write(tmp_path, "mismatch.yml", FIELD_MISMATCH_RULE)
    report = verify.evaluate(rule, FIXTURE)
    assert len(report.outcomes) == 5
    assert report.any_unverifiable is True
    assert all(o.status == "unverifiable" for o in report.outcomes), (
        "a whole-file schema problem must poison every record uniformly - "
        f"got: {[o.status for o in report.outcomes]}"
    )
    assert report.unverifiable_count == 5


def test_multi_record_outcomes_carry_a_record_identifying_label(tmp_path):
    rule = _write(tmp_path, "malicious.yml", MALICIOUS_RULE)
    report = verify.evaluate(rule, FIXTURE)
    labels = [o.label for o in report.outcomes]
    assert all(lbl and lbl.startswith("EventRecordID=") for lbl in labels)
    assert len(set(labels)) == 5  # every record has a genuinely distinct id
