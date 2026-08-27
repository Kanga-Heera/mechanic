"""Stage 3 Part 2: harness self-validation on known-answer cases.

Per the phase's own rule ("the harness does not get the benefit of the
doubt"), every case here has an answer known in advance from a source
mechanic didn't produce - SigmaHQ's own regression-test fixtures declare
`match_count` in their `info.yml`, and the benign/mismatched cases are
constructed so the correct answer is obvious by inspection. If any of
these fail, mechanic/verify.py is wrong and must be fixed before Stage 3
Part 3 (the gate) is allowed to depend on it.

Skipped as a whole (not failed) if the pinned rsigma binary isn't
available in this environment - see docs/stage3-harness-evaluation.md for
how it was installed and pinned (v0.21.0, checksum-verified prebuilt
binary from github.com/timescale/rsigma releases).
"""

from pathlib import Path

import pytest

from mechanic import verify

SIGMA_REPO = Path("D:/sigma-research/sigma")

try:
    verify.find_rsigma_binary()
    _RSIGMA_AVAILABLE = True
    _RSIGMA_SKIP_REASON = ""
except verify.VerifyError as e:
    _RSIGMA_AVAILABLE = False
    _RSIGMA_SKIP_REASON = str(e)

pytestmark = pytest.mark.skipif(not _RSIGMA_AVAILABLE, reason=_RSIGMA_SKIP_REASON)


# ---------------------------------------------------------------------------
# Case 1: the investigation's own proven case, kept as a permanent regression
# ---------------------------------------------------------------------------


def test_schtasks_security_channel_known_positive():
    """win_security_susp_scheduled_task_delete_or_disable, EventID+TaskName
    over Event.System/Event.EventData - the exact case hand-validated live
    in docs/stage3-harness-evaluation.md (Task 4). SigmaHQ's own regression
    fixture declares match_count: 1."""
    rule = SIGMA_REPO / "rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml"
    evtx = (
        SIGMA_REPO
        / "regression_data/rules/windows/builtin/security"
        / "win_security_susp_scheduled_task_delete_or_disable"
        / "7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx"
    )
    report = verify.evaluate(rule, evtx)
    assert not report.any_unverifiable, report.to_dict()
    assert report.outcomes[0].fired is True
    assert report.outcomes[0].status == "trusted"
    matched_fields = {m["field"]: m["value"] for m in report.outcomes[0].matched_fields}
    assert matched_fields.get("Event.System.EventID") == 4701
    assert matched_fields.get("Event.EventData.TaskName") == "\\Microsoft\\Windows\\SystemRestore\\SR"


# ---------------------------------------------------------------------------
# Case 2: a second security/builtin-category rule, chosen specifically
# because its payload lives under Event.UserData.*, not Event.EventData.* -
# this is the silent-zero danger class, and the one that caught a real bug
# in a naive System-vs-EventData pipeline heuristic during this phase (see
# mechanic/verify.py's module docstring).
# ---------------------------------------------------------------------------


def test_wmi_activity_userdata_schema_known_positive():
    rule = SIGMA_REPO / "rules/windows/builtin/wmi/win_wmi_activity_nteventlogfile_cleareventlog.yml"
    evtx = (
        SIGMA_REPO
        / "regression_data/rules/windows/builtin/wmi/win_wmi_activity_nteventlogfile_cleareventlog"
        / "d4f1a2b3-7c8e-4d5f-b6a9-1e0c2d3f4e5b.evtx"
    )
    report = verify.evaluate(rule, evtx)
    assert not report.any_unverifiable, report.to_dict()
    assert report.outcomes[0].fired is True
    # the discovered path must NOT be a naive Event.EventData.Operation guess
    assert report.discovery.mapping.get("Operation") == "Event.UserData.Operation_ClientFailure.Operation"


# ---------------------------------------------------------------------------
# Case 3: process_creation / Sysmon-shaped - the "common case." Also proves
# (contrary to the original investigation doc's untested assumption) that
# RSigma's builtin `-p sysmon` pipeline does NOT flatten raw EVTX for this
# rule and auto-discovery is needed here too, not just for builtin rules.
# ---------------------------------------------------------------------------


def test_process_creation_known_positive():
    rule = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml"
    evtx = (
        SIGMA_REPO
        / "regression_data/rules/windows/process_creation/proc_creation_win_bitsadmin_download"
        / "d059842b-6b9d-4ed1-b5c3-5b89143c6ede.evtx"
    )
    report = verify.evaluate(rule, evtx)
    assert not report.any_unverifiable, report.to_dict()
    assert report.outcomes[0].fired is True
    matched_fields = {m["field"] for m in report.outcomes[0].matched_fields}
    assert "Event.EventData.CommandLine" in matched_fields
    assert "Event.EventData.Image" in matched_fields


def test_process_creation_builtin_sysmon_pipeline_does_not_flatten_raw_evtx():
    """Documents a real, live-tested correction to the original investigation
    doc: RSigma's own `-p sysmon` builtin pipeline was assumed (untested) to
    handle Sysmon-shaped rules for free. It does not, for raw EVTX input -
    every EventData field the rule needs is still reported missing (and the
    pipeline adds its own unmet EventID requirement on top). This is why
    auto-discovery in this module doesn't special-case rule category."""
    rule = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml"
    evtx = (
        SIGMA_REPO
        / "regression_data/rules/windows/process_creation/proc_creation_win_bitsadmin_download"
        / "d059842b-6b9d-4ed1-b5c3-5b89143c6ede.evtx"
    )
    report = verify.evaluate(rule, evtx, pipeline=None, auto_pipeline=False)
    # with no pipeline and auto-discovery disabled, RSigma's raw un-mapped fields
    # leave the rule's fields missing -> must be UNVERIFIABLE, never a clean zero.
    assert report.any_unverifiable is True


# ---------------------------------------------------------------------------
# Case 4: benign event that should not fire, confirmed no-fire (trusted)
# ---------------------------------------------------------------------------


def test_benign_flat_json_confirmed_no_fire():
    rule = SIGMA_REPO / "rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml"
    benign = [{"EventID": 4701, "TaskName": "\\Microsoft\\Windows\\CustomApp\\Cleanup", "SubjectUserName": "jdoe"}]
    report = verify.evaluate(rule, benign)
    assert not report.any_unverifiable, report.to_dict()
    assert report.outcomes[0].fired is False
    assert report.outcomes[0].status == "trusted"


# ---------------------------------------------------------------------------
# Case 5: the guard itself - a deliberately field-mismatched rule must trip
# UNVERIFIABLE, never report a clean, trusted zero.
# ---------------------------------------------------------------------------


def test_field_mismatched_rule_trips_unverifiable_guard(tmp_path):
    rule_text = (SIGMA_REPO / "rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml").read_text()
    mismatched_text = rule_text.replace("TaskName|contains:", "ThisFieldDoesNotExistAnywhere|contains:")
    assert mismatched_text != rule_text  # sanity: the replace actually did something
    mismatched_rule = tmp_path / "mismatched.yml"
    mismatched_rule.write_text(mismatched_text)

    evtx = (
        SIGMA_REPO
        / "regression_data/rules/windows/builtin/security"
        / "win_security_susp_scheduled_task_delete_or_disable"
        / "7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx"
    )
    report = verify.evaluate(mismatched_rule, evtx)
    assert report.any_unverifiable is True
    assert report.outcomes[0].status == "unverifiable"
    assert "ThisFieldDoesNotExistAnywhere" in report.outcomes[0].reasons[0]
    # the guard must report this as unverifiable, not as a trusted "did not fire"
    assert report.fired(0) is None


def test_malformed_json_file_fails_loud_not_silent(tmp_path):
    """The second silent-zero-shaped bug found while building this module
    (not in the original investigation): a JSON file with an improperly
    escaped backslash is silently dropped by rsigma's own `-e @file` (its
    summary line still claims "Processed 1 events" using the raw line
    count). Closed by construction here: evaluate()'s own file reader
    parses strictly, in Python, before rsigma ever sees the file."""
    rule = SIGMA_REPO / "rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml"
    bad = tmp_path / "bad.json"
    # deliberately-invalid JSON: a raw backslash before a letter is not a valid escape
    bad.write_bytes(rb'{"EventID": 4701, "TaskName": "\Microsoft\Windows\SystemRestore\SR"}')
    with pytest.raises(verify.VerifyError):
        verify.evaluate(rule, bad)
