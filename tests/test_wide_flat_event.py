"""Stage 3 Phase 3: verify.full_flat_event_from_evtx - the wide-projection
fix for the narrow-template-event gap the first stratified run surfaced
(see docs/stage3-phase3-status.md). Reuses the same known-good fixture
tests/test_verify.py already validates the narrow flat_event_from_evtx
against, so this is a direct, known-answer comparison of narrow vs wide."""

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

RULE = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml"
EVTX = (
    SIGMA_REPO
    / "regression_data/rules/windows/process_creation/proc_creation_win_bitsadmin_download"
    / "d059842b-6b9d-4ed1-b5c3-5b89143c6ede.evtx"
)


def test_wide_projection_is_a_superset_of_the_narrow_one():
    if not EVTX.exists():
        pytest.skip(f"fixture not present at {EVTX}")
    narrow = verify.flat_event_from_evtx(RULE, EVTX)
    wide = verify.full_flat_event_from_evtx(RULE, EVTX)
    assert set(narrow.keys()) <= set(wide.keys())
    for k, v in narrow.items():
        assert wide[k] == v  # values agree where both resolved the same field


def test_wide_projection_includes_fields_the_rule_never_referenced():
    """The whole point of the fix: fields the rule doesn't reference (e.g.
    Image, ParentImage for a rule keyed only on CommandLine) must still
    show up, so a repair proposing one of them can be checked fairly."""
    if not EVTX.exists():
        pytest.skip(f"fixture not present at {EVTX}")
    narrow = verify.flat_event_from_evtx(RULE, EVTX)
    wide = verify.full_flat_event_from_evtx(RULE, EVTX)
    assert len(wide) > len(narrow)
    assert "Image" in wide  # bitsadmin_download's own rule only references CommandLine
