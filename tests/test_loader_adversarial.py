"""Hardening Part 1: the core's headline property is "one malformed file
never kills a batch." This file proves it holds at the edges - a fixture
(or synthetic scenario) per adversarial case named in the hardening brief,
each asserting the SAME three things: the scan completes, the bad input is
reported with a specific reason, and every good rule alongside it still
loads.

Two cases from the brief - "a repo with no .git" and "a shallow clone
(must fail LOUD, not silently under-report)" - are existing, already-locked
behavior in tests/test_churn.py (`test_no_git_history_fails_clearly`,
`test_shallow_clone_fails_clearly`); not duplicated here, referenced by
name so the coverage is traceable from one place.
"""

from __future__ import annotations

import os
import random
import string
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from mechanic import discovery, loader

GOOD_RULE = (
    "title: Suspicious Certutil Download\n"
    "id: {rid}\n"
    "status: test\n"
    "logsource:\n  category: process_creation\n  product: windows\n"
    "detection:\n"
    "  selection:\n"
    "    Image|endswith: '\\certutil.exe'\n"
    "    CommandLine|contains: '-urlcache'\n"
    "  condition: selection\n"
)


def _good_rule_text(n: int = 0) -> str:
    return GOOD_RULE.format(rid=str(uuid.UUID(int=n)))


def _scan_completes_with_reason(tmp_path: Path, bad_filename: str, bad_content: bytes | str) -> loader.ScanResult:
    """Shared shape for most of the cases below: one bad file plus one good
    file in the same directory; assert the scan finishes, the good rule
    loads, and the bad file is reported (never silently dropped, never a
    crash)."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    good_path = rules_dir / "good.yml"
    good_path.write_text(_good_rule_text(1))
    bad_path = rules_dir / bad_filename
    if isinstance(bad_content, bytes):
        bad_path.write_bytes(bad_content)
    else:
        bad_path.write_text(bad_content)

    result = loader.load_ruleset(rules_dir, "sigma")

    assert result.files_scanned == 2, "scan must see both files"
    assert len(result.rules) == 1, "the good rule must still load despite the bad one"
    assert result.rules[0].file == str(good_path)
    assert result.files_scanned == result.files_ok + result.files_failed, (
        "every scanned file must land in exactly one bucket - none silently unaccounted for"
    )
    assert result.files_failed == 1
    assert len(result.failures) >= 1, "the bad file must be reported, not silently dropped"
    return result


def test_empty_file(tmp_path: Path):
    result = _scan_completes_with_reason(tmp_path, "empty.yml", "")
    assert result.failures[0].category == "empty_or_no_documents"


def test_comments_only_file(tmp_path: Path):
    """A file that is only YAML comments parses to zero documents, same
    shape as truly empty - must be flagged the same way, not silently
    treated as 'nothing to do here.'"""
    result = _scan_completes_with_reason(tmp_path, "comments.yml", "# just a comment\n# and another\n")
    assert result.failures[0].category == "empty_or_no_documents"


def test_bare_document_marker_only(tmp_path: Path):
    result = _scan_completes_with_reason(tmp_path, "bare.yml", "---\n")
    assert result.failures[0].category == "empty_or_no_documents"


def test_non_yaml_binary_junk(tmp_path: Path):
    """Genuinely non-text/binary content, decoded with errors='replace' by
    the loader - must not crash the batch even if the result is garbage."""
    junk = bytes(random.Random(1).randbytes(4096))
    result = _scan_completes_with_reason(tmp_path, "binary.yml", junk)
    assert result.failures[0].stage in ("yaml_parse", "rule_construct")


def test_truncated_yaml(tmp_path: Path):
    truncated = "title: Truncated\ndetection:\n  selection:\n    Image|endswith: [\"a\", \"b\"\n"
    result = _scan_completes_with_reason(tmp_path, "truncated.yml", truncated)
    assert result.failures[0].category == "yaml_parser_error"


def test_valid_yaml_list_not_a_mapping(tmp_path: Path):
    result = _scan_completes_with_reason(tmp_path, "list.yml", "- a\n- b\n- c\n")
    assert result.failures[0].category == "non_mapping_document"


def test_valid_yaml_scalar_not_a_mapping(tmp_path: Path):
    result = _scan_completes_with_reason(tmp_path, "scalar.yml", "just a plain string\n")
    assert result.failures[0].category == "non_mapping_document"


def test_all_fields_null(tmp_path: Path):
    result = _scan_completes_with_reason(
        tmp_path, "allnull.yml", "title:\nid:\nstatus:\nlogsource:\ndetection:\ncondition:\n"
    )
    # Whatever pySigma's exact exception is here, it must be captured (never
    # an uncaught traceback) and reported with SOME reason - the exact
    # uncategorized_<ExceptionType> bucket is allowed to shift with pySigma
    # version, so this only pins "it was caught and named," not the name.
    assert result.failures[0].message


def test_no_detection_block(tmp_path: Path):
    result = _scan_completes_with_reason(
        tmp_path,
        "nodetection.yml",
        "title: No Detection\nid: 44444444-4444-4444-4444-444444444444\nstatus: test\n"
        "logsource:\n  category: process_creation\n",
    )
    assert result.failures[0].message


def test_utf8_bom_rule_loads_cleanly(tmp_path: Path):
    """A BOM is not corruption - a rule authored/saved by an editor that
    writes one (common on Windows) must load exactly as if it hadn't. This
    is a "must NOT be flagged as bad" case, the inverse of the others."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    content = _good_rule_text(2).encode("utf-8")
    (rules_dir / "bom.yml").write_bytes(b"\xef\xbb\xbf" + content)
    result = loader.load_ruleset(rules_dir, "sigma")
    assert len(result.rules) == 1
    assert not result.failures


def test_crlf_line_endings_load_cleanly(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    crlf_content = _good_rule_text(3).replace("\n", "\r\n").encode("utf-8")
    (rules_dir / "crlf.yml").write_bytes(crlf_content)
    result = loader.load_ruleset(rules_dir, "sigma")
    assert len(result.rules) == 1
    assert not result.failures


def test_10mb_junk_file_does_not_hang_or_crash(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yml").write_text(_good_rule_text(4))
    rng = random.Random(42)
    junk = "".join(rng.choices(string.ascii_letters + string.digits + " :{}[]\n-", k=10 * 1024 * 1024))
    (rules_dir / "huge.yml").write_text(junk)

    t0 = time.time()
    result = loader.load_ruleset(rules_dir, "sigma")
    elapsed = time.time() - t0

    assert elapsed < 30, f"10MB adversarial file took {elapsed:.1f}s - should be well under 30s"
    assert len(result.rules) == 1
    assert result.files_scanned == result.files_ok + result.files_failed


def test_directory_with_zero_rules(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    result = loader.load_ruleset(rules_dir, "sigma")
    assert result.files_scanned == 0
    assert result.rules == []
    assert result.failures == []


def test_file_vanishes_mid_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Regression for the real Windows-Defender-quarantine incident
    (docs/... / RESULTS.md, Stage 2 "Practical obstacles" #2): a file that
    exists at discovery time but is gone (or locked) by the time it's
    opened must be reported, not crash the batch."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    good_path = rules_dir / "good.yml"
    good_path.write_text(_good_rule_text(5))
    vanishing_path = rules_dir / "vanishing.yml"
    vanishing_path.write_text(_good_rule_text(6))  # must exist for discovery to find it

    real_read_text = Path.read_text

    def flaky_read_text(self: Path, *args, **kwargs):
        if self.name == "vanishing.yml":
            raise FileNotFoundError(f"[simulated mid-scan vanish] {self}")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", flaky_read_text)
    result = loader.load_ruleset(rules_dir, "sigma")

    assert result.files_scanned == 2
    assert len(result.rules) == 1
    assert result.rules[0].file == str(good_path)
    assert result.files_failed == 1
    assert result.failures[0].category == "unreadable_file"
    assert result.failures[0].file == str(vanishing_path)


def _mklink_junction(link: Path, target: Path) -> bool:
    """Create a Windows directory junction (no elevated privilege needed,
    unlike os.symlink on Windows) or a real symlink on POSIX. Returns False
    if neither is possible in this environment (test skips rather than
    failing - the protection is still exercised directly via the
    non-privileged unit test below regardless)."""
    if sys.platform == "win32":
        r = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True
        )
        return r.returncode == 0
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except OSError:
        return False


def test_symlink_or_junction_loop_terminates(tmp_path: Path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yml").write_text(_good_rule_text(7))
    loop_dir = rules_dir / "loop"
    if not _mklink_junction(loop_dir, rules_dir):
        pytest.skip("could not create a symlink/junction in this environment (needs a privilege this sandbox lacks)")

    t0 = time.time()
    files = discovery.discover_files(rules_dir, "sigma")
    elapsed = time.time() - t0

    assert elapsed < 10, f"symlink/junction loop took {elapsed:.1f}s to resolve - should terminate near-instantly"
    assert len(files) == 1, f"cycle protection should visit each real directory once, got {files}"

    # And the full loader pipeline on top, since discovery alone isn't the
    # whole story - a batch scan through the loop must also complete.
    result = loader.load_ruleset(rules_dir, "sigma")
    assert len(result.rules) == 1


def test_directory_identity_cycle_detection_unit():
    """Direct unit coverage of the cycle-detection primitive itself,
    independent of whether this environment can create a real symlink/
    junction: the same real directory, stat'd twice, must report the same
    identity (this is what discover_files uses to refuse re-entry)."""
    from mechanic.discovery import _dir_identity

    here = Path(__file__).parent
    assert _dir_identity(here) == _dir_identity(here)
    assert _dir_identity(here) != _dir_identity(here.parent)


@pytest.mark.parametrize("n", [30, 200])
def test_perf_sanity_roughly_linear(tmp_path: Path, n: int):
    """Not a full 10,000-rule run (that would make every test invocation
    take several minutes - see test_perf_sanity_10k_opt_in below for the
    real thing, opt-in). Two sizes ~6.7x apart, each checked against a
    generous flat per-rule time budget (observed baseline ~43ms/rule on
    this dev machine; budgeted at 4x that) - a scan degrading to
    meaningfully-worse-than-linear (an accidental O(n^2) in discovery or
    accounting) would blow this budget at the larger size even though the
    smaller size passes comfortably."""
    rules_dir = tmp_path / f"rules_{n}"
    rules_dir.mkdir()
    for i in range(n):
        (rules_dir / f"rule_{i}.yml").write_text(_good_rule_text(i))
    t0 = time.time()
    result = loader.load_ruleset(rules_dir, "sigma")
    elapsed = time.time() - t0
    assert len(result.rules) == n
    assert result.files_scanned == result.files_ok + result.files_failed
    per_rule_budget_s = 0.20
    assert elapsed < n * per_rule_budget_s, (
        f"{n} rules took {elapsed:.1f}s ({elapsed / n * 1000:.1f}ms/rule) - "
        f"over the {per_rule_budget_s * 1000:.0f}ms/rule budget, possible non-linear regression"
    )


@pytest.mark.skipif(
    os.environ.get("MECHANIC_RUN_SLOW_TESTS") != "1",
    reason="10,000-rule perf-sanity run is slow (multiple minutes) - opt in with MECHANIC_RUN_SLOW_TESTS=1",
)
def test_perf_sanity_10k_opt_in(tmp_path: Path):
    """The literal case from the hardening brief: a directory with 10,000
    rules must not crash, hang, or blow up memory - it must finish and
    load every rule. Not run by default (see skip reason above) so the
    normal `pytest` invocation used during development stays fast; run
    deliberately (e.g. before a release) with MECHANIC_RUN_SLOW_TESTS=1."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    n = 10_000
    for i in range(n):
        (rules_dir / f"rule_{i}.yml").write_text(_good_rule_text(i))
    t0 = time.time()
    result = loader.load_ruleset(rules_dir, "sigma")
    elapsed = time.time() - t0
    assert result.files_scanned == n
    assert len(result.rules) == n
    assert not result.failures
    print(f"\n10,000-rule scan: {elapsed:.1f}s ({elapsed / n * 1000:.2f}ms/rule)")
