"""Staleness / organic churn (Component 2).

All git access goes through PyDriller (`pydriller.Repository`); repo-level
raw commit counts are cross-checked against `pydriller.metrics.process`. No
subprocess git calls, no manual `git log` parsing.

Mass mechanical commits (bulk reformats, metadata-schema migrations, CI
housekeeping) dominate raw commit counts and make them useless as a
maintenance signal - the largest single commits observed in prior
investigation were SigmaHQ 2,931 files, Splunk 2,073, Elastic 1,064 in one
commit each. This module filters those out *before* computing any statistic,
and reports exactly what was excluded so the filter is auditable rather than
a magic number.
"""

from __future__ import annotations

import pickle
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from statistics import mean, median
from typing import Any, Callable, Optional

from pydriller import Repository
from pydriller.domain.commit import Commit
from pydriller.metrics.process.commits_count import CommitsCount

from mechanic.discovery import FORMATS, RuleFormat, discover_files

DEFAULT_THRESHOLD = 0.10
REPORT_THRESHOLDS = (0.05, 0.10, 0.20)
STALE_DAYS = 730  # > 2 years
RECENT_DAYS = 182  # touched within 6 months

# Below this many total mined commits, staleness statistics are still
# computed (this is NOT a hard failure like NoGitHistoryError/
# ShallowRepositoryError - some history exists and every number reported is
# real), but there simply isn't enough history for the resulting percentages
# to mean much. Deliberately small and conservative: this is a floor below
# which "insufficient" is unambiguous, not a tuned-to-look-good number, and
# genuinely borderline repos (dozens of commits) are left as HEALTHY rather
# than manufacturing a false sense of precision about exactly where
# "enough" begins.
DEGRADED_HISTORY_MIN_COMMITS = 5

HEALTH_HEALTHY = "healthy"
HEALTH_DEGRADED = "degraded"

# Shared default for every caller that wants SOME timeout protection without
# picking a number itself (the CLI's `--mining-timeout` default, and the
# GUI's job runner). 30 minutes is generous enough for every corpus this
# project has actually mined (SigmaHQ/Elastic/Splunk all finish well under
# that - RESULTS.md's timing section) while still turning a genuine hang
# into a clear, bounded failure instead of an indefinite one. The library
# functions themselves (`mine_commits`, `compute_staleness`, ...) still
# default their own `timeout` parameter to `None` (no timeout) - this
# constant is an opt-in convenience for callers, never a silently-changed
# default behavior.
DEFAULT_MINING_TIMEOUT_SECONDS = 1800


class ChurnError(Exception):
    """Base class for conditions that would silently produce wrong staleness
    numbers if not surfaced to the user."""


class NoGitHistoryError(ChurnError):
    def __init__(self, root: Path):
        super().__init__(
            f"{root} has no git history (no .git directory, or zero commits). "
            "Staleness requires git history - point mechanic at a real clone."
        )


class ShallowRepositoryError(ChurnError):
    def __init__(self, root: Path):
        super().__init__(
            f"{root} is a shallow git clone (found .git/shallow). A shallow clone's "
            "commit history is truncated, which silently understates organic commit "
            "counts and understates staleness. Run `git fetch --unshallow` (or "
            "reclone without --depth) in this repo before running staleness on it."
        )


class MiningTimeoutError(ChurnError):
    """Raised when a full-history mining pass exceeds its wall-clock budget.

    Context: `_modified_files_no_patch`'s own docstring documents a real,
    reproducibly diagnosed (via `py-spy dump`) GitPython/Windows deadlock in
    `Diffable.diff()`'s stdout/stderr-pumping threads, hit while mining
    `splunk/security_content`'s ~28,000-commit history - already fixed by
    replacing that specific call with a plain `git diff-tree` subprocess
    call carrying its own 30-second timeout, which cannot deadlock the same
    way (confirmed by benchmark: all 28,249 commits diffed in ~18 minutes
    with zero hangs). This timeout is a SEPARATE, outer safety net around
    the WHOLE mining pass (commit walking, not just per-commit diffing) -
    defense-in-depth against a different or future hang, not a re-fix of an
    already-fixed one.

    Known limitation, stated rather than hidden: this is implemented as a
    daemon background thread with `.join(timeout=...)`, not a killable
    subprocess. Python has no safe, cross-platform way to forcibly
    terminate a thread blocked in a C-level blocking call - so on timeout,
    control returns to the caller immediately (the process does NOT hang),
    but the orphaned mining thread may continue running in the background
    until it finishes on its own or the process exits (a daemon thread is
    reclaimed by the OS at process exit, not left as a zombie). A true
    subprocess-based kill was considered and rejected here as
    disproportionate: it would need to serialize `_CommitFacts` across a
    process boundary and reimplement `progress_cb` over IPC, for a failure
    class (an indefinite hang with zero forward progress) this project has
    only ever reproduced in the diff step already fixed above.
    """

    def __init__(self, root: Path, timeout: float):
        super().__init__(
            f"mining {root} exceeded the {timeout:.0f}s mining timeout with no result. "
            "This is a wall-clock safety net, not a claim about what's wrong with the "
            "repo - rerun with a larger --mining-timeout if this repo is just large, or "
            "investigate (e.g. `py-spy dump` on the mechanic process) if it recurs on a "
            "repo that previously mined fine."
        )
        self.root = root
        self.timeout = timeout


def _mine_with_timeout(fn: Callable[[], list["_CommitFacts"]], root: Path, timeout: Optional[float]) -> list["_CommitFacts"]:
    """Runs `fn` (a zero-arg thunk wrapping a full mining pass) directly if
    `timeout` is None (the default - every existing call site is
    byte-for-byte unaffected), otherwise on a daemon background thread with
    a hard wall-clock join timeout. See `MiningTimeoutError` for exactly
    what this does and does not guarantee."""
    if timeout is None:
        return fn()

    result: dict[str, Any] = {}
    error: dict[str, BaseException] = {}

    def _worker() -> None:
        try:
            result["facts"] = fn()
        except BaseException as e:  # re-raised on the calling thread below
            error["exc"] = e

    t = threading.Thread(target=_worker, daemon=True, name="mechanic-mining")
    t.start()
    t.join(timeout=timeout)
    if t.is_alive():
        print(
            f"[mechanic] MINING TIMEOUT: {root} exceeded {timeout:.0f}s - aborting this "
            "mining attempt (the background thread may continue running; see "
            "MiningTimeoutError's docstring for why it cannot be forcibly killed).",
            file=sys.stderr,
            flush=True,
        )
        raise MiningTimeoutError(root, timeout)
    if "exc" in error:
        raise error["exc"]
    return result["facts"]


@dataclass
class ExcludedCommit:
    hash: str
    subject: str
    rule_files_touched: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "hash": self.hash,
            "subject": self.subject,
            "rule_files_touched": self.rule_files_touched,
        }


@dataclass
class RuleChurn:
    file: str
    organic_commit_count: int
    last_organic_commit_date: Optional[date]
    days_since: Optional[int]
    # Optional[bool]: None means "cannot be determined from available git
    # history" - NOT a silent false. See `_ever_revised` for exactly which
    # cases resolve to True/False/None and why. `ever_revised_basis` names
    # the reasoning in every case so a caller never has to guess why a
    # given value was produced.
    ever_revised: Optional[bool]
    ever_revised_basis: str
    distinct_author_count: int
    # Additive Part 1 (semantic diff) fields. None/absent until a caller runs
    # `mechanic.semantic_diff.enrich_staleness_report` on this report - plain
    # `mechanic staleness` (Pass 1 only, cheap) never populates these, since
    # Pass 2 (fetching + classifying diff content) is the expensive step this
    # schema is deliberately kept separable from.
    behavioral_commit_count: Optional[int] = None
    last_behavioral_change: Optional[date] = None
    days_since_behavioral_change: Optional[int] = None
    cosmetic_commit_count: Optional[int] = None
    semantic_metadata_commit_count: Optional[int] = None
    classification_confidence: Optional[str] = None  # "high" | "medium" | "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "organic_commit_count": self.organic_commit_count,
            "last_organic_commit_date": (
                self.last_organic_commit_date.isoformat() if self.last_organic_commit_date else None
            ),
            "days_since": self.days_since,
            "ever_revised": self.ever_revised,
            "ever_revised_basis": self.ever_revised_basis,
            "distinct_author_count": self.distinct_author_count,
            "behavioral_commit_count": self.behavioral_commit_count,
            "last_behavioral_change": (
                self.last_behavioral_change.isoformat() if self.last_behavioral_change else None
            ),
            "days_since_behavioral_change": self.days_since_behavioral_change,
            "cosmetic_commit_count": self.cosmetic_commit_count,
            "semantic_metadata_commit_count": self.semantic_metadata_commit_count,
            "classification_confidence": self.classification_confidence,
        }


@dataclass
class ThresholdSensitivity:
    threshold: float
    excluded_commits: list[ExcludedCommit]

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "excluded_commit_count": len(self.excluded_commits),
            "excluded_commits": [c.to_dict() for c in self.excluded_commits],
        }


@dataclass
class StalenessReport:
    root: str
    rule_count: int
    mechanical_threshold: float
    raw_commit_total: int  # unfiltered, whole-repo commit-touch count over the trailing 365 days
    raw_commit_window_days: int
    excluded_commits: list[ExcludedCommit]
    rules: list[RuleChurn] = field(default_factory=list)
    sensitivity: list[ThresholdSensitivity] = field(default_factory=list)
    # Distinct from NoGitHistoryError/ShallowRepositoryError, which ABORT
    # before a report is ever built - this describes a report that DID get
    # built from real (unfaked) numbers, but whose history is thin enough
    # that those numbers deserve a caveat. "healthy" unless a reason below
    # fired. Never blocks anything; purely informational.
    history_health: str = HEALTH_HEALTHY
    history_health_reasons: list[str] = field(default_factory=list)

    @property
    def rules_with_history(self) -> list[RuleChurn]:
        return [r for r in self.rules if r.organic_commit_count > 0]

    def summary(self) -> dict[str, Any]:
        rated = self.rules_with_history
        counts = [r.organic_commit_count for r in rated]
        n = len(self.rules)
        return {
            "rule_count": n,
            "rules_with_no_organic_history": n - len(rated),
            "mean_organic_commits_per_rule": mean(counts) if counts else 0.0,
            "median_organic_commits_per_rule": median(counts) if counts else 0.0,
            "pct_ever_revised": 100.0 * sum(1 for r in rated if r.ever_revised) / n if n else 0.0,
            "pct_touched_within_6mo": (
                100.0 * sum(1 for r in rated if r.days_since is not None and r.days_since <= RECENT_DAYS) / n
                if n
                else 0.0
            ),
            "pct_stale_over_2yr": (
                100.0 * sum(1 for r in rated if r.days_since is not None and r.days_since > STALE_DAYS) / n
                if n
                else 0.0
            ),
        }

    def top_stalest(self, top_n: int) -> list[RuleChurn]:
        rated = [r for r in self.rules if r.days_since is not None]
        return sorted(rated, key=lambda r: r.days_since, reverse=True)[:top_n]

    def to_dict(self, top_n: Optional[int] = None) -> dict[str, Any]:
        d: dict[str, Any] = {
            "root": self.root,
            "rule_count": self.rule_count,
            "mechanical_threshold": self.mechanical_threshold,
            "raw_commit_total": self.raw_commit_total,
            "raw_commit_window_days": self.raw_commit_window_days,
            "excluded_commits": [c.to_dict() for c in self.excluded_commits],
            "summary": self.summary(),
            "sensitivity": [s.to_dict() for s in self.sensitivity],
            "rules": [r.to_dict() for r in self.rules],
            "history_health": self.history_health,
            "history_health_reasons": self.history_health_reasons,
        }
        if top_n is not None:
            d["top_stalest"] = [r.to_dict() for r in self.top_stalest(top_n)]
        return d


def _check_git_preconditions(root: Path) -> None:
    git_dir = root / ".git"
    if not git_dir.exists():
        raise NoGitHistoryError(root)
    if (git_dir / "shallow").exists():
        raise ShallowRepositoryError(root)


def _rule_extensions(fmt: RuleFormat) -> set[str]:
    exts = set()
    for glob in fmt.globs:
        exts.add(Path(glob).suffix)
    return exts


def _is_rule_path(
    path: Optional[str],
    extensions: set[str],
    exclude_dirs: tuple[str, ...],
    subdir_prefix: Optional[str] = None,
) -> bool:
    if not path:
        return False
    p = Path(path)
    if p.suffix not in extensions:
        return False
    if subdir_prefix is not None and not path.startswith(subdir_prefix + "/"):
        return False
    return not any(part in exclude_dirs for part in p.parts)


@dataclass
class FileChangeFact:
    """One rule file's change within one commit - the file-level granularity
    Part 1 (semantic diff) needs that the flattened `rule_paths_touched` /
    `renames` lists on `_CommitFacts` don't preserve (which old_path goes with
    which new_path when a commit touches several rule files at once, some
    renamed, some not, some newly added)."""

    old_path: Optional[str]  # None if the file didn't exist before this commit (created here)
    new_path: Optional[str]  # None if the file was deleted in this commit
    change_type: str  # pydriller ModificationType name: ADD | MODIFY | RENAME | DELETE | ...


@dataclass
class _CommitFacts:
    hash: str
    parent_hash: Optional[str]
    is_merge: bool
    subject: str
    author_key: str
    author_date: date
    rule_paths_touched: list[str]  # canonical-ish paths (pre-rename-resolution) this commit touched
    renames: list[tuple[str, str]]  # (old_path, new_path) for rule files renamed in this commit
    file_changes: list[FileChangeFact] = field(default_factory=list)



class _FallbackChangeType:
    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name


class _FallbackModifiedFile:
    """Minimal stand-in for pydriller's `ModifiedFile`, exposing only the
    three attributes `_mine_commits` actually reads (`old_path`, `new_path`,
    `change_type.name`). Named for its origin as a fallback from a GitPython
    diff path that deadlocked (see `_modified_files_no_patch`'s docstring);
    that GitPython path has since been removed entirely and this is now the
    only way modified-file facts are produced, not a rare fallback."""

    __slots__ = ("old_path", "new_path", "change_type")

    def __init__(self, old_path: Optional[str], new_path: Optional[str], change_type: str) -> None:
        self.old_path = old_path
        self.new_path = new_path
        self.change_type = _FallbackChangeType(change_type)


def _git_diff_via_subprocess(root: Path, args: list[str]) -> list[_FallbackModifiedFile]:
    """Reconstruct modified-file facts via a plain `git` subprocess call with
    its own timeout, bypassing GitPython's `Diffable.diff()` entirely.

    Exists because `Diffable.diff()` internally spawns a `git` subprocess and
    blocks the calling thread in `handle_process_output`, joining two
    background threads that pump the subprocess's stdout/stderr - and this
    was observed, reproducibly (confirmed via `py-spy dump` on a genuinely
    hung process, not assumed), to deadlock on this machine while mining
    `splunk/security_content`'s ~28,000-commit history: the main thread sat
    forever in `join()` waiting on a stream-pump thread that never returned,
    with 0 forward CPU progress. This is a known category of GitPython/
    Windows subprocess-pipe fragility, not a mechanic logic bug - and a
    plain `subprocess.run(..., timeout=...)` call sidesteps GitPython's
    threaded pump mechanism altogether, so it cannot deadlock the same way.
    """
    result = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-status", "-r", "-M", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=30,
        encoding="utf-8",
        errors="replace",
    )
    files: list[_FallbackModifiedFile] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") or status.startswith("C"):
            old_path, new_path = parts[1], parts[2]
            change_type = "RENAME" if status.startswith("R") else "COPY"
        elif status == "A":
            old_path, new_path = None, parts[1]
            change_type = "ADD"
        elif status == "D":
            old_path, new_path = parts[1], None
            change_type = "DELETE"
        else:  # M, T (type change), etc. - treated as a plain modify
            old_path, new_path = parts[1], parts[1]
            change_type = "MODIFY"
        files.append(_FallbackModifiedFile(old_path, new_path, change_type))
    return files


def _modified_files_no_patch(commit: Commit, root: Path) -> list[_FallbackModifiedFile]:
    """Equivalent to `commit.modified_files`, but without asking GitPython to
    build unified-diff patch text (`create_patch=True`) for every file, and
    without going through GitPython's `Diffable.diff()` at all.

    We only ever read `.old_path`/`.new_path`/`.change_type` off the result -
    all three come straight off `git diff-tree`'s own rename-detected
    name-status output, so a plain `git diff-tree` subprocess call
    (`_git_diff_via_subprocess`) is sufficient; no patch text, and no
    GitPython `Diff` object, is ever needed.

    DEPLOYMENT HISTORY (kept because it explains why this looks the way it
    does, not because the old path is still reachable): this function
    originally called GitPython's `c.parents[0].diff(...)` first, in a
    daemon thread with a 15-second timeout, falling back to
    `_git_diff_via_subprocess` only when that timeout fired. That design was
    built around a real, reproducible finding - confirmed via three separate
    `py-spy dump` traces on a genuinely hung process, not assumed - that
    GitPython's `Diffable.diff()` can deadlock on Windows (the main thread
    blocks in `handle_process_output`'s `join()`, waiting on background
    `pump_stream` threads reading the underlying `git` subprocess's stdout/
    stderr that never signal completion). Two things about that design are
    also worth keeping on record: (1) an even earlier version shared one
    `ThreadPoolExecutor(max_workers=1)` across calls, which meant that once
    ONE commit deadlocked, that sole worker stayed occupied and every
    subsequent commit's diff call queued forever behind it - a self-inflicted
    bug found and fixed (switched to a fresh `threading.Thread` per call)
    before the underlying GitPython issue was even correctly identified; (2)
    even with that fix, the deadlock turned out to recur across MANY commits
    in `splunk/security_content`'s history, not one rare one, so the
    15-second timeout was being paid repeatedly and the aggregate mining run
    stayed impractically slow (see RESULTS.md's practical-obstacles section
    for the full diagnostic trail).

    That motivated benchmarking subprocess-only diffing as the PRIMARY path
    instead of a timeout-triggered fallback (`scratchpad/
    profile_splunk_subprocess.py`): all 28,249 commits in
    `splunk/security_content` diffed in 1,073.1 seconds (~37ms/commit
    average, dominated by per-call process-spawn overhead, not blocking) -
    fast enough, and immune to the GitPython deadlock class by construction,
    since it never touches GitPython's threaded stdout/stderr pump path at
    all. Deployed here after that benchmark confirmed it; the threaded-
    timeout design and its own `_fallback_diff_count` bookkeeping were
    removed as dead code once subprocess calls stopped being a fallback and
    became the only path.
    """
    c = commit._c_object
    if len(commit.parents) == 1:
        return _git_diff_via_subprocess(root, [c.parents[0].hexsha, c.hexsha])
    elif len(commit.parents) > 1:
        return []  # merge commit: pydriller does the same (see Commit.modified_files)
    else:
        return _git_diff_via_subprocess(root, ["--root", c.hexsha])


def _mine_commits(
    root: Path,
    fmt: RuleFormat,
    subdir_prefix: Optional[str] = None,
    single: Optional[str] = None,
    progress_cb: Optional[Callable[[int], None]] = None,
) -> list[_CommitFacts]:
    """`single`, if given (a commit hash), mines exactly that one commit
    instead of walking the whole history - PyDriller's own `Repository(...,
    single=...)` targets one commit without a full traversal, so this stays
    fast even on a huge repo. Used by the Part 4 hardening regression-lock
    test (tests/test_validated_numbers_lock.py) to re-check a specific
    historical mechanical commit's rule-file-touch count without re-mining
    all of SigmaHQ/Elastic/Splunk's history just to check one commit.

    `progress_cb`, if given, is called with a running commit-count roughly
    every 250 commits (real progress off the actual traversal, not a timer
    or an estimate - added for the GUI's "mining N commits..." status, does
    not change what's mined or returned)."""
    extensions = _rule_extensions(fmt)
    exclude_dirs = fmt.exclude_dirs
    facts: list[_CommitFacts] = []
    repo_kwargs = {"single": single} if single else {}
    for i, commit in enumerate(Repository(str(root), **repo_kwargs).traverse_commits(), start=1):
        if progress_cb is not None and i % 250 == 0:
            progress_cb(i)
        touched: list[str] = []
        renames: list[tuple[str, str]] = []
        file_changes: list[FileChangeFact] = []
        for mf in _modified_files_no_patch(commit, root):
            # GOTCHA (confirmed empirically against real repo history, not
            # assumed): GitPython's underlying Diff object populates BOTH
            # a_path and b_path with the SAME path for a plain ADD or DELETE,
            # not just for MODIFY/RENAME - e.g. an added file's a_path is NOT
            # None, it mirrors b_path. PyDriller's own `old_path`/`new_path`
            # properties only check truthiness of a_path/b_path, so they does
            # NOT reliably read as None on an add/delete. `change_type` is the
            # only reliable signal for "did this path exist before/after this
            # commit" - old_path/new_path must be nulled out from it
            # explicitly, not trusted as-is. This doesn't affect Stage 1's own
            # use of old_path/new_path (touched-file collection and rename
            # detection both only care whether old_path == new_path, which is
            # unaffected), but Part 1's creation-detection depends on it.
            change_type = mf.change_type.name
            raw_old = mf.old_path.replace("\\", "/") if mf.old_path else mf.old_path
            raw_new = mf.new_path.replace("\\", "/") if mf.new_path else mf.new_path
            old_path = None if change_type == "ADD" else raw_old
            new_path = None if change_type == "DELETE" else raw_new
            old_is_rule = _is_rule_path(old_path, extensions, exclude_dirs, subdir_prefix)
            new_is_rule = _is_rule_path(new_path, extensions, exclude_dirs, subdir_prefix)
            if not (old_is_rule or new_is_rule):
                continue
            if new_path:
                touched.append(new_path)
            elif old_path:
                touched.append(old_path)
            if old_is_rule and new_is_rule and old_path != new_path and old_path:
                renames.append((old_path, new_path))
            file_changes.append(
                FileChangeFact(
                    old_path=old_path if old_is_rule else None,
                    new_path=new_path if new_is_rule else None,
                    change_type=change_type,
                )
            )
        if not touched:
            continue
        author = commit.author
        author_key = (author.email or author.name or "unknown") if author else "unknown"
        parents = commit.parents
        facts.append(
            _CommitFacts(
                hash=commit.hash,
                parent_hash=parents[0] if len(parents) == 1 else None,
                is_merge=commit.merge,
                subject=(commit.msg or "").splitlines()[0] if commit.msg else "",
                author_key=author_key,
                author_date=commit.author_date.date(),
                rule_paths_touched=touched,
                renames=renames,
                file_changes=file_changes,
            )
        )
    return facts


def _resolve_canonical(path: str, renamed_to: dict[str, str]) -> str:
    seen = set()
    while path in renamed_to and path not in seen:
        seen.add(path)
        path = renamed_to[path]
    return path


def _build_renamed_to(all_facts: list[_CommitFacts]) -> dict[str, str]:
    """Whole-history old_path -> new_path map, used with `_resolve_canonical`
    to attribute a commit's touch under an old (pre-rename) path to the file's
    CURRENT identity. This is exactly the step the prior (pre-Stage-1) ad-hoc
    `git log --name-only` churn script never did - see RESULTS.md Part 0."""
    renamed_to: dict[str, str] = {}
    for f in all_facts:
        for old, new in f.renames:
            renamed_to[old] = new
    return renamed_to


def _build_exclusion(
    all_facts: list[_CommitFacts], rule_count: int, threshold: float
) -> tuple[set[str], list[ExcludedCommit]]:
    excluded_hashes: set[str] = set()
    excluded: list[ExcludedCommit] = []
    for f in all_facts:
        if (len(f.rule_paths_touched) / rule_count) >= threshold:
            excluded_hashes.add(f.hash)
            excluded.append(
                ExcludedCommit(hash=f.hash, subject=f.subject, rule_files_touched=len(f.rule_paths_touched))
            )
    return excluded_hashes, excluded


@dataclass
class OrganicTouch:
    """One (organic commit, current rule file) pairing - the file-level, Pass-1
    output that Part 1's semantic diff (Pass 2) consumes to decide which
    commits are worth fetching diff content for. Mechanical commits and merge
    commits are excluded before this is built; `old_path`/`new_path` are the
    raw paths as they appeared IN THIS COMMIT (not whole-history-resolved),
    since Pass 2 needs to fetch the blob at the parent commit under
    `old_path` and at this commit under `new_path`."""

    commit_hash: str
    parent_hash: Optional[str]
    author_date: date
    subject: str
    old_path: Optional[str]  # None => this commit created the file
    new_path: Optional[str]  # None => this commit deleted the file (no current identity)
    canonical_file: str  # this touch's rule file, resolved to its CURRENT path
    is_creation: bool


def mine_organic_touches(
    root: Path,
    fmt: str = "sigma",
    mechanical_threshold: float = DEFAULT_THRESHOLD,
    subdir: Optional[str] = None,
    all_facts: Optional[list[_CommitFacts]] = None,
    timeout: Optional[float] = None,
) -> list[OrganicTouch]:
    """Pass 1 for Part 1 (semantic diff): every organic, non-merge commit's
    touch on a file that currently exists, resolved to that file's current
    identity. Reuses `_mine_commits` (the same single git traversal
    `compute_staleness` uses) rather than re-mining history - deliberately
    file-level (not aggregated) since Pass 2 needs per-commit before/after
    content, unlike `compute_staleness`'s per-rule counts.

    `all_facts`, if given (e.g. from `mine_commits`, possibly already used
    for `compute_staleness` on the same repo), skips mining entirely.

    Deletions and touches on files that no longer exist under any current
    name are dropped - Part 1 only scores rules that still exist today.
    """
    root = Path(root)
    _check_git_preconditions(root)
    rule_format = FORMATS[fmt] if isinstance(fmt, str) else fmt
    rules_root = (root / subdir) if subdir else root
    subdir_prefix = subdir.replace("\\", "/").rstrip("/") if subdir else None

    current_files = discover_files(rules_root, fmt)
    rule_count = len(current_files)
    if rule_count == 0:
        raise ChurnError(f"No rule files matching format '{fmt}' found under {rules_root}.")
    current_rel_paths = {str(p.relative_to(root)).replace("\\", "/") for p in current_files}

    if all_facts is None:
        all_facts = _mine_with_timeout(lambda: _mine_commits(root, rule_format, subdir_prefix), root, timeout)
    if not all_facts:
        raise NoGitHistoryError(root)

    renamed_to = _build_renamed_to(all_facts)
    excluded_hashes, _ = _build_exclusion(all_facts, rule_count, mechanical_threshold)

    touches: list[OrganicTouch] = []
    for f in all_facts:
        if f.hash in excluded_hashes or f.is_merge:
            continue
        for fc in f.file_changes:
            if fc.new_path is None:
                continue  # deletion - nothing current to attribute this to
            canonical = _resolve_canonical(fc.new_path, renamed_to)
            if canonical not in current_rel_paths:
                continue  # this path's lineage doesn't end at a file that exists today
            touches.append(
                OrganicTouch(
                    commit_hash=f.hash,
                    parent_hash=f.parent_hash,
                    author_date=f.author_date,
                    subject=f.subject,
                    old_path=fc.old_path,
                    new_path=fc.new_path,
                    canonical_file=canonical,
                    is_creation=fc.old_path is None,
                )
            )
    return touches


def _cache_path(root: Path, fmt: str, subdir: Optional[str]) -> Path:
    cache_dir = root / ".mechanic_cache"
    cache_dir.mkdir(exist_ok=True)
    subdir_key = (subdir or "_none_").replace("/", "_").replace("\\", "_")
    return cache_dir / f"mine_commits__{fmt}__{subdir_key}.pkl"


def _current_head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def mine_commits_cached(
    root: Path,
    fmt: str = "sigma",
    subdir: Optional[str] = None,
    refresh: bool = False,
    progress_cb: Optional[Callable[[str, int], None]] = None,
    timeout: Optional[float] = None,
) -> list[_CommitFacts]:
    """Disk-cached wrapper around `mine_commits`, keyed by (repo root, fmt,
    subdir, current `git rev-parse HEAD`).

    `mine_commits` already ensures one mining pass is shared across every
    consumer WITHIN a single process (see its own docstring - the
    3x-redundant-mining bug already found and fixed once in Part 3's
    gathering script). This wrapper exists because that cost was still being
    paid repeatedly ACROSS separate process invocations - the CLI's
    `triage`/`explain` commands, or a script restarted after being killed -
    each of which mines from zero with no memory of a previous run. Part 3's
    threshold-sensitivity validation (RESULTS.md) needs several thresholds
    against the SAME mined history; without this cache, each restart (and
    every alternative threshold explored across separate invocations) pays
    the full mining cost again.

    Cache safety: the pickle stores `(head_hash, all_facts)`. A cache is only
    used if its stored `head_hash` matches the repo's CURRENT
    `git rev-parse HEAD` - if the repo has moved forward since the cache was
    written, the key no longer matches and this is treated as a cache miss
    (re-mines, then overwrites the stale cache) rather than silently serving
    stale facts. `refresh=True` forces re-mining regardless of cache state.

    Every path (hit, miss - no cache, miss - stale, refresh) prints an
    explicit one-line message to STDERR (never stdout - `mechanic triage
    --json`/`explain --json` must stay pure JSON on stdout for anyone
    piping it to `jq` or another program; this was a real bug, found and
    fixed during the Part 2 hardening pass: these messages used to go to
    stdout and would corrupt --json output on every cache miss), so a fast
    cached run is never mistaken for a fresh mining run or vice versa.

    `progress_cb`, if given, is called with `("cache_hit"|"mining", n)` -
    once with `("cache_hit", len(cached_facts))` on a hit, or repeatedly
    with `("mining", commit_count)` while actually mining (see
    `_mine_commits`). Added for the GUI's real progress display; every
    core CLI path passes `None` and behaves exactly as before.

    `timeout`, if given, bounds the actual mining call (never the cache-hit
    path, which does no mining at all) - see `MiningTimeoutError` and
    `_mine_with_timeout`. `None` (default) behaves exactly as before this
    parameter existed.
    """
    root = Path(root)
    _check_git_preconditions(root)
    head = _current_head(root)
    cache_file = _cache_path(root, fmt, subdir)

    if refresh:
        print(f"[mechanic] cache SKIPPED (--refresh): re-mining {root} (fmt={fmt}, subdir={subdir}).", file=sys.stderr, flush=True)
    elif cache_file.exists():
        cached_head, cached_facts = None, None
        try:
            with open(cache_file, "rb") as f:
                cached_head, cached_facts = pickle.load(f)
        except Exception as e:
            print(f"[mechanic] cache UNREADABLE ({e}) - re-mining.", file=sys.stderr, flush=True)
        if cached_facts is not None and cached_head == head:
            print(
                f"[mechanic] cache HIT: {len(cached_facts)} commit-facts for {root} "
                f"(fmt={fmt}, subdir={subdir}) at HEAD={head[:10]} - reusing, no mining performed.",
                file=sys.stderr,
                flush=True,
            )
            if progress_cb is not None:
                progress_cb("cache_hit", len(cached_facts))
            return cached_facts
        elif cached_facts is not None:
            print(
                f"[mechanic] cache MISS (stale): cached HEAD={cached_head[:10] if cached_head else '?'} "
                f"!= current HEAD={head[:10]} - repo has moved, re-mining.",
                file=sys.stderr,
                flush=True,
            )
    else:
        print(f"[mechanic] cache MISS (none found): mining {root} (fmt={fmt}, subdir={subdir}).", file=sys.stderr, flush=True)

    mine_kwargs = {"progress_cb": lambda n: progress_cb("mining", n)} if progress_cb is not None else {}
    all_facts = mine_commits(root, fmt, subdir=subdir, timeout=timeout, **mine_kwargs)
    with open(cache_file, "wb") as f:
        pickle.dump((head, all_facts), f)
    print(f"[mechanic] mined and cached {len(all_facts)} commit-facts at HEAD={head[:10]} -> {cache_file}", file=sys.stderr, flush=True)
    return all_facts


def mine_commits(
    root: Path,
    fmt: str = "sigma",
    subdir: Optional[str] = None,
    progress_cb: Optional[Callable[[int], None]] = None,
    timeout: Optional[float] = None,
) -> list[_CommitFacts]:
    """Public entry point for a single full-history mining pass.

    `compute_staleness`, `mine_organic_touches`, and any caller that also
    needs whole-history facts (e.g. Part 3's per-rule creation-date lookup)
    all consume the same `_CommitFacts` list this returns. Mining is the
    expensive step (a full PyDriller traversal); computing it once per repo
    and threading the result through every consumer via each function's
    `all_facts` parameter - instead of each one re-mining independently -
    is a 3x reduction in git-history walks for Part 3's gathering script,
    which needs all three (staleness aggregation, organic touches for
    semantic diffing, and creation dates) from the same repo in one run.

    `progress_cb`, if given, forwards to `_mine_commits` (a running commit
    count, roughly every 250 commits) - optional, `None` by default,
    changes nothing about what's mined or returned.

    `timeout`, if given (seconds), bounds the WHOLE mining pass with a hard
    wall-clock budget - see `MiningTimeoutError`. `None` (default) behaves
    exactly as before this parameter existed.
    """
    root = Path(root)
    _check_git_preconditions(root)
    rule_format = FORMATS[fmt] if isinstance(fmt, str) else fmt
    subdir_prefix = subdir.replace("\\", "/").rstrip("/") if subdir else None
    all_facts = _mine_with_timeout(
        lambda: _mine_commits(root, rule_format, subdir_prefix, progress_cb=progress_cb), root, timeout
    )
    if not all_facts:
        raise NoGitHistoryError(root)
    return all_facts


def _ever_revised(touches: list[tuple[date, str]]) -> tuple[Optional[bool], str]:
    """Resolve the `ever_revised` tri-state for one rule from its organic
    touches (`(author_date, git change_type)`, each already known to be a
    non-mechanical, non-merge commit touching this file under some path
    resolving to its current identity - see `compute_staleness`'s caller).

    A single organic commit is NOT inherently ambiguous, contrary to a naive
    `organic_commit_count > 1` check: git's own `change_type` on that one
    commit already distinguishes the two cases the ambiguity is actually
    about -

      ADD             -> the file was newly created in this commit and has
                          no other organic touch on record: created once,
                          no revision observed (Case A).
      MODIFY / RENAME  -> the file already existed before this commit (a
                          MODIFY/RENAME target always has a prior version by
                          definition), so a revision did happen at least
                          once, even though the file's actual creation isn't
                          itself visible in the organic set (e.g. it
                          happened inside an excluded mechanical bulk-import
                          commit) (Case B).

    Zero organic commits is the one case genuinely lacking any signal at
    all: every touch this file ever had was filtered out as mechanical, so
    whether it was ever individually revised afterward cannot be determined
    from this data - reported as UNKNOWN (`None`), never silently `False`.
    """
    if not touches:
        return None, "no_organic_history"
    if len(touches) > 1:
        return True, "multiple_organic_commits"
    _, change_type = touches[0]
    if change_type == "ADD":
        return False, "single_commit_creation"
    return True, "single_commit_modification"


def _assess_history_health(all_facts: list[_CommitFacts], rules: list["RuleChurn"]) -> tuple[str, list[str]]:
    """Soft (non-blocking) degraded-history detection, distinct from the
    hard NoGitHistoryError/ShallowRepositoryError preconditions that abort
    before any report is built. Every reason here corresponds to a
    concrete, previously-observed failure mode - not a speculative check:

    - `insufficient_total_commits`: the whole repo's mined history is too
      small for percentages computed over it to mean much (a repo with 2
      total commits reporting "50% of rules revised" is technically true
      and practically meaningless).
    - `mechanical_threshold_excluded_all_history`: every mined commit got
      filtered out as mechanical, so 100% of rules show zero organic
      history - this is exactly the small-repo-single-commit-touches-every-
      file shape this project's own test fixtures had to work around
      (`revised_repo` in tests/test_priority_matrix.py) to get a genuine
      diffable touch at all. Reported here so a real user hits the same
      diagnosis instead of silently seeing "0% ever revised" and assuming
      the rules are actually all fresh-and-untouched.

    Does not attempt to detect squashed history - git has no reliable
    signal for "this one commit represents what would otherwise have been
    several" (see docs/core-vs-experiment.md-style disclosure in
    protected_literals.py for the same kind of honest scope limit).
    """
    reasons: list[str] = []
    if len(all_facts) < DEGRADED_HISTORY_MIN_COMMITS:
        reasons.append("insufficient_total_commits")
    if rules and all(r.organic_commit_count == 0 for r in rules):
        reasons.append("mechanical_threshold_excluded_all_history")
    return (HEALTH_DEGRADED if reasons else HEALTH_HEALTHY), reasons


def compute_staleness(
    root: Path,
    fmt: str = "sigma",
    mechanical_threshold: float = DEFAULT_THRESHOLD,
    as_of: Optional[date] = None,
    subdir: Optional[str] = None,
    all_facts: Optional[list[_CommitFacts]] = None,
    timeout: Optional[float] = None,
) -> StalenessReport:
    """Compute the staleness report for a repo.

    `subdir`, if given, restricts rule discovery and mechanical-commit
    counting to that path within the repo (e.g. SigmaHQ/sigma's `rules/`,
    excluding `rules-emerging-threats/` etc.) while git history mining still
    runs against the whole repo root - PyDriller's `Repository` needs the
    actual `.git` root, not an arbitrary subdirectory.

    Two-pass, single-traversal design: PyDriller walks history exactly once
    (`_mine_commits`); everything else (mechanical-commit exclusion, rename
    resolution, per-rule aggregation) is pure Python over the mined facts, so
    this scales to repos with thousands of commits without re-walking git
    once per rule file.

    `all_facts`, if given (e.g. from `mine_commits`), skips mining entirely
    and reuses the supplied facts - for callers that also need
    `mine_organic_touches`/other consumers on the same repo and want to
    avoid a second full traversal.

    `timeout`, if given (seconds), bounds the mining pass when `all_facts`
    isn't already supplied - see `MiningTimeoutError`. Ignored (mining never
    happens) when `all_facts` is given directly.
    """
    root = Path(root)
    _check_git_preconditions(root)
    rule_format = FORMATS[fmt] if isinstance(fmt, str) else fmt
    as_of = as_of or datetime.now().date()
    rules_root = (root / subdir) if subdir else root
    subdir_prefix = subdir.replace("\\", "/").rstrip("/") if subdir else None

    current_files = discover_files(rules_root, fmt)
    rule_count = len(current_files)
    if rule_count == 0:
        raise ChurnError(f"No rule files matching format '{fmt}' found under {rules_root}.")

    if all_facts is None:
        all_facts = _mine_with_timeout(lambda: _mine_commits(root, rule_format, subdir_prefix), root, timeout)
    if not all_facts:
        raise NoGitHistoryError(root)

    # pydriller.metrics.process.CommitsCount.count() always computes full
    # unified-diff patches per commit (create_patch=True is hardcoded in
    # Commit.modified_files); over a repo's *entire* history that's minutes
    # on a several-thousand-commit repo just for an illustrative contrast
    # figure. Bound it to a trailing window so it stays cheap regardless of
    # repo size - it's reported as illustrative context (raw, unfiltered
    # commit volume), not used in any staleness computation.
    raw_window_days = 365
    as_of_dt = datetime.combine(as_of, datetime.min.time())
    raw_commit_total = CommitsCount(
        str(root), since=as_of_dt - timedelta(days=raw_window_days), to=as_of_dt
    ).count()
    raw_commit_total_sum = sum(raw_commit_total.values()) if raw_commit_total else 0

    renamed_to = _build_renamed_to(all_facts)

    sensitivity: list[ThresholdSensitivity] = []
    for t in sorted(set(REPORT_THRESHOLDS) | {mechanical_threshold}):
        _, excl = _build_exclusion(all_facts, rule_count, t)
        sensitivity.append(ThresholdSensitivity(threshold=t, excluded_commits=excl))

    excluded_hashes, excluded_commits = _build_exclusion(all_facts, rule_count, mechanical_threshold)

    # Per-canonical-current-path aggregation. Iterates `file_changes` (not the
    # flattened `rule_paths_touched`) specifically so each touch's git-level
    # `change_type` (ADD vs MODIFY/RENAME) travels alongside its date - the
    # signal `_ever_revised` below needs to resolve the single-organic-commit
    # ambiguity, which the flat path list on its own cannot distinguish.
    current_rel_paths = {str(p.relative_to(root)).replace("\\", "/") for p in current_files}
    per_path: dict[str, dict[str, Any]] = {
        p: {"touches": [], "authors": set()} for p in current_rel_paths
    }

    for f in all_facts:
        if f.hash in excluded_hashes:
            continue
        for fc in f.file_changes:
            touched = fc.new_path or fc.old_path
            if touched is None:
                continue
            canonical = _resolve_canonical(touched, renamed_to)
            if canonical not in per_path:
                continue  # historical path whose current identity no longer exists (deleted rule)
            per_path[canonical]["touches"].append((f.author_date, fc.change_type))
            per_path[canonical]["authors"].add(f.author_key)

    rules: list[RuleChurn] = []
    for rel_path in sorted(current_rel_paths):
        data = per_path[rel_path]
        touches: list[tuple[date, str]] = data["touches"]
        dates = [d for d, _ in touches]
        organic_commit_count = len(dates)
        ever_revised, ever_revised_basis = _ever_revised(touches)
        if organic_commit_count == 0:
            rules.append(
                RuleChurn(
                    file=rel_path,
                    organic_commit_count=0,
                    last_organic_commit_date=None,
                    days_since=None,
                    ever_revised=ever_revised,
                    ever_revised_basis=ever_revised_basis,
                    distinct_author_count=0,
                )
            )
            continue
        last_date = max(dates)
        rules.append(
            RuleChurn(
                file=rel_path,
                organic_commit_count=organic_commit_count,
                last_organic_commit_date=last_date,
                days_since=(as_of - last_date).days,
                ever_revised=ever_revised,
                ever_revised_basis=ever_revised_basis,
                distinct_author_count=len(data["authors"]),
            )
        )

    history_health, history_health_reasons = _assess_history_health(all_facts, rules)
    return StalenessReport(
        root=str(root),
        rule_count=rule_count,
        mechanical_threshold=mechanical_threshold,
        raw_commit_total=raw_commit_total_sum,
        raw_commit_window_days=raw_window_days,
        excluded_commits=excluded_commits,
        rules=rules,
        sensitivity=sensitivity,
        history_health=history_health,
        history_health_reasons=history_health_reasons,
    )
