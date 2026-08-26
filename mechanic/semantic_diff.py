"""Semantic diff / behavioral staleness (Part 1 of Stage 2).

PROBLEM. Stage 1's staleness only knows *whether* a commit touched a rule
file, never *what* it changed inside it. A commit that fixes a typo in
`description:` counts identically to one that rewrites the detection logic.
"Touched recently" therefore does not mean "still maintained" - Stage 1's
staleness numbers are an optimistic floor.

DESIGN - two passes, for performance (mirrors churn.py's own rationale for
disabling patch generation):

  Pass 1 (cheap): `churn.mine_organic_touches` - already implemented, reused
      unmodified here. Identifies which ORGANIC (non-mechanical, non-merge)
      commits touched which CURRENT rule files, with per-commit old/new path
      (rename-aware) - no diff content is fetched in this pass.
  Pass 2 (expensive, this module): for each Pass-1 touch, fetch the file's
      blob text at the commit and at its parent (via direct GitPython tree
      lookup - NOT `Commit.modified_files`/patch generation, which is exactly
      the cost churn.py already found and removed) and classify the change.

Every commit touching a current rule file is classified into exactly one of:

  creation           - the file did not exist at the parent commit (or this
                       commit has no parent - the repo's root commit).
  behavioral         - `detection:` or `logsource:` changed. Logsource counts
                       because e.g. product: windows -> product: linux
                       changes what the rule means entirely, even though it
                       sits outside the detection block.
  semantic_metadata  - ATT&CK `tags:`, `status:`, `level:`, `fields:` changed
                       and nothing behavioral did. Meaning shifts, logic does
                       not - kept separate from `cosmetic` deliberately.
  cosmetic           - only title/description/author/references/
                       falsepositives/date/modified/whitespace/key-order
                       changed - no functional change.

Classification method, in preference order (each downgrades confidence):

  (a) AST-level comparison - preferred, `classification_confidence: "high"`.
      Both sides parsed to a `SigmaRule` (via `loader.parse_text`, so this
      goes through the exact same isolation/categorization path as a normal
      scan - no separate parsing logic) and compared via `ast_repr.build_ast`.
      Robust to key reordering, quoting style, and YAML formatting churn -
      exactly what a raw text diff is not.
  (b) Parsed-YAML key comparison - fallback, `"medium"`. Used when either
      side fails to construct as a `SigmaRule` (common in history - rules
      were often broken before being fixed) but both still parse as YAML.
      Also used for correlation-rule documents, whose actual detection logic
      (the `correlation:` block) isn't represented in `ast_repr`'s minimal
      correlation AST.
  (c) Raw text diff - last resort, `"low"`. Used when either side isn't even
      valid YAML. A crude line-based "which top-level key block changed"
      scanner - reported explicitly (see `method_counts` / `unknown_count` on
      `SemanticDiffReport`) so it's visible how often this weaker signal was
      needed, per Stage 2's brief: "if it's frequent, the whole signal is
      weaker than it looks and that must be visible."

  If (c) itself can't identify which section changed (no recognizable
  top-level `key:` structure in either version), the outcome is `None`
  (bucket "unknown") rather than a guess - "insufficient information" is the
  explicit, deliberate output for that case, not a forced classification.

FORMAT AWARENESS: (a) is Sigma-only - there is no EQL/SPL AST anywhere in
this codebase. Elastic (TOML: `query`/`language`/`type`/`tags`/`risk_score`)
and Splunk (YAML: `search`/`mitre_attack_id`/`analytic_story`) have their own
field names for the same concepts, tracked in `FORMAT_KEYS` and used by
fallbacks (b)/(c) - using Sigma's key names against those two formats
unmodified would silently misclassify every real detection-logic change as
cosmetic (neither format has a `detection:` key at all). Every Elastic/Splunk
classification is therefore capped at `"medium"` confidence, never `"high"`.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

import git
import yaml

from mechanic import ast_repr, loader
from mechanic.churn import STALE_DAYS, DEFAULT_THRESHOLD, RuleChurn, StalenessReport, mine_organic_touches

BEHAVIORAL_KEYS = {"detection", "logsource", "correlation"}
METADATA_KEYS = {"tags", "status", "level", "fields"}

# Format-aware key sets for (b)/(c) fallbacks - Sigma's own key names don't
# exist in Elastic's TOML or Splunk's YAML schema at all, so using
# BEHAVIORAL_KEYS/METADATA_KEYS unmodified against those formats would
# silently misclassify every real detection-logic change as cosmetic (Elastic
# rules keep their query under `query`, not `detection`; Splunk keeps it
# under `search`). The AST path (a) is Sigma-only regardless (no EQL/SPL
# parser exists) - Elastic/Splunk always go straight to (b)/(c), capped at
# "medium" confidence, using these format-specific key sets.
FORMAT_KEYS: dict[str, tuple[set[str], set[str]]] = {
    "sigma": (BEHAVIORAL_KEYS, METADATA_KEYS),
    "elastic_toml": (
        {"query", "language", "type", "threat", "filters", "index", "data_view_id", "machine_learning_job_id"},
        {"tags", "risk_score", "severity", "threshold"},
    ),
    "splunk_yaml": ({"search"}, {"mitre_attack_id", "analytic_story", "type"}),
}

BUCKET_PRIORITY = {"behavioral": 3, "semantic_metadata": 2, "cosmetic": 1, "unknown": 0}

_TOP_LEVEL_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$")


@dataclass
class ChangeClassification:
    bucket: Optional[str]  # "behavioral" | "semantic_metadata" | "cosmetic" | None ("unknown")
    confidence: str  # "high" | "medium" | "low"
    method: str  # "ast" | "yaml_key" | "raw_text_section" | "unknown"
    detail: str = ""


# ---------------------------------------------------------------------------
# (a) AST-level comparison
# ---------------------------------------------------------------------------


def _tag_list(rule) -> list[str]:
    return ast_repr._tag_strings(rule)


def _standard_rule_classification(rule_before, rule_after) -> ChangeClassification:
    ast_before = ast_repr.build_ast(rule_before)
    ast_after = ast_repr.build_ast(rule_after)

    if ast_before["conditions"] != ast_after["conditions"] or ast_before["logsource"] != ast_after["logsource"]:
        return ChangeClassification("behavioral", "high", "ast", "detection or logsource tree differs")

    if (
        _tag_list(rule_before) != _tag_list(rule_after)
        or str(rule_before.status) != str(rule_after.status)
        or str(rule_before.level) != str(rule_after.level)
        or list(rule_before.fields or []) != list(rule_after.fields or [])
    ):
        return ChangeClassification(
            "semantic_metadata", "high", "ast", "tags/status/level/fields differ, detection unchanged"
        )

    return ChangeClassification("cosmetic", "high", "ast", "no behavioral or semantic-metadata difference")


def _try_ast_classification(before_text: str, after_text: str, path: Path) -> Optional[ChangeClassification]:
    """Returns None (not a hard failure) if either side can't be cleanly
    reduced to exactly one comparable rule pair - caller falls back to (b)."""
    rules_before, failures_before = loader.parse_text(before_text, path)
    rules_after, failures_after = loader.parse_text(after_text, path)
    if failures_before or failures_after:
        return None
    if len(rules_before) != 1 or len(rules_after) != 1:
        # Multi-document files, or a document that vanished/appeared: the
        # unambiguous 1:1 AST comparison this method is "high confidence"
        # about doesn't apply cleanly. Fall back rather than guess a pairing.
        return None
    rb, ra = rules_before[0].rule, rules_after[0].rule
    if rb.__class__ is not ra.__class__:
        return ChangeClassification("behavioral", "high", "ast", "rule type changed (standard <-> correlation)")
    from sigma.correlations import SigmaCorrelationRule

    if isinstance(rb, SigmaCorrelationRule):
        return None  # correlation logic isn't modeled in ast_repr - use YAML-key fallback
    try:
        return _standard_rule_classification(rb, ra)
    except Exception:
        # `loader.parse_text`'s isolation only covers YAML-parse and
        # rule_construct - condition parsing happens LAZILY, inside
        # `ast_repr.build_ast` itself, and pySigma raises hard
        # (SigmaConditionError, etc.) for historically-valid-but-now-
        # rejected syntax (e.g. the deprecated `|`-pipe condition syntax) a
        # rule may have used at some point in its git history, even though
        # the same rule constructs cleanly as a SigmaRule object. This
        # mirrors exactly the crash class Stage 1's `loader.py` docstring
        # calls out for the validator stage - the same isolation principle
        # applies here: fall back to (b), don't crash the whole diff run.
        return None


# ---------------------------------------------------------------------------
# (b) Parsed-YAML key comparison
# ---------------------------------------------------------------------------


def _classify_doc_pair(
    doc_before: Any, doc_after: Any, behavioral_keys: set[str], metadata_keys: set[str]
) -> ChangeClassification:
    if doc_before is None or doc_after is None:
        # A whole document appeared/disappeared inside a multi-document file.
        # Not cosmetic by construction - conservatively behavioral.
        return ChangeClassification("behavioral", "medium", "yaml_key", "document added/removed in multi-doc file")
    if not isinstance(doc_before, dict) or not isinstance(doc_after, dict):
        return ChangeClassification("behavioral", "medium", "yaml_key", "non-mapping document changed")

    if any(doc_before.get(k) != doc_after.get(k) for k in behavioral_keys):
        return ChangeClassification("behavioral", "medium", "yaml_key", f"behavioral key differs (of {behavioral_keys})")
    if any(doc_before.get(k) != doc_after.get(k) for k in metadata_keys):
        return ChangeClassification("semantic_metadata", "medium", "yaml_key", f"metadata key differs (of {metadata_keys})")
    return ChangeClassification("cosmetic", "medium", "yaml_key", "no behavioral or metadata key differs")


def _worst(classifications: list[ChangeClassification]) -> ChangeClassification:
    return max(classifications, key=lambda c: BUCKET_PRIORITY.get(c.bucket, -1))


def _try_yaml_key_classification(before_text: str, after_text: str, fmt: str) -> Optional[ChangeClassification]:
    behavioral_keys, metadata_keys = FORMAT_KEYS.get(fmt, (BEHAVIORAL_KEYS, METADATA_KEYS))
    try:
        if fmt == "elastic_toml":
            import tomllib

            docs_before = [tomllib.loads(before_text).get("rule", {})]
            docs_after = [tomllib.loads(after_text).get("rule", {})]
        else:
            docs_before = list(yaml.safe_load_all(before_text))
            docs_after = list(yaml.safe_load_all(after_text))
    except Exception:
        return None
    from itertools import zip_longest

    pairs = list(zip_longest(docs_before, docs_after, fillvalue=None))
    if not pairs:
        return ChangeClassification("cosmetic", "medium", "yaml_key", "both sides empty")
    return _worst([_classify_doc_pair(b, a, behavioral_keys, metadata_keys) for b, a in pairs])


# ---------------------------------------------------------------------------
# (c) Raw text diff, line/section heuristic - last resort
# ---------------------------------------------------------------------------


def _top_level_sections(text: str) -> dict[str, str]:
    """Crude, YAML-validity-independent sectioning: group every line under
    the nearest preceding column-0 `key:` line. Works even on text that isn't
    valid YAML, which is the whole point of this being the last-resort tier."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        m = _TOP_LEVEL_KEY_RE.match(line)
        if m and not line.startswith((" ", "\t")):
            current = m.group(1)
            sections.setdefault(current, []).append(line)
        elif current is not None:
            sections[current].append(line)
    return {k: "\n".join(v) for k, v in sections.items()}


def _try_raw_text_classification(before_text: str, after_text: str, fmt: str) -> ChangeClassification:
    behavioral_keys, metadata_keys = FORMAT_KEYS.get(fmt, (BEHAVIORAL_KEYS, METADATA_KEYS))
    sections_before = _top_level_sections(before_text)
    sections_after = _top_level_sections(after_text)
    all_keys = set(sections_before) | set(sections_after)
    if not all_keys:
        return ChangeClassification(None, "low", "unknown", "no recognizable top-level key structure in either side")

    changed_keys = {k for k in all_keys if sections_before.get(k) != sections_after.get(k)}
    if not changed_keys:
        # Diff exists (Pass 1 only includes commits that touched the file) but
        # our section-level view sees no change - most likely a change this
        # heuristic can't localize (e.g. inside an unrecognized/malformed
        # block). Don't guess.
        diff_has_content = list(
            difflib.unified_diff(before_text.splitlines(), after_text.splitlines(), lineterm="")
        )
        if not diff_has_content:
            return ChangeClassification("cosmetic", "low", "raw_text_section", "byte-identical after sectioning")
        return ChangeClassification(None, "low", "unknown", "diff present but no top-level section changed")

    if changed_keys & behavioral_keys:
        return ChangeClassification("behavioral", "low", "raw_text_section", f"changed sections: {changed_keys}")
    if changed_keys & metadata_keys:
        return ChangeClassification(
            "semantic_metadata", "low", "raw_text_section", f"changed sections: {changed_keys}"
        )
    return ChangeClassification("cosmetic", "low", "raw_text_section", f"changed sections: {changed_keys}")


# ---------------------------------------------------------------------------
# Entry point: the (a) -> (b) -> (c) waterfall
# ---------------------------------------------------------------------------


def classify_change(before_text: str, after_text: str, path: Path, fmt: str = "sigma") -> ChangeClassification:
    """`fmt` selects the format-specific key sets used by fallbacks (b)/(c) -
    see `FORMAT_KEYS`. The AST path (a) is attempted ONLY for `fmt="sigma"`;
    Elastic/Splunk have no real parser here (Stage 1 built an AST for Sigma
    only) and go straight to the format-aware YAML/TOML-key fallback, capped
    at "medium" confidence - never "high" for those two formats."""
    if before_text == after_text:
        return ChangeClassification("cosmetic", "high", "ast", "byte-identical content")
    if fmt == "sigma":
        result = _try_ast_classification(before_text, after_text, path)
        if result is not None:
            return result
    result = _try_yaml_key_classification(before_text, after_text, fmt)
    if result is not None:
        return result
    return _try_raw_text_classification(before_text, after_text, fmt)


# ---------------------------------------------------------------------------
# Git blob access (random access by commit+path - no patch generation, no
# full-history re-traversal; Pass 1 already identified exactly which
# (commit, path) pairs are worth fetching).
# ---------------------------------------------------------------------------


class _BlobFetcher:
    def __init__(self, root: Path):
        self._repo = git.Repo(str(root))
        self._tree_cache: dict[str, Any] = {}

    def _tree(self, commit_hash: str):
        tree = self._tree_cache.get(commit_hash)
        if tree is None:
            tree = self._repo.commit(commit_hash).tree
            self._tree_cache[commit_hash] = tree
        return tree

    def text_at(self, commit_hash: Optional[str], path: Optional[str]) -> Optional[str]:
        if commit_hash is None or path is None:
            return None
        try:
            blob = self._tree(commit_hash)[path]
        except KeyError:
            return None
        try:
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass
class SemanticDiffReport:
    root: str
    total_organic_touches: int
    creation_touches: int
    classified_touches: int
    content_fetch_failures: int
    method_counts: dict[str, int] = field(default_factory=dict)
    staleness: Optional[StalenessReport] = None

    @property
    def unknown_count(self) -> int:
        return self.method_counts.get("unknown", 0)

    def to_dict(self, top_n: Optional[int] = None) -> dict[str, Any]:
        return {
            "root": self.root,
            "total_organic_touches": self.total_organic_touches,
            "creation_touches": self.creation_touches,
            "classified_touches": self.classified_touches,
            "content_fetch_failures": self.content_fetch_failures,
            "method_counts": self.method_counts,
            "low_confidence_fraction": (
                self.method_counts.get("raw_text_section", 0) + self.method_counts.get("unknown", 0)
            )
            / self.classified_touches
            if self.classified_touches
            else 0.0,
            "staleness": self.staleness.to_dict(top_n=top_n) if self.staleness else None,
        }


def behavioral_summary(report: StalenessReport) -> dict[str, Any]:
    """NOT a mirror of `StalenessReport.summary()`'s "no organic history"
    convention, deliberately - that would be wrong here, and WAS wrong here
    (caught by the registered prediction check: behavioral staleness must
    never come out lower than raw staleness, and an earlier version of this
    function violated that on real data - joesecurity: 29.4% behavioral vs.
    96.6% raw).

    For raw staleness, "zero organic commits" is rare and means "no data" -
    excluding it from the numerator is reasonable. For behavioral staleness,
    "zero behavioral commits" is COMMON (a rule can have plenty of organic
    history that's entirely cosmetic/metadata) and means something else
    entirely: full information, and that information says the rule's
    detection logic has NEVER been revised since creation - the worst case,
    not a missing-data case. Excluding it from the numerator (as the raw
    convention does) systematically understates behavioral staleness by
    exactly the rules Part 1 exists to surface. Fixed: a rule with zero
    behavioral commits counts as stale directly; `rules_with_no_behavioral_
    history` is still reported for transparency, but no longer excluded from
    the percentage."""
    n = len(report.rules)
    stale_count = 0
    no_behavioral_history = 0
    for r in report.rules:
        if (r.behavioral_commit_count or 0) == 0:
            no_behavioral_history += 1
            stale_count += 1
            continue
        if r.days_since_behavioral_change is not None and r.days_since_behavioral_change > STALE_DAYS:
            stale_count += 1
    return {
        "rule_count": n,
        "rules_with_no_behavioral_history": no_behavioral_history,
        "pct_stale_over_2yr_behavioral": 100.0 * stale_count / n if n else 0.0,
        "pct_touched_behaviorally_within_6mo": (
            100.0
            * sum(
                1
                for r in report.rules
                if (r.behavioral_commit_count or 0) > 0 and (r.days_since_behavioral_change or 10**9) <= 182
            )
            / n
            if n
            else 0.0
        ),
    }


def compute_semantic_diff(
    root: Path,
    fmt: str = "sigma",
    mechanical_threshold: float = DEFAULT_THRESHOLD,
    subdir: Optional[str] = None,
    as_of: Optional[date] = None,
    staleness_report: Optional[StalenessReport] = None,
    all_facts: Optional[list] = None,
) -> SemanticDiffReport:
    """Pass 2: classify every organic touch Pass 1 (`churn.mine_organic_touches`)
    identified, then enrich `staleness_report`'s per-rule `RuleChurn` records
    with the new behavioral/cosmetic/semantic_metadata fields in place.

    If `staleness_report` isn't supplied, `churn.compute_staleness` is run
    with the same arguments first - callers that already have one (e.g. the
    CLI's `report`/`triage` commands) should pass it in to avoid mining the
    repo's history twice.

    `all_facts`, if given (e.g. from `churn.mine_commits`, mined once by the
    caller), is threaded through to `mine_organic_touches` so this function
    never re-mines history on its own - between this and the
    `staleness_report` passthrough, a caller that mines once up front (as
    Part 3's gathering script now does) triggers exactly one full traversal
    per repo, not three.
    """
    from mechanic import churn as churn_mod

    root = Path(root)
    as_of = as_of or datetime.now().date()
    if staleness_report is None:
        staleness_report = churn_mod.compute_staleness(
            root, fmt, mechanical_threshold, as_of=as_of, subdir=subdir, all_facts=all_facts
        )

    touches = mine_organic_touches(root, fmt, mechanical_threshold, subdir=subdir, all_facts=all_facts)
    creation_touches = [t for t in touches if t.is_creation]
    diffable_touches = [t for t in touches if not t.is_creation]

    fetcher = _BlobFetcher(root)
    method_counts: dict[str, int] = {}
    fetch_failures = 0

    per_rule: dict[str, dict[str, Any]] = {
        r.file: {"behavioral_dates": [], "cosmetic": 0, "semantic_metadata": 0, "confidences": []}
        for r in staleness_report.rules
    }

    for t in diffable_touches:
        before_text = fetcher.text_at(t.parent_hash, t.old_path)
        after_text = fetcher.text_at(t.commit_hash, t.new_path)
        if before_text is None or after_text is None:
            fetch_failures += 1
            continue
        result = classify_change(before_text, after_text, Path(t.new_path), fmt=fmt)
        method_counts[result.method] = method_counts.get(result.method, 0) + 1
        bucket_stats = per_rule.get(t.canonical_file)
        if bucket_stats is None:
            continue  # shouldn't happen: mine_organic_touches only yields current files
        bucket_stats["confidences"].append(result.confidence)
        if result.bucket == "behavioral":
            bucket_stats["behavioral_dates"].append(t.author_date)
        elif result.bucket == "semantic_metadata":
            bucket_stats["semantic_metadata"] += 1
        elif result.bucket == "cosmetic":
            bucket_stats["cosmetic"] += 1
        # bucket is None ("unknown"): counted in method_counts but not in any
        # per-rule bucket - an honest gap, not silently folded into cosmetic.

    _CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}
    updated_rules: list[RuleChurn] = []
    for r in staleness_report.rules:
        stats = per_rule[r.file]
        behavioral_dates = stats["behavioral_dates"]
        confidence = None
        if stats["confidences"]:
            confidence = min(stats["confidences"], key=lambda c: _CONFIDENCE_RANK[c])
        last_behavioral = max(behavioral_dates) if behavioral_dates else None
        r.behavioral_commit_count = len(behavioral_dates)
        r.last_behavioral_change = last_behavioral
        r.days_since_behavioral_change = (as_of - last_behavioral).days if last_behavioral else None
        r.cosmetic_commit_count = stats["cosmetic"]
        r.semantic_metadata_commit_count = stats["semantic_metadata"]
        r.classification_confidence = confidence
        updated_rules.append(r)
    staleness_report.rules = updated_rules

    return SemanticDiffReport(
        root=str(root),
        total_organic_touches=len(touches),
        creation_touches=len(creation_touches),
        classified_touches=sum(method_counts.values()),
        content_fetch_failures=fetch_failures,
        method_counts=method_counts,
        staleness=staleness_report,
    )
