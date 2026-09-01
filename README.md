# mechanic

Detection rule maintenance triage.

**Status, plainly, no spin:** the CORE product — a fault-isolated Sigma/
Elastic/Splunk rule loader, a git-driven behavioral staleness engine, and a
structural fragility classifier externally validated against MITRE Center
for Threat-Informed Defense's Summiting the Pyramid methodology (Kendall's
tau-b = 0.361, p = 0.0010 against MITRE's own human-expert-scored analytics
— see `RESULTS.md`) — is a finished, production-hardened rule-triage tool
that fills a gap nothing else in the space fills: alert triage is a crowded
field, but *rule* triage (telling an engineer which detection rules are
fragile and/or stale and therefore need attention first, at repository
scale) is not. It runs `scan`/`staleness`/`triage`/`explain` with zero
dependency on RSigma, zero network access, and no API key, enforced by a
test (`docs/core-vs-experiment.md`, `tests/test_core_isolation.py`) — see
`QUICKSTART.md` for five real commands against a real SigmaHQ checkout. A
separate, later Stage 3 experiment asked whether a fragile rule can be
*repaired* automatically and verified by a real detection engine rather than
an LLM's own say-so; that experiment is complete and its honestly-measured
result (a 3.6% acceptance rate, 1 of 28 sampled rules, independence-audited
— see `RESULTS.md`'s Stage 3 Phase 3 section) is a real finding worth
keeping, but it is **not** part of the core product, is not required for
anything above, and is quarantined into its own module tree and its own
`mechanic-repair` CLI so its presence, correctness, or failure can never
affect the core's reliability.

This project was originally scoped and built in three stages; the sections
below still describe Stage 1's infrastructure (loader, staleness, AST) in
detail, with Stage 2's fragility classifier and Stage 3's repair experiment
covered in `RESULTS.md` and the `docs/` status documents. It does **not**
judge ATT&CK coverage or claim to catch every possible evasion — see
`RESULTS.md` for every disclosed limitation, not just the ones repeated
here.

## Why this exists

Two things fell out of prior investigation into pySigma/sigma-cli and five
real-world rule repositories:

1. **`SigmaCollection.load_ruleset()` is not fault-tolerant.** It has no
   defensive coding around parsing untrusted YAML into a rule object: one
   malformed file kills the whole batch, and even its own `collect_errors`
   mode only catches `SigmaError` subclasses — not the `AttributeError`s and
   `TypeError`s that real-world rules actually trigger (a bare-int `id:`, a
   malformed correlation-rule document, a null date field). A second,
   independent crash class happens *after* successful parsing, during
   validation (a null `references:` entry blowing up a validator's
   `re.match()` call) — so isolation has to wrap the load step **and** every
   individual validator call, not just the load.
2. **Raw git commit counts are useless for measuring rule maintenance.**
   Mass mechanical commits (bulk reformats, metadata migrations, CI
   housekeeping) dominate them. The largest single commits observed:
   SigmaHQ 2,931 files, Splunk 2,073, Elastic 1,064 — each in one commit.

`mechanic` addresses both, plus builds the AST substrate a later
classification stage will need.

## Components

### 1. Fault-isolated rule loader (`mechanic/loader.py`, `mechanic/categories.py`)

Two layers of isolation:

- **Per-file** try/except around YAML parsing and `SigmaRule`/
  `SigmaCorrelationRule` construction. A crash on one document does not stop
  the batch; a crash on one document in a multi-document file does not stop
  the other documents in that file.
- **Per-rule-per-validator** try/except around every `validator.validate(rule)`
  call. A validator that crashes on one rule (e.g. the SigmaHQ github-link
  validator dying on a null `references:` entry) doesn't take down validation
  for every other rule.

Every failure becomes a structured `FailureRecord`: file, stage
(`yaml_parse` / `rule_construct` / `validate`), category, exception type,
message, line number (where recoverable — PyYAML errors carry a `problem_mark`;
most `AttributeError`/`TypeError` crashes don't have a YAML line to point at),
and a fix hint. Seven categories are built in (see below); anything else falls
into an `uncategorized_<ExceptionType>` bucket so it's still captured and
never silently swallowed or allowed to crash the run.

**Categories are pluggable two ways**, both in `categories.py`:

- `PREFLIGHT_CHECKS` — deterministic, version-independent structural checks
  run on the raw parsed YAML dict *before* pySigma ever sees it (bare-int
  `id`, null date fields, a malformed `correlation:` value). These don't
  depend on pySigma's internal exception text, which can change across
  versions.
- `REGISTRY` — reactive exception-pattern matchers, used as a fallback when
  no preflight check caught the problem, or for failures that only manifest
  once pySigma is actually running (YAML syntax errors, validator crashes).

Adding a new category means appending to one of these two lists. Nothing in
`loader.py` changes.

Built-in categories:

| category | stage | trigger |
|---|---|---|
| `bare_int_id` | rule_construct | `id:` is a bare YAML int; pySigma calls `UUID(id)` and dies |
| `correlation_as_standard_rule` | rule_construct | `correlation:` key present but its value isn't a mapping |
| `yaml_scanner_error` | yaml_parse | PyYAML `ScannerError` (tabs, bad tokens) |
| `yaml_composer_error` | yaml_parse | PyYAML `ComposerError` — usually an unquoted value starting with `*`, read as a YAML alias |
| `yaml_parser_error` | yaml_parse | PyYAML `ParserError` (malformed block structure) |
| `null_date_split` | rule_construct | `date:`/`modified:` present but null; pySigma calls `.split()` on it |
| `null_reference_typeerror` | validate | a null entry in `references:` crashes the SigmaHQ github-link validator's `re.match()` |

`mechanic scan <repo>` runs both layers and exits cleanly with a summary
instead of a traceback, no matter how broken the input is.

### 2. Staleness / organic churn (`mechanic/churn.py`)

All git access goes through `pydriller.Repository`; no subprocess git, no
manual `git log` parsing.

**Mechanical-commit filtering**, before any statistic is computed:

1. Compute the current rule count `N` (via `discover_files`).
2. Exclude any commit that touches `>= threshold * N` rule files (default
   `threshold = 0.10`, configurable via `--mechanical-threshold`).
3. Report every excluded commit (hash, subject, file count) so the filter is
   auditable, not a black box.
4. Report exclusion results at 5%, 10%, and 20% simultaneously (`sensitivity`
   in the JSON output / the "Threshold sensitivity" table), so the choice of
   default can't be dismissed as cherry-picked — you can see how much the
   excluded set changes as the threshold moves.

**Why 10%?** It's a round number picked to be well above the size of a
normal single-rule-tuning commit (touches 1 file) or a small coordinated
edit (a handful of related rules), and well below the size of the bulk
mechanical commits actually observed (which touch 30–100% of the corpus in
one shot). The sensitivity table exists specifically so this isn't just
taken on faith — see RESULTS.md for how much the excluded set shifts between
5% and 20% on each of the five validation repos.

Per-rule metrics after filtering: organic commit count, last organic commit
date, days since, an `ever_revised` flag, distinct author count. Renamed
files are followed across their whole history (rename edges collected from
`ModifiedFile.change_type == RENAME` during the one required traversal, then
resolved to each current file's canonical identity in pure Python — no
per-file `git log --follow` calls, which would not scale to a repo with
thousands of rule files).

**A known, documented limitation**: `ever_revised` is computed purely from
*organic* commits (`organic_commit_count > 1`). If a rule's creation commit
was itself part of a mass mechanical commit (common — that's exactly how
SigmaHQ/Splunk/Elastic onboarded large batches of rules at once) and it was
later tuned exactly once, organic history shows only 1 commit and
`ever_revised` reads `False` — even though a real edit happened. There is no
way to distinguish "created organically, never touched again" from "created
mechanically, revised exactly once" using only the organic commit stream;
both leave a count of 1. This is called out rather than smoothed over.

**Failure modes that are surfaced, not silently wrong**:

- **Shallow clone.** Detected via `.git/shallow`. A shallow clone's truncated
  history would silently understate every organic-commit count and every
  staleness figure — `mechanic` refuses to compute staleness at all and tells
  you to `git fetch --unshallow`.
- **No git history.** No `.git` directory, or zero commits — fails clearly
  rather than reporting an empty/zero staleness table.

**Performance note**: PyDriller's own `Commit.modified_files` hardcodes
`create_patch=True` in its underlying GitPython diff call, which computes
full unified-diff text for every file in every commit — the dominant cost on
a large repo, and unnecessary here since only `.old_path`/`.new_path`/
`.change_type` are ever read (all three come straight off diff/rename
metadata, none need patch text). `churn.py` builds the same `ModifiedFile`
objects PyDriller would, from the same underlying commit diff, just without
requesting patch generation — a large, correctness-neutral speedup, not a
bypass of PyDriller's history-mining logic. `pydriller.metrics.process.
CommitsCount` is still used for a contrast "raw commit-touch volume" figure,
bounded to a trailing 365-day window so it stays cheap regardless of total
repo history length — it's illustrative context only, never an input to any
staleness computation.

### 3. Rule AST (`mechanic/ast_repr.py`)

Converts a successfully-loaded rule into a syntax-independent tree:
selections/filters as named nodes, AND/OR/NOT as structure, `field`/
`operators`/`value` triples as leaves, and an explicit `negated` polarity
flag on every node (computed as the ambient ancestor NOT-count XORed with
each detection item's own `negated` flag, so a leaf under `not (a or b)`
reads `negated: true` regardless of how many ORs sit between it and the
`not`). `logsource` and ATT&CK tags are carried as rule-level metadata.

Rather than hand-writing a condition-string grammar, this reuses pySigma's
own pyparsing-based parser (`sigma.conditions`) and its `SigmaDetection`/
`SigmaDetectionItem` structures — specifically the *non*-postprocessed parse
tree (`SigmaCondition.parse(postprocess=False)`), so named selections stay
intact as nodes instead of being fully inlined, then converts that into a
small, stable, JSON-safe dict shape (see `mechanic ast <file>` / the JSON
schema below). A small traversal API (`iter_leaves`, `iter_selections`,
`is_negated`) sits on top.

**Prior art**: ARMS (Ghaffarzadegan, Concordia MASc thesis, April 2026) also
converts Sigma rules to an AST, for mutation-based rule testing. Same
conversion idea; different purpose (this AST is meant as the classification
substrate for Stage 2's maintenance-triage work) and an independent
implementation.

Correlation rules (`correlation:` documents) have no detection tree — they
reference other rules by id/name — and are represented minimally
(`{"type": "correlation", "id": ..., "title": ...}`).

### 4. CLI (`mechanic/cli.py`)

```
mechanic scan <path>        # load report + failure diagnosis
mechanic staleness <path>   # staleness report
mechanic ast <file>         # dump one rule's AST
mechanic report <path>      # scan + staleness combined
```

Common options: `--json` (machine-readable, all commands), `--top N`
(stalest N rules), `--fmt` (rule format — see `mechanic/discovery.py`),
`--mechanical-threshold`, `--subdir` (restrict a repo to a subdirectory for
staleness, e.g. SigmaHQ's `rules/` while excluding `rules-emerging-threats/`
etc. — the git root stays at the repo root pydriller needs).

Rule-file discovery (`mechanic/discovery.py`) is format-agnostic and
pluggable — staleness works on any rule-file repo (Elastic's TOML, Splunk's
YAML), not just Sigma; only `scan` and `ast` require actual Sigma YAML.

### 5. Priority / triage (`mechanic/priority.py`, Stage 3 / Part 3)

```
mechanic triage <path>   # review-priority ordering, staleness + fragility side by side
mechanic explain <file>  # why one rule sits where it does
```

**This does not compute a combined score, and that is a finding, not a
missing feature.** Part 3's original premise was that behavioral staleness
(Part 1) and fragility tier (Part 2) should be fused into one weighted
priority number, conditional on a pre-registered correlation experiment
(Task 7, see RESULTS.md's "Part 3 (pre-work)" section) actually finding an
association between the two that survives an age control. It didn't:
SigmaHQ (the one corpus with externally-validated tiers) shows no
meaningful association at all, and Elastic shows a real one that survives
age-stratification but runs in the direction that argues AGAINST combining
the signals, not for it. Per the interpretation fixed in advance, this
means: two independent axes, not a combined score. No `--weight` flag
exists here because Task 7 found no statistical basis for one — adding a
configurable weight over an association that isn't there (or runs
backwards) would manufacture false precision, not add flexibility.

What `triage` actually does:

- Runs staleness + fragility once per rule, using `--mechanical-threshold`
  (same parameter, same default, same justification as Section 2 above —
  it is not re-derived for Part 3, since it is the same commit-classification
  boundary).
- Sorts for **scanning convenience only** — fragility tier first (the only
  axis with any external validation, via STP), then never-revised/staleness
  as a tie-break — explicitly labelled in the CLI output as not a validated
  score.
- Reports every rule's fragility **confidence**, propagated from Part 2:
  `high` for Sigma's AST path (AND/OR-corrected against STP), `medium` for
  Elastic/Splunk's text-only path — visible on every row and in `--json`,
  not just in this document, per the same source rules always carrying the
  caveat that their tier is computed WITHOUT the AND/OR correction (no
  parse tree to walk).
- Puts every unscoreable rule in its own section (`unscoreable` in
  `--json`), each with the specific reason (`UNSCOREABLE` structural
  detector, insufficient information, failed to parse, no query/search
  text) — never defaulted into a tier.
- Offers **triage hypotheses** (`likely-repairable`, `likely-needs-
  telemetry-check`, `likely-retire`) from simple, documented, arbitrary
  threshold combinations of the two axes (`mechanic/priority.py::_hypotheses`)
  — labelled as Stage 3 hypotheses to be tested in later work, never as
  conclusions, and never as a verdict on an individual rule. `mechanic
  explain` and every table header say "review this," not "this is bad."

`mechanic explain <file>` auto-detects the git repository above `<file>`
and re-runs the same full-corpus computation `triage` uses (so numbers are
always consistent between the two commands), then prints that one rule's
signals - leading with a **prose narrative** (`RuleSignals.narrative`), not
a table of field names and values first: a few sentences on what the
staleness and fragility facts actually mean for this rule, ending with
"review this," followed by the full field/value/atom/structural-detector
detail underneath for anyone who wants to verify the narrative against the
raw data. For a text-path (Elastic/Splunk) rule, the AND/OR-correction
caveat is one of those sentences, not a footnote - it renders in the
narrative itself. Per-node AST path breadcrumbs are not tracked by the
classifier (`mechanic/fragility.py` records field/value/tier/reason per
atom, not a path into the tree) - `explain` reports the full reasoning
trail that actually exists rather than fabricating path detail that
doesn't. One full example: see RESULTS.md's Part 3 validation section.

**Git-history mining is cached to disk**, keyed to the repo's current
`git rev-parse HEAD` (`churn.mine_commits_cached`, cache file under
`<repo>/.mechanic_cache/`) - `triage`/`explain` share the cache with each
other and across separate invocations, so running several
`--mechanical-threshold` values (or restarting after an interrupted run)
doesn't re-pay the full mining cost each time. If the repo has moved
forward since the cache was written, it's detected and re-mined
automatically, never silently served stale; pass `--refresh` to force a
re-mine regardless.

Validation (top-20 SigmaHQ triage output with full explanations, threshold
sensitivity, bucket counts, unscoreable counts and reasons): see RESULTS.md.

**Priority (CRITICAL/HIGH/MEDIUM/LOW)** is layered on top of the same two
axes as an explicit, documented lookup table
(`mechanic/priority.py::PRIORITY_MATRIX`) — never a third, blended number.
It exists precisely because the two axes above don't fuse (Task 7's own
finding); the matrix is a transparent function of them, always shown with
both axis values (`mechanic priority-legend` prints the table itself, no
repository needed). See `RESULTS.md`'s "Priority as a transparent matrix"
section for the full rationale and the correction made to the naive "worse
tier = TTP" framing (it's IOC, matching mechanic's own tier semantics and
the STP validation's direction).

```
mechanic priority-legend        # the fixed matrix + rationale, no repo needed
mechanic triage --ordering priority_first <path>
```

### 6. GUI (`mechanic gui`, `mechanic/gui/`)

```
mechanic gui                    # opens http://127.0.0.1:8642/ in a browser
```

A local, offline web GUI over the exact same engine — no repair, no
network, no API key. It's a FastAPI backend that calls
`priority.compute_triage()` (the same function `triage`/`explain` use) and
serves its JSON to a static vanilla-JS frontend: repo overview cards,
a sortable/filterable triage table with the priority matrix cell on every
row, a rule-detail panel (the same `explain` prose), and a priority-matrix
legend. Needs the optional `gui` extra (`pip install "mechanic[gui]"`).
Full architecture, the offline guarantee, and how "this never recomputes
anything" is actually enforced (not just claimed): see
[`docs/gui-notes.md`](docs/gui-notes.md).

## JSON schema (stable — Stage 2/3 consume this)

`scan --json`:

```jsonc
{
  "root": "...", "files_scanned": 0, "files_ok": 0, "files_failed": 0,
  "rules_loaded": 0, "failures_total": 0,
  "failures_by_category": {"<category>": 0},
  "rules": [{"file": "...", "type": "standard|correlation", "id": "...", "title": "..."}],
  "failures": [{
    "file": "...", "stage": "yaml_parse|rule_construct|validate",
    "category": "...", "exception_type": "...", "message": "...",
    "line": null, "fix_hint": "...", "validator": null
  }],
  "validate_failures": [ /* same shape as failures, stage == "validate" */ ]
}
```

`staleness --json`:

```jsonc
{
  "root": "...", "rule_count": 0, "mechanical_threshold": 0.10,
  "raw_commit_total": 0, "raw_commit_window_days": 365,
  "excluded_commits": [{"hash": "...", "subject": "...", "rule_files_touched": 0}],
  "summary": {
    "rule_count": 0, "rules_with_no_organic_history": 0,
    "mean_organic_commits_per_rule": 0.0, "median_organic_commits_per_rule": 0.0,
    "pct_ever_revised": 0.0, "pct_touched_within_6mo": 0.0, "pct_stale_over_2yr": 0.0
  },
  "sensitivity": [{"threshold": 0.05, "excluded_commit_count": 0, "excluded_commits": [ /* ... */ ]}],
  "rules": [{
    "file": "...", "organic_commit_count": 0, "last_organic_commit_date": null,
    "days_since": null, "ever_revised": false, "distinct_author_count": 0
  }],
  "top_stalest": [ /* same shape as rules, present only when --top passed */ ]
}
```

`ast <file>` (one rule; a list if the file has multiple documents):

```jsonc
{
  "schema_version": 1, "type": "standard|correlation",
  "id": "...", "title": "...",
  "logsource": {"product": null, "category": null, "service": null},
  "tags": ["attack.execution"], "attack_tags": ["attack.execution"],
  "conditions": [ /* one root node per condition: string in the rule */ ]
}
```

Node shapes under `conditions`:

- `{"node": "AND"|"OR"|"NOT", "negated": bool, "children": [node, ...]}`
- `{"node": "SELECTOR", "quantifier": "1"|"any"|"all", "pattern": "...", "negated": bool, "children": [selection, ...]}`
- `{"node": "selection", "name": "...", "kind": "selection"|"filter", "negated": bool, "child": node}`
- `{"node": "leaf", "kind": "field_value"|"keyword"|"field_null"|"keyword_null", "field": "...", "operators": ["contains", ...], "value": ..., "negated": bool}`

`triage --json`:

```jsonc
{
  "root": "...", "fmt": "sigma", "mechanical_threshold": 0.10, "ordering": "tier_first",
  "rule_count": 0, "scoreable_count": 0, "unscoreable_count": 0,
  "summary": "N rules, X fragile, Y stale, Z need attention (fragile AND stale)",
  "bucket_counts": {"likely-repairable": 0, "likely-needs-telemetry-check": 0, "likely-retire": 0},
  "priority_breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNCERTAIN": 0},  // sums to rule_count
  "priority_matrix": { /* the full matrix schema - see `priority-legend --json` below, embedded here too so a GUI never needs a second call to render its legend */ },
  "disclosure": "...",  // the no-combined-score disclosure, always present, never omit when displaying this data
  "rules": [ /* scoreable rules, sorted per `ordering` - shape below */ ],
  "unscoreable": [ /* same shape, tier/fragility fields null/empty, unscoreable_reason set */ ]
}
```

`ordering` accepts `tier_first` (default), `staleness_first`, or `priority_first` - all three are unweighted
lookups/sorts, never a fused score (see `mechanic/priority.py`'s module docstring for why).

Each entry in `rules`/`unscoreable` (also the shape `explain --json` returns for one rule):

```jsonc
{
  "file": "...",
  "narrative": "...",       // full prose - what `explain` prints first
  "short_reason": "...",    // one line - the specific driving observable, what `triage`'s table shows
  "staleness": {
    "behavioral_commit_count": 0, "never_revised": false,
    "days_since_behavioral_change": 0, "age_days": 0,
    "classification_confidence": "high|medium|low|null",
    "is_stale": false        // same 730-day (2yr) threshold as staleness's own pct_stale_over_2yr
  },
  "fragility": {
    "tier": "IOC|Artifact|Tool|TTP|null", "confidence": "high|medium|low",
    "and_or_corrected": true, "unscoreable": false, "unscoreable_reason": null,
    "structural_findings": [], "structural_detail": {}, "atoms": [{"field": "...", "value": "...", "tier": "...", "reason": "..."}],
    "caveat": null  // non-null ONLY for the text-only (Elastic/Splunk) path - always check this before trusting a tier at face value
  },
  "is_fragile": false,       // tier in {IOC, Artifact, Tool}
  "needs_attention": false,  // is_fragile AND staleness.is_stale
  "priority": {
    "label": "CRITICAL|HIGH|MEDIUM|LOW|null",  // null exactly when uncertain=true - never a guessed label
    "tier": "IOC|Artifact|Tool|TTP|null",       // axis 1 - ALWAYS present alongside label, never a bare label
    "staleness_band": "stale_over_2yr|aging_6mo_to_2yr|fresh_under_6mo|null",  // axis 2
    "lower_confidence": false,   // true for text-path (Elastic/Splunk) tiers - same signal as fragility.caveat
    "uncertain": false,          // true if label is null (unscoreable rule, or unresolvable staleness band)
    "uncertainty_reason": null   // stated reason whenever uncertain=true
  },
  "triage_hypotheses": []    // UNTESTED Stage 3 labels - never a verdict, see disclosure
}
```

**The `fragility.caveat` field is the machine-readable form of the text-path confidence warning** - any consumer building automation on top of `--json` output must check it before treating a `tier` as high-confidence; it is non-null precisely (and only) when the tier came from the Elastic/Splunk text-only path rather than a Sigma AST walk.

**Priority is a lookup, never a fused score** - `priority.label` is always paired with `priority.tier` and `priority.staleness_band`, the exact two axes that produced it (`mechanic/priority.py::PRIORITY_MATRIX`); no consumer should display `label` without them. `mechanic priority-legend --json` returns the matrix itself (also embedded as `priority_matrix` in every `triage --json` response):

```jsonc
{
  "tiers_worst_to_best": ["IOC", "Artifact", "Tool", "TTP"],
  "staleness_bands_stale_to_fresh": ["stale_over_2yr", "aging_6mo_to_2yr", "fresh_under_6mo"],
  "labels_worst_to_best": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
  "cells": [{"tier": "IOC", "staleness_band": "stale_over_2yr", "label": "CRITICAL"}, /* ... 12 total */],
  "rationale": "..."
}
```

`report --json` is `{"scan": <scan output + validate_failures>, "staleness": <staleness output or null>, "staleness_error": "..." or null}`.

## Prior art

**Summiting the Pyramid (STP)** — MITRE Center for Threat-Informed Defense's
published, versioned (currently v4.0) methodology for scoring detection-
analytic robustness against adversary evasion
(https://ctid.mitre.org/projects/summiting-the-pyramid/,
https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/).
This is prior art for mechanic's fragility taxonomy itself, not a peer
comparison — mechanic's IOC/Artifact/Tool/TTP tiers were arrived at
independently but measure the same construct STP formalized first, with
industry partners. SigmaHQ has formally adopted STP: the `stp` tag is
defined in the official Sigma specification
(`sigma-appendix-tags.md`). See `RESULTS.md`'s STP validation section and
`data/STP_MAPPING.md` for the full comparison, including a discovered,
unresolved divergence in how mechanic combines multiple observables within
one rule versus STP's own documented AND/OR combination rule.

Other related work in this space, from Stage 2's earlier prior-art review:
sigmalint, EvoSIEM, Uetz et al., GRIDAI, RuleGenie, and ARMS (cited in
context above, in Component 3) — each addresses a different piece of the
detection-engineering-quality problem (linting, evasion generation/testing,
automated repair, rule generation, mutation testing) rather than STP's and
mechanic's shared target of scoring robustness itself.

## Stage 3 (built, but NOT part of the core - see status note at the top)

At the time this section was originally written, Stage 3's verification
harness was still deferred, pending a choice of matching engine (zircolite
was the leading candidate). It has since been built - `docs/stage3-harness-
evaluation.md` documents the actual investigation and decision, which
landed on **RSigma** instead, not zircolite. The harness, gate, evasion
transformer, and LLM repair generator all exist now
(`mechanic/verify.py`, `mechanic/gate.py`, `mechanic/evasion.py`,
`mechanic/repair_generator.py`, run via the separate `mechanic-repair` CLI)
and are complete, with an honest, disclosed result (RESULTS.md's Stage 3
Phase 3 section). None of it is part of the core described above, by
design - see `docs/core-vs-experiment.md` for the boundary and how it's
enforced.

## Explicitly out of scope for this stage

No fragility scoring, no ATT&CK technique-proximity analysis, no evasion
generation, no repair, and no heuristic anywhere that judges whether a rule
is *good*. The AST captures structure and polarity, nothing else.

## Running

```
pip install -e .[dev]
mechanic scan  /path/to/rules
mechanic staleness /path/to/repo --subdir rules
pytest tests/
```

See `RESULTS.md` for the five-repo validation run.
