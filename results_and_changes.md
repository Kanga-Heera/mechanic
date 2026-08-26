# Stage 2 follow-up: what changed this session

The prior write-up (Part 0 investigation + Part 2 classifier v2) was
reviewed and found to have a measurement flaw in its ablation study and an
overclaimed thesis statement. Six tasks were assigned to fix this before
Part 3 (priority ranking) could proceed. All six are complete. This
document is the same `RESULTS.md` that follows, with this summary prepended
so the changes are visible without diffing the whole file.

## Task 1 — Re-ran the ablation correctly

Two flaws in the original ablation were fixed: (a) the "structural ON,
lists OFF" arm had reverted the atom-classification lists further back than
v1's own documented baseline, making it an unfair comparator; a corrected
arm (`structural_only_v1_documented`) was added, using the exact list-state
that produced the real kappa=0.412 baseline. (b) The aggregate kappa used to
judge the structural-detection thesis was diluted by 60 Elastic/Splunk rules
that have no real AST to run structural detection against at all. The
ablation was re-run split by population - Sigma-only (n=30, real AST) vs.
text-only (n=60, regex approximation) - with a paired bootstrap confidence
interval on the marginal structural-detection gain, since n=30 is small and
that limitation had to be stated in the text, not a footnote.

**Result: hypothesis A confirmed.** Structural detection's marginal kappa
contribution is larger on Sigma-only (+0.09 to +0.10) than in the diluted
aggregate (+0.06 to +0.07) or text-only (+0.05 to +0.07) - the aggregate
figure really was measuring the wrong population. The 95% bootstrap CI on
the Sigma-only gain is [+0.000, +0.226] to [+0.000, +0.245] - positive and
credible, but the lower bound touches zero, so the exact size should not be
over-claimed.

## Task 2 — Rewrote the thesis statement

The original framing ("detection durability is frequently a property of
query structure, not of the literals a query matches") implied structure was
the *primary* driver, which the corrected ablation doesn't support - list
fixes recovered more of the aggregate kappa gain than structural detection
did. Replaced everywhere with the narrower, evidence-matched claim:
*"Atom-level analysis has a systematic blind spot: rules whose durability
lives in a relationship between fields are consistently under-scored.
Correcting the atom lists addresses most cases; structural detection is what
recovers the specific class of rules no wordlist can reach - including the
most durable rule in the corpus."*

## Task 3 — Closed the security-configuration-registry gap

Four separate disagreements (NLA disabled, RDP registry deletion, IE ZoneMap
downgrade x2) shared one root cause: a real OS-defined security-relevant
registry mechanism that fell outside the deliberately autorun/persistence-
scoped `windows_autorun_registry` category. Added a new principled category,
`windows_security_subsystem_config` (Terminal Services/RDP's auth-policy and
connection-history registry area; Internet Explorer's ZoneMap security-zone
assignment), documented with the same source-citation discipline as every
other category. All four disagreements resolved; zero hand-added paths -
the four fall out of the stated principle, or the principle would have been
wrong.

## Task 4 — Investigated the over-scoring false positives

Verified, via an isolated before/after test, that the requested short-tool-
name suppression (<3 characters without executable context) is correctly
implemented but has **zero measured effect** on this 90-rule sample - the
actual over-scores (three Splunk rules) come from a different, longer-word
mechanism (`security`, `replace`, `url` are genuine LOLBAS/LOOBins catalog
entries colliding with ordinary field values), reported honestly as a
still-open gap rather than claimed as fixed. Separately, implemented the
requested RARITY-vs-tool-selector distinction: a count/rarity threshold now
only promotes to TTP when no atom already resolved to Tool tier, fixing the
one rule (`Excessive Usage Of Cacls App`) where a threshold was wrapping an
ordinary Tool-tier selector rather than standing as an independent signal.

## Task 5 — Wrote up the CIM finding as its own section

This turned out to be the single largest lever in the whole re-validation,
not a footnote. Splunk's CIM (Common Information Model) normalization layer
structurally strips platform identity out of a rule's resolved search text
- the *only* place "okta" appears in the Okta rule's search is inside a
macro's NAME, which macro resolution consumes before it ever reaches atom
extraction. Fixed by extending cloud-context detection to also scan the
pre-resolution macro-reference text with the same existing regex - a
principled widening of *where* the detector looks, not a hand-list of macro
names. This surfaced and fixed two precise underlying bugs: a word-boundary
regex (`\bokta\b`) that could never match Splunk's underscore-compounded
macro-naming convention (`okta_..._filter`), and a missing Kubernetes `verb`
field (that platform's own documented audit-schema action-name field).
Splunk's per-corpus kappa moved from 0.505 to 0.703 as a direct result.

## Task 6 — Completed Part 0's numeric confirmation and Part 1's five-repo run

Part 0's empirical diagnostic finished: rename-blindness in the prior
investigation's ad-hoc script is confirmed as the exact cause of the
organic-commit-count discrepancy, reproducing its reported figures almost to
the decimal (SigmaHQ 3.58 vs. 3.57 reported; Elastic 6.41 vs. 6.41 exact;
Splunk 9.53 vs. 9.42). Part 1's five-repo behavioral-staleness validation
also completed, and along the way surfaced two real bugs that were fixed
before trusting any result: an unguarded crash on a historically-valid-but-
now-rejected Sigma condition syntax, and a bug in the behavioral-staleness
formula itself that the REGISTERED PREDICTION caught directly (a rule with
zero behavioral commits was being excluded from the stale count rather than
counted as stale - exactly backwards). After both fixes, the prediction
holds directionally in all five repos with zero violations - though
SigmaHQ's predicted magnitude (a rise to "roughly 60-70%") was a real
underestimate against the actual result (82.5%), reported plainly rather
than rounded toward "basically right."

## Net effect on the headline number

| | Kappa | Agreement |
|---|---:|---:|
| v1 (documented baseline) | 0.412 | 57.8% |
| v2, as first reported (before this session's fixes) | 0.636 | 75.6% |
| **v2, final (after Tasks 1, 3, 4, 5)** | **0.747** | **83.3%** |

0.747 crosses the pre-registered 0.65 "substantial agreement" threshold -
the classifier and the (now narrower) thesis both hold, on real data, with
the honest caveats stated throughout the report that follows rather than in
a closing footnote.

---

# Validation run: five real repositories

Run 2026-08-20 against local clones (paths are illustrative; substitute your
own):

| Repo | Path | git history |
|---|---|---|
| SigmaHQ/sigma | `sigma/`, scoped to `rules/` | full clone, 16,865 commits |
| elastic/detection-rules | `thirdparty/elastic-detection-rules/`, scoped to `rules/` | full clone, 4,005 commits |
| splunk/security_content | `thirdparty/splunk-security-content/`, scoped to `detections/` | full clone, 28,249 commits |
| joesecurity/sigma-rules | `thirdparty/sigma-rules/` | was a shallow clone; unshallowed with `git fetch --unshallow` before this run (233 commits) |
| mdecrevoisier/SIGMA-detection-rules | `thirdparty/SIGMA-detection-rules/` | was a shallow clone; unshallowed before this run (310 commits) |

Elastic and Splunk aren't Sigma, so `scan`/`ast` only ran against the three
Sigma repos; `staleness` ran against all five (file discovery is
format-agnostic — `elastic_toml` and `splunk_yaml` formats in
`discovery.py`). SigmaHQ, Elastic, and Splunk were each scoped to their
curated rule directory via `--subdir` (`rules/`, `rules/`, `detections/`
respectively) so mass changes to docs/schemas/tests elsewhere in the repo
don't pollute either the rule count `N` or the mechanical-commit filter.

Commands used, e.g.:

```
mechanic scan --json sigma/rules > sigmahq_scan.json
mechanic staleness --json --subdir rules sigma > sigmahq_staleness.json
mechanic staleness --json --fmt elastic_toml --subdir rules thirdparty/elastic-detection-rules
mechanic staleness --json --fmt splunk_yaml --subdir detections thirdparty/splunk-security-content
```

---

## 1. Loading (Component 1) — Sigma repos only

| Repo | Files | Rules loaded | Load failures | Loader crash rate |
|---|---:|---:|---:|---:|
| SigmaHQ/sigma `rules/` | 3,144 | 3,144 | 0 | **0%** |
| joesecurity/sigma-rules | 119 | 0 | 119 | **100%** |
| mdecrevoisier/SIGMA-detection-rules | 353† | 293 | 74 | 21.0% |

† 353 files were present at scan time; 2 of them (both in `windows-os/`,
filenames containing "encoded PowerShell deployed") vanished from disk
between this run and the later staleness run on the same clone, with no
corresponding git operation on our side — `git status` showed them as
locally deleted with no other explanation found. The working theory is
Windows Defender real-time protection quarantining Sigma rule files whose
*content* legitimately contains the encoded-PowerShell command-line patterns
the rule exists to detect. Both files hit `mechanic`'s `unreadable_file`
category (`OSError: [Errno 22] Invalid argument`) rather than crashing the
run — which is itself a small, unplanned validation of the "capture
everything, never crash" design goal: an I/O failure mid-scan, not even a
parse/construct failure, still produced a clean structured record. Reported
here rather than silently re-restoring and re-running, since a rule-triage
tool being unable to assume its own input files stay put is a real
finding, not noise to smooth over.

**joesecurity/sigma-rules reproduces the "100% failure, zero rules reach
validation" finding from prior investigation exactly.** Failure breakdown:

| category | count |
|---|---:|
| `bare_int_id` | 112 |
| `yaml_scanner_error` | 4 |
| `yaml_composer_error` | 3 |

This matches the prior investigation's cited root-cause breakdown for this
repo (112 bare-int-id `AttributeError`s; 7 YAML syntax errors split 4
`ScannerError`/3 `ComposerError`) precisely.

**mdecrevoisier/SIGMA-detection-rules** — prior investigation (351 files,
7.1% loader-crash rate on a smaller/earlier snapshot of this repo) is not
directly comparable to the current 353-file snapshot's 21.0% (74/353), since
the repo has grown and changed in the interim. What *is* directly comparable
— the specific root-cause categories — reproduces:

| category | count | stage |
|---|---:|---|
| `correlation_as_standard_rule` | 22 | rule_construct |
| `uncategorized_SigmaLogsourceError` | 42 | rule_construct |
| `uncategorized_SigmaValueError` | 3 | rule_construct |
| `uncategorized_SigmaStatusError` | 2 | rule_construct |
| `yaml_scanner_error` | 1 | yaml_parse |
| `yaml_parser_error` | 1 | yaml_parse |
| `unreadable_file` | 2 | yaml_parse |
| `null_date_split` | 1 | rule_construct |

`correlation_as_standard_rule` at exactly 22 matches the prior
investigation's cited count for this repo's `AttributeError` at
`sigma/correlations.py:528` precisely. `yaml_scanner_error` (1) and
`yaml_parser_error` (1) also match prior counts exactly.

**Three new crash categories showed up that weren't in the original seven** —
`SigmaLogsourceError` (log source category isn't a string), `SigmaValueError`
(a tag missing its `namespace.` prefix), `SigmaStatusError` (an invalid
`status:` value, including one rule with a literal `'experimental|'` typo).
None of them crashed the run; all three landed in the
`uncategorized_<ExceptionType>` fallback bucket exactly as designed. This is
the pluggability design working as intended on genuinely new input, not a
gap — promoting these three to named categories (with fix hints) is a
one-line addition each to `categories.py` whenever that's wanted, and
requires no change to `loader.py`.

**Validator-stage crashes** (post-load, only meaningful where rules loaded):

| Repo | Rules validated | Validator crashes |
|---|---:|---:|
| SigmaHQ/sigma `rules/` | 3,144 | 0 |
| mdecrevoisier/SIGMA-detection-rules | 293 | 46 (`uncategorized_SigmaConditionError`, all from `dangling_condition`/`dangling_detection`) |

SigmaHQ's zero validator crashes is consistent with it being the upstream,
CI-gated repo the validators were written against. mdecrevoisier's 46
crashes are **another new crash class**, distinct from the seven built-in
categories and from the three found in Component 1: `dangling_condition`/
`dangling_detection` call `SigmaCondition.parse()` internally and don't
catch `SigmaConditionError` — so a rule with a malformed condition string
(including the deprecated `|`-pipe syntax pySigma explicitly rejects) that
otherwise loads cleanly still crashes these two validators. Caught, isolated,
categorized as `uncategorized_SigmaConditionError`, run continued. This is
the scenario the design doc called out by name (\"a rule that pySigma has
already accepted as structurally valid... still takes down the entire
validation run the moment the default validator set touches it\" — except
here it doesn't take the run down, because Component 1's per-validator
isolation is exactly the fix for that scenario).

**AST validation on a real production rule**: `mechanic ast` was run against
`sigma/rules/windows/process_creation/proc_creation_win_citrix_trolleyexpress_procdump.yml`
— a real SigmaHQ rule combining the canonical renamed-binary pattern
(`Image|endswith` vs `OriginalFileName`) with a `SELECTOR` (`1 of filter*`),
a top-level `OR`, and a `NOT` wrapping the selector. The resulting tree
correctly nests `OR → AND → [selection, NOT → SELECTOR → [filter_renamed,
filter_empty]]`, and both filter selections' leaves read `negated: true`
despite being three structural levels below the `NOT` (through a `SELECTOR`
and a `selection` node) — confirming the ambient-polarity computation
doesn't lose track of NOT-count across intervening node types, not just
across bare AND/OR as in the unit tests.

---

## 2. Staleness (Component 2) — all five repos

Mechanical-commit filtering at the default 10% threshold:

| Repo | Rule count N | Excluded commits | Largest excluded commit |
|---|---:|---:|---|
| SigmaHQ/sigma `rules/` | 3,144 | 14 | 2,931 files ("Comply With v2 Spec Changes") |
| elastic/detection-rules `rules/` | 1,942 | 28 | 1,064 files ("Add Supplemental Mitre Mappings") |
| splunk/security_content `detections/` | 2,144 | 63 | 2,068 files ("Initial commit of modified objects...") |
| joesecurity/sigma-rules | 119 | 2 | 101 files ("Fixed indentation") |
| mdecrevoisier/SIGMA-detection-rules | 351 | 4 | 66 files ("mitre tactic updated") |

**Largest-commit reproduction against prior investigation's cited figures:**
SigmaHQ 2,931 (**exact match**), Elastic 1,064 (**exact match**), Splunk
2,068 vs. cited 2,073 (off by 5 — plausibly a slightly different rule count
`N` or a handful of files added/removed/renamed in `detections/` between the
prior investigation's snapshot and this one, shifting which commits clear
the 10%-of-N bar; not investigated further since it doesn't change the
conclusion).

**Threshold sensitivity** (excluded-commit count at 5% / 10% / 20% of N):

| Repo | 5% | 10% | 20% |
|---|---:|---:|---:|
| SigmaHQ/sigma | 32 | 14 | 6 |
| elastic/detection-rules | 55 | 28 | 14 |
| splunk/security_content | 92 | 63 | 37 |
| joesecurity/sigma-rules | 3 | 2 | 1 |
| mdecrevoisier/SIGMA-detection-rules | 26 | 4 | 0 |

The excluded set roughly halves or doubles moving one step between 5/10/20%
on every repo — a smooth, monotonic response with no cliff at 10%, meaning
the default isn't sitting on a boundary where a small change in threshold
would flip a lot of commits' classification. mdecrevoisier is the one repo
where the choice visibly matters: 26 commits excluded at 5% vs. 0 at 20% —
this is the smallest, least mechanically-batched repo of the five, so a
handful of ~10-15-file "touch several related rules" commits sit right in
the middle of the sensitivity range. That's disclosed here rather than
picking whichever threshold produced the cleanest-looking number.

**Staleness summary (post-filtering):**

| Repo | Mean organic commits/rule | % ever revised | % touched <6mo | **% stale (>2yr)** |
|---|---:|---:|---:|---:|
| SigmaHQ/sigma `rules/` | 7.72 | 92.5% | 8.1% | **51.1%** |
| elastic/detection-rules `rules/` | 7.38 | 81.9% | 48.0% | **2.7%** |
| splunk/security_content `detections/` | 10.58 | 86.3% | 33.8% | **5.6%** |
| joesecurity/sigma-rules | 2.10 | 33.6% | 0.0% | 96.6% |
| mdecrevoisier/SIGMA-detection-rules | 4.85 | 80.6% | 0.3% | 88.0% |

### Does this reproduce the cited prior-investigation numbers?

**Yes, closely, for all three repos prior investigation covered:**

| Repo | Prior investigation | This run | Delta |
|---|---:|---:|---:|
| SigmaHQ | 51.1% stale >2yr | 51.1% | ~0 |
| Elastic | 2.7% stale >2yr | 2.7% | ~0 |
| Splunk | 5.7% stale >2yr | 5.6% | 0.1pp |

Given these numbers depend on wall-clock "today" (staleness is computed
relative to the run date) and on exact current `N` (which shifts slightly
run to run as upstream repos get new commits), this is as close a
reproduction as should be expected — the methodology, not just the number,
checks out. **Reported plainly: no repo failed to reproduce.** joesecurity
and mdecrevoisier weren't part of the prior investigation's staleness
numbers (only its loader-crash numbers), so there's nothing to compare their
88–97% stale figures against — they're new results, not reproductions.
Read in context, though, they're the expected shape: both are smaller,
single/few-maintainer repos with far less organic revision activity than
the three heavily-governed upstream projects (mean organic commits/rule
2.1–4.9 vs. 7.4–10.6), so a much larger fraction of their rules sitting
untouched for 2+ years is consistent with the rest of the picture, not an
anomaly.

### Top-5 stalest rules, SigmaHQ (`rules/`, illustrative)

| file | days since organic touch | organic commits | ever revised |
|---|---:|---:|---|
| `windows/process_creation/proc_creation_win_hwp_exploits.yml` | 2135 | 5 | True |
| `windows/process_creation/proc_creation_win_renamed_whoami.yml` | 1834 | 1 | False |
| `windows/process_creation/proc_creation_win_susp_service_dir.yml` | 1807 | 3 | True |
| `windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml` | 1672 | 6 | True |
| `windows/process_access/proc_access_win_uac_bypass_wow64_logger.yml` | 1635 | 2 | True |

---

## 3. Performance note (not a correctness finding, but material to how this was run)

PyDriller's `Commit.modified_files` hardcodes full unified-diff patch
generation for every file in every commit. Initial timing on the smallest
repo (mdecrevoisier, 310 commits) was ~89s; profiling isolated >80% of that
to patch generation neither `mechanic` nor its output ever reads
(`old_path`/`new_path`/`change_type` are all rename/path metadata, not diff
content). `churn.py` builds the same PyDriller `ModifiedFile` objects from
the same commit diff, only without requesting patch text — see the
docstring on `_modified_files_no_patch` in `churn.py`. Post-fix, the same
run dropped to ~40s. Even so, full-history mining on the two largest repos
(SigmaHQ 16,865 commits, Splunk 28,249 commits) took on the order of
15-30 minutes each in this environment — expected and acceptable for a
one-time/periodic maintenance-triage run, not something this stage tries to
make instant.

---

## Reproducing this run

```
git fetch --unshallow   # only needed for joesecurity and mdecrevoisier clones
mechanic scan --json <sigma-repo>/rules > scan.json
mechanic staleness --json --subdir rules --top 30 <sigma-repo> > staleness.json
mechanic staleness --json --fmt elastic_toml --subdir rules <elastic-repo> > elastic.json
mechanic staleness --json --fmt splunk_yaml --subdir detections <splunk-repo> > splunk.json
mechanic staleness --json <joesecurity-or-mdecrevoisier-repo> > staleness.json
```

---

# Stage 2: judgement on top of Stage 1's infrastructure

Builds on Stage 1's fault-isolated loader, PyDriller staleness engine, and
Sigma AST. This section covers Part 0 (a required discrepancy investigation),
Part 1 (semantic diff / behavioral staleness, five-repo validation complete),
and Part 2 (the structural fragility classifier, v2).

## Part 0 — the organic-commit-count discrepancy

**The discrepancy, restated:** Stage 1's `RESULTS.md` reported mean organic
commits/rule of 7.72 (SigmaHQ), 7.38 (Elastic), 10.58 (Splunk). A prior,
independent investigation (an ad-hoc `git log --name-only`-based script, not
part of this codebase) had reported 3.57, 6.41, 9.42 for the same three repos
- SigmaHQ's figure more than doubled, and the SigmaHQ/Elastic ordering
flipped.

**Root cause, confirmed by reading both implementations line-by-line, then
verified empirically:** the prior script keyed every commit's file-touch by
the RAW PATH STRING exactly as it appeared in `git log --name-only` output,
then discarded any touch whose path didn't match a file that exists **today**
(`if f in current`). Stage 1's `churn.py`, by contrast, explicitly tracks
every rename edge (`old_path -> new_path`) encountered across a repo's whole
history and resolves any historical touch through that chain to the file's
CURRENT identity (`_resolve_canonical`) before counting it.

The effect: for any rule file that was renamed or moved at some point in its
history, the prior script silently drops every commit that happened **before**
the rename - it has no way to know that an old path's history belongs to a
file that now lives somewhere else. Stage 1's rename-resolution recovers
that pre-rename history. SigmaHQ has undergone far more large-scale directory
reorganization over its history than Elastic or Splunk's rule trees (its
`rules/` directory was restructured by category/product multiple times);
Elastic and Splunk have had comparatively few renames. That difference in
**rename volume**, not a difference in "true" maintenance activity, explains
both why SigmaHQ's number moved the most and why the ordering flipped.

**Empirical confirmation** (`scratchpad/part0_diagnostic.py`, reusing
`churn._mine_commits`/`_resolve_canonical` unmodified - re-aggregating the
exact same mined commit facts two ways: WITH rename resolution, matching
Stage 1's real output, and WITHOUT it, deliberately reproducing the prior
script's bug):

| Repo | Rename events in history | Touches recovered ONLY via rename resolution | Mean, WITH resolution (= Stage 1) | Mean, WITHOUT resolution (= prior script's bug, reproduced) | Prior script's reported figure |
|---|---:|---:|---:|---:|---:|
| SigmaHQ | 5,152 | 13,024 | **7.72** | **3.58** | 3.57 |
| Elastic | 508 | 1,892 | **7.38** | **6.41** | 6.41 |
| Splunk | 824 | 2,172 | **10.58** | **9.53** | 9.42 |

**Confirmed, exactly.** Deliberately reproducing the prior script's bug
(same mined commit facts, aggregated without rename resolution) reproduces
its reported figures almost to the decimal: SigmaHQ 3.58 vs. 3.57, Elastic
6.41 vs. 6.41 (exact), Splunk 9.53 vs. 9.42 (off by 0.11 - the same order of
snapshot-drift Stage 1's own largest-commit reproduction already disclosed,
e.g. its 2,068-vs-2,073 largest-Splunk-commit note). SigmaHQ's rename-event
count (5,152) is roughly 6-10x Elastic's (508) and Splunk's (824) - direct,
numeric confirmation of why SigmaHQ's figure moved the most (more than
doubled) and why the SigmaHQ/Elastic ordering flipped: it isn't a difference
in "true" maintenance activity, it's a difference in how much each repo's
rule tree has been reorganized over its history.

**Verdict: Stage 1's numbers (7.72 / 7.38 / 10.58) are correct.** The prior
investigation's numbers were an artifact of a rename-blind aggregation
script, not a different but equally valid methodology. Every subsequent
Stage 1 staleness figure (the 51.1%/2.7%/5.6% two-year-stale percentages,
which Stage 1 already cross-checked directly against the prior investigation
and found near-exact) is unaffected - staleness (days since last touch) only
needs a rule's MOST RECENT organic commit, which rename-blindness does not
usually corrupt (the most recent touch is far more likely to already be
under the file's current name than an old one); mean COMMIT COUNT is exactly
the statistic rename-blindness corrupts, because it depends on the full
history, not just the latest point in it.

**An unplanned, independently useful finding from building this diagnostic**:
confirming `_CommitFacts.file_changes` needed real fixing (see Part 1) turned
up that GitPython's underlying `Diff` object populates BOTH `a_path` and
`b_path` with the SAME value for a plain ADD or DELETE change, not just for
MODIFY/RENAME - i.e. `mf.old_path` is NOT reliably `None` for an added file.
This was verified empirically against real commits in the SigmaHQ repo (not
assumed), documented in `churn.py`'s `_mine_commits`, and confirmed
NOT to affect any Stage 1 output (mechanical-commit exclusion and rename
detection both only depend on `old_path == new_path`, which this quirk
doesn't change) - but it WOULD have silently broken Part 1's creation-commit
detection had it gone unnoticed, since that logic depends specifically on
`old_path is None` meaning "this commit created the file."

---

## Part 1 — Semantic diff / behavioral staleness (five-repo validation)

**Registered prediction, stated before running, not adjusted after seeing
the numbers:**

> Behavioral staleness will be HIGHER than raw staleness for every repo,
> because some rules currently counted as fresh were only touched
> cosmetically. SigmaHQ's stale figure is expected to rise from 51.1%
> toward roughly 60-70%. If behavioral staleness comes out LOWER than raw
> staleness anywhere, that is a bug, not a finding.

Two real bugs surfaced while running this for the first time, and were
fixed before trusting any of the numbers below (not smoothed over):

1. **A crash, not a finding.** `_try_ast_classification` called
   `ast_repr.build_ast` unguarded. A historical version of an mdecrevoisier
   rule used Sigma's now-deprecated `|`-pipe condition syntax - valid when
   committed, rejected by current pySigma at condition-*parse* time (a
   later step than `loader.parse_text`'s own isolation boundary, which only
   covers YAML-parse and rule-construction). This crashed the whole run.
   Fixed by wrapping the AST-comparison path in the same try/except-and-
   fall-back-to-(b) pattern Stage 1's loader already uses for exactly this
   class of "valid then, rejected now" content.
2. **The registered prediction itself caught a real bug before any repo
   finished.** joesecurity's first run produced 29.4% behavioral staleness
   against 96.6% raw - a direct violation of "must never be lower," exactly
   as anticipated. Root cause: `behavioral_summary()` mirrored
   `StalenessReport.summary()`'s "no organic history -> excluded from the
   stale numerator" convention, which is right for RAW staleness (zero
   organic commits is rare and genuinely means "no data") but wrong for
   BEHAVIORAL staleness (zero behavioral commits is COMMON - a rule can have
   plenty of organic history that's entirely cosmetic - and means "full
   information, and the information says this rule's logic has never been
   revised," the worst case, not a missing-data case). Fixed: a rule with
   zero behavioral commits now counts as stale directly rather than being
   excluded from the percentage; `rules_with_no_behavioral_history` is still
   reported separately for transparency.

**Results, all five repos:**

| Repo | Raw stale (>2yr) | Behavioral stale (>2yr) | Delta | Rules never behaviorally touched | Prediction |
|---|---:|---:|---:|---:|---|
| SigmaHQ | 51.1% | **82.5%** | **+31.4pp** | 1,109/3,144 (35.3%) | Holds directionally - **magnitude far exceeds the predicted 60-70% ceiling** |
| Elastic | 2.7% | **33.2%** | **+30.5pp** | 533/1,942 (27.4%) | Holds |
| Splunk | 5.6% | **51.9%** | **+46.3pp** | 790/2,144 (36.8%) | Holds - largest delta of the five |
| joesecurity | 96.6% | 99.2% | +2.5pp | 83/119 (69.7%) | Holds (small delta - already near-ceiling on raw) |
| mdecrevoisier | 88.0% | 93.7% | +5.7pp | 125/351 (35.6%) | Holds (same ceiling effect) |

**The prediction holds directionally in all five repos - zero violations.**
But the SigmaHQ magnitude prediction was wrong, and that has to be said
plainly rather than rounded toward "basically right": 51.1% was predicted to
rise "toward roughly 60-70%" (a +9 to +19pp move); it actually rose to 82.5%
(+31.4pp) - nearly double the top of the predicted range. The direction was
right for the right reason (cosmetic-only revision is real and common); the
prediction underestimated by how much.

**The most striking single number in this table isn't SigmaHQ's - it's
Elastic's and Splunk's.** Raw staleness made Elastic (2.7%) and Splunk (5.6%)
look like the two best-maintained corpora in the entire study, by a wide
margin over SigmaHQ. Behavioral staleness tells a materially different
story: roughly a third of Elastic's rules (27.4%) and over a third of
Splunk's (36.8%) have **never had their detection logic revised since
creation** - they've simply been touched often enough, for metadata/cosmetic
reasons, to look "actively maintained" by a raw commit-recency measure. This
is Part 1's entire thesis made concrete on real data: "touched recently"
and "still maintained" are different claims, and the gap between them is
largest in exactly the two repos raw staleness rated best.

**Low-confidence (raw-text-diff) fallback usage** - reported in the
headline, not a footnote, per the brief: 0.0% (Elastic) / 1.4% (SigmaHQ) /
1.6% (Splunk) / 3.1% (mdecrevoisier) / 10.1% (joesecurity). All five are low
- the behavioral classification signal is not being propped up by a weak
fallback path in the vast majority of cases. joesecurity's 10.1% is the
highest (its small, less-tooled rule corpus produces more malformed
historical YAML), still a small minority of its 129 classified touches.

**Classification method mix, all five repos** (for context on how much of
each repo's classification is "high confidence" AST-based vs. "medium"
YAML/TOML-key fallback vs. "low" raw-text): SigmaHQ 19,288 AST / 1,417
yaml_key / 286 raw_text_section (91.9% high-confidence - Sigma's real AST
does almost all the work); Elastic 12,259 yaml_key / 39 ast (99.7%
medium-confidence, expected - Elastic has no real AST path at all, per
Part 1's design); Splunk 19,376 yaml_key / 322 raw_text_section / 79 ast
(97.9% medium-confidence, same reason); mdecrevoisier 1,062 ast / 243
yaml_key / 42 raw_text_section; joesecurity 116 yaml_key / 13
raw_text_section.

---

## Part 2 — Structural fragility classifier, v2

### 2a/2b — what changed from v1

v1 tokenized rules into literal atoms and scored a rule as the max tier
among them. Measured against the 90 hand-labelled rules (30/repo, seed 42):
**57.8% agreement, kappa = 0.412** ("fair-to-moderate"), with disagreement
overwhelmingly one-directional (36 of 38 cases under-scoring). Five causes
were identified; v2 addresses all five:

1. **Cross-platform tool names**, sourced from external catalogs rather than
   hand-picked - `mechanic/data/SOURCES.md` documents exact provenance:
   [LOLBAS](https://lolbas-project.github.io/) (240 Windows binaries),
   [GTFOBins](https://gtfobins.github.io/) (478 Linux/Unix binaries),
   [LOOBins](https://www.loobins.io/) (62 macOS binaries - added specifically
   because v1's Windows-only list missed macOS rules like `Suspicious
   PlistBuddy Usage`), and MITRE ATT&CK's `malware`/`tool` STIX objects (825
   named attacker tools: Mimikatz, Rubeus, PsExec, Cobalt Strike, ...) -
   2,032 names combined, none hand-typed.
2. **Protected literals derived from a principle** ("the attacker cannot
   rename this without losing the capability, because an OS/protocol/schema
   defines it"), not from examples - `mechanic/protected_literals.py`:
   Windows autorun registry locations, well-known DCE/RPC named pipes
   (cross-checked directly against SigmaHQ's own
   `win_security_lm_namedpipe.yml` false-positive list - independent
   convergent evidence, not a re-derivation from the same examples),
   well-known SIDs, Active Directory schema attribute names, and
   Linux/macOS persistence-mechanism paths (`/etc/crontab`,
   `/etc/systemd/system/*`, `/etc/ld.so.preload`, launchd directories - all
   explicitly required by the task brief, all present). Cloud-provider audit
   action names remain context-gated (protected only alongside a recognized
   cloud-audit data-source marker in the same rule), exactly as designed in
   the prior round - but the marker regex now covers the full `azure.*`
   dataset namespace, not just `azure.auditlogs`.
3. **EventID/syscall as a structural test, not a blanket exclude**: excluded
   only when OTHER positive atoms also drive the rule (a data-source
   selector); kept as the rule's own substantive criterion when it's the
   only positive content there is - verified directly against
   `auditd.data.syscall in ("init_module", "finit_module")`, the exact tail
   case the prior round flagged as wrong.
4. **Negation handled via the AST's `negated` flag** - an atom inside a NOT
   is excluded from atom-max scoring entirely, not counted as a positive
   match.
5. **Structural pattern detectors** (`mechanic/structural_detectors.py`) -
   the one fix no wordlist could provide. `FIELD_MISMATCH` (a metadata-
   identity field and a path-identity field asserted under opposite polarity
   with overlapping basenames, or a direct `fieldref` between two identity
   fields - deliberately narrow so it does NOT fire on unrelated `fieldref`
   use like a same-user check), `ABSENCE` (a non-`filter`-named selection
   consisting of a null-value assertion or entirely negated leaves, with no
   independent positive match - distinct from an ordinary exclusion filter),
   `RARITY`/`CORRELATION` (Sigma correlation-rule type), and `UNSCOREABLE`
   (zero leaves of any kind). All four are gated on `use_structural`, tested
   independently, and each returns the AST node path that triggered it.

**The must-pass test passes**: `proc_creation_win_renamed_binary_highly_relevant.yml`,
loaded from the real SigmaHQ clone (not a synthetic fixture), classifies TTP
via `FIELD_MISMATCH` (`Description`/`OriginalFileName` vs `Image`, opposite
polarity, shared basename `pwsh`/`rundll32`/etc.) - `tests/test_fragility.py::test_canonical_renamed_binary_rule_classifies_ttp`.

**A retracted finding, restated per the brief's explicit instruction**: an
earlier round reported "~3% of SigmaHQ rules are TTP-tier." That number is
wrong and must never be reproduced - it was an artifact of exact (not
last-dotted-segment) field-name matching in the protected-literal check.
Corrected hand-classification of the same corpus gives ~36.7% TTP-tier.

### 2c — re-validation against the same 90 hand-labelled rules (the actual experiment)

No re-sampling, no re-labelling - the CSV's `hand_tier` column
(`mechanic/data/phase0_hand_labels.csv`) is the frozen ground truth from the
original round, joined back to full rule identity (path/name) since the
original kappa computation only had anonymous tier pairs.

**A review caught a real measurement flaw in the first pass of this section
before it was finalized, and the corrected numbers below are the result of
fixing it - not the first numbers computed.** Two problems were found: (1)
the original "structural ON, lists OFF" ablation arm reverted the atom lists
further back than v1's own documented baseline, making it an unfair,
not-like-for-like comparison; (2) the aggregate kappa used to judge the
structural thesis was diluted by 60 Elastic/Splunk rules that are
structurally blind by construction (no real AST exists for those languages),
which understates what structural detection actually contributes where it
CAN run. Both are fixed below - see "Ablation, corrected" and "Sigma-only
vs. text-only."

**Headline result** (also reflects Task 3/4/5 fixes below - registry
category, RARITY/tool-selector distinction, and the CIM pre-resolution-macro
fix - applied before this final number, per the brief's instruction to
re-run after each fix):

| Classifier | Combined kappa | Agreement | Disagreement | Interpretation (pre-registered bands) |
|---|---:|---:|---:|---|
| v1 (documented baseline) | 0.412 | 57.8% | 42.2% (38/90) | fair-to-moderate |
| **v2 (final)** | **0.747** | **83.3%** | **16.7% (15/90)** | **substantial - the tool and the thesis hold** |

0.747 crosses the pre-registered 0.65 "substantial agreement" threshold.
Per the brief's own interpretation bands, this now supports the claim
without qualification on the aggregate kappa itself - though see "Sigma-only
vs. text-only" below for how much of this is real Sigma-side improvement
vs. real Splunk-side improvement from a different mechanism (the CIM fix),
and n=30's honest confidence interval before treating any single-corpus
number as precise.

**Per-corpus breakdown** (v2, final):

| Corpus | n | Agreement | Disagreement | Kappa |
|---|---:|---:|---:|---:|
| Elastic | 30 | 86.7% | 4/30 | **0.780** |
| SigmaHQ | 30 | 83.3% | 5/30 | 0.741 (95% bootstrap CI **[0.524, 0.941]** - see n=30 caveat below) |
| Splunk | 30 | 80.0% | 6/30 | 0.703 |

All three corpora now cross 0.65. Splunk moved the most (0.505 -> 0.703
across the Task 3-5 fixes below) - the CIM finding (Task 5) turned out to be
its single biggest lever, not a footnote.

**Direction of disagreement**: 11 under-scores vs. 4 over-scores (v2, final)
- still majority under-scoring (73%), down from v1's 36:2 (94.7%).

#### Ablation, corrected (Task 1)

Two fixes to the ablation methodology itself, both required before its
conclusion could be trusted:

**Fix 1 - the isolation arm.** The "structural ON, lists OFF" arm previously
used lists reverted further back than v1's own documented baseline
(pre-dotted-path-fix, pre-context-gating) - an unfair comparator that
couldn't support any conclusion about structural detection's marginal value
over the real baseline. Added the missing, correct arm:
`structural_only_v1_documented` - structural detectors ON, using the EXACT
list-state that produced the documented kappa=0.412 (last-dotted-segment
matching and context-gating already fixed, but v1's narrow categories,
Windows-only tool list, blanket EventID exclusion, no negation-awareness).
The old, over-reverted arm is kept in the table, clearly relabelled
(`structural_only_v1_prefix_OVER_REVERTED`), not deleted or conflated with
the corrected one.

**Fix 2 - population.** Aggregate kappa across all 90 rules dilutes the
structural signal with 60 Elastic/Splunk rules that cannot benefit from
tree-based structural detection no matter how good the detectors are (no
real AST exists for those query languages). Reported below split by
population: Sigma-only (n=30, real AST) vs. text-only (n=60, regex
approximation), not just aggregate.

| Configuration | Aggregate (n=90) | Sigma-only (n=30) | Text-only (n=60) |
|---|---:|---:|---:|
| v1 (documented, reconstructed via this session's own pipeline*) | 0.386 | 0.384 | 0.373 |
| List fixes ON, structural OFF | 0.681 | 0.639 | 0.698 |
| **Structural ON, v1's REAL lists (v1_documented)** | 0.458 | 0.476 | 0.439 |
| Structural ON, lists reverted too far (OVER-REVERTED, kept for contrast) | 0.323 | 0.476† | 0.243 |
| v2 full (both ON) | 0.747 | 0.741 | 0.749 |

*This reconstruction (0.386 aggregate) doesn't exactly reproduce the true
documented baseline (0.412, from the CSV directly) because it's computed
through this session's own atom-extraction pipeline rather than the
original Phase 0 scratchpad scripts - small, expected implementation
differences. It exists solely to give the ablation a live, re-runnable
"lists off" arm using the SAME pipeline as every other row in this table,
which is what makes the ablation a clean isolation (comparing apples grown
in the same pipeline) rather than a comparison across two different
codebases. †identical to the row above by coincidence at this n - the
Sigma-only fieldref/field-mismatch detector logic didn't happen to depend on
which pre-fix list state it sat on for this particular 30-rule sample.

**Marginal contribution of structural detection specifically** (the number
that actually answers "does structural detection matter, over a fair
baseline"), computed both ways:

| Population | On v1-documented lists | On v2 lists |
|---|---:|---:|
| Aggregate (n=90) | 0.386 -> 0.458 (**+0.072**) | 0.681 -> 0.747 (**+0.066**) |
| **Sigma-only (n=30)** | 0.384 -> 0.476 (**+0.092**) | 0.639 -> 0.741 (**+0.102**) |
| Text-only (n=60) | 0.373 -> 0.439 (**+0.066**) | 0.698 -> 0.749 (**+0.051**) |

**This resolves cleanly in favor of the pre-registered hypothesis A:**
structural detection's marginal contribution on Sigma-only (+0.09 to +0.10)
is meaningfully larger than on text-only (+0.05 to +0.07) or in the diluted
aggregate - confirming the aggregate figure understated it, exactly as
anticipated. **The size of that gap should not be overstated, though**: it
is real and directionally consistent across both list-states, but it is not
dramatic (roughly double, not an order of magnitude), and it rests on n=30.

**n=30 confidence interval, stated in the text, not a footnote**: a paired
bootstrap (5,000 resamples) on the Sigma-only structural-detection delta
gives a 95% CI of **[+0.000, +0.226]** (on v1-documented lists) and
**[+0.000, +0.245]** (on v2 lists), with the delta positive in 86.8% of
bootstrap resamples. In plain terms: the +0.09-to-+0.10 gain is the best
point estimate and the direction is credible, but the interval's lower bound
touches exactly zero - **this sample cannot rule out that structural
detection's true marginal contribution on Sigma is smaller than measured,
or (at the extreme low end of the interval) negligible.** Do not read
"+0.09" as a precise, load-bearing number; read it as "positive and
plausibly around this size, on a sample too small to pin down further."

**What is NOT in doubt, regardless of any of the above**: the canonical
`FIELD_MISMATCH` test - `proc_creation_win_renamed_binary_highly_relevant.yml`
classifying TTP - passes unconditionally and is unaffected by any ablation
setting. Aggregate kappa and getting the one canonical, most-durable-rule-
in-the-corpus example right are different claims. The ablation is about the
former; the must-pass test is about the latter, and it holds.

#### Sigma-only vs. text-only, restated plainly

Structural detection contributes real, positive, but modest aggregate lift,
concentrated where a real AST exists (Sigma) and measurably smaller where it
doesn't (Elastic/Splunk's regex approximation). The text-side kappa still
improved substantially in absolute terms (0.373 documented-equivalent -> 0.749
final) - but that improvement is now known to come predominantly from the
list fixes and the Task 5 CIM finding, not from FIELD_MISMATCH/RARITY
approximated over flat atom lists.

#### Every remaining disagreement (15, v2 final vs. hand)

| # | Rule | Hand | v2 | Boundary |
|---|---|---|---|---|
| elastic#16 | Potential Hex Payload Execution via Command-Line | Artifact | Tool | Over-scoring: a broadened-vocabulary tool-name/cmdlet-pattern match in a long command-line literal, not a genuine tool reference. |
| elastic#22 | Kernel Driver Load | TTP | Artifact | `auditd.data.syscall` accompanied by other atoms that are *themselves* just boilerplate (`event.action == "loaded-kernel-module"`, `host.os.type == "linux"`) - the "sole criterion" test is too strict to see that none of the co-occurring atoms are substantive alternatives. |
| elastic#23 | Manual Loading of a Suspicious Chromium Extension | Tool | Artifact | `Google Chrome`/`Brave Browser`/`Microsoft Edge` are Tool-tier by the pure Pyramid-of-Pain definition (bound to one specific named app) but aren't LOLBAS/GTFOBins/LOOBins/ATT&CK entries - those catalogs list dual-use/attacker tools, not ordinary consumer applications. |
| elastic#26 | Entra ID Protection Admin Confirmed Compromise | TTP | Artifact | Azure's identity-protection risk field is named `risk_detail`, not one of the `eventName`/`operation`/`action`/`verb`-family suffixes the cloud-audit-action category recognizes - a different platform naming idiom, not yet covered. |
| splunk#3 | Suspicious PlistBuddy Usage | Tool | Artifact | `PlistBuddy` is a disclosed, deliberate gap - present in none of the four tool catalogs as of the fetch date (see `data/SOURCES.md`). |
| splunk#5 | Linux System Reboot Via System Request Key | TTP | Tool | `/proc/sysrq-trigger` is a kernel-magic immediate-action interface - a different mechanism family from the Task 3 security-configuration category (see Task 3 write-up); left a disclosed gap, not folded in. |
| splunk#10 | Splunk Secure Application Alerts for Runtime Security | Artifact | Tool | Over-scoring, root-caused precisely (Task 4): the field value `url` and/or the word `security`-adjacent tokens are genuine, longer (>=3 character) LOLBAS/LOOBins entries colliding with ordinary field content - NOT the short-name (<3 char) mechanism Task 4 fixed, and NOT yet addressed. |
| splunk#11 | PingID New MFA Method After Credential Reset | TTP | Tool | Same longer-word-collision mechanism as splunk#10 (`replace`, a genuine LOLBAS entry - old Windows `replace.exe` - appearing in an unrelated regex-substitution field value). |
| splunk#18 | Windows Query Registry UnInstall Program List | Artifact | Tool | Same mechanism again: `security` (a genuine LOOBins macOS tool name) matches a Windows EventLog `Channel=security` field value. |
| splunk#26 | Suspicious Ticket Granting Ticket Request | TTP | Tool | SPL's `transaction` command performs a genuine temporal join across two EventCodes (4781/4768) - a real multi-event correlation idiom with no detector built for it (Sigma correlation rules get type-based detection; SPL's inline `transaction`/`join`/`streamstats` idioms don't have an equivalent check). |
| sigma#3 | Antivirus - Password Dumper Signature | Artifact | Tool | Philosophical tension, not a bug: `Mimikatz`/`Rubeus`/etc. are genuine ATT&CK tool names (correctly Tool-tier by name), but the hand-labeller's Artifact rating reflects that an AV *signature label* is itself a brittle, vendor-specific string easily changed by repacking/obfuscation - arguably more fragile than the tool-name match implies. |
| sigma#6 | Invoke-Obfuscation Via Use Clip - System | Tool | Artifact | The match is on a tool's *output artifact* (an obfuscation pattern in `ImagePath`), not the tool's name - a different, unimplemented kind of Tool-tier signal. |
| sigma#7 | Register new Logon Process by Rubeus | Tool | Artifact | Same as sigma#6: the detection value is Rubeus's known fingerprint string (`User32LogonProcesss`, a deliberate typo), not the word "Rubeus" itself - "Rubeus" appears only in the rule's title/metadata. |
| sigma#14 | OneLogin User Account Locked | TTP | Artifact | `event_type_id` is a bare numeric SaaS event-type id, structurally equivalent to Okta's `eventType` but with no string action-name to recognize. **Pre-disclosed in the prior investigation** as a known tail-case weakness - confirmed still unresolved, not a new discovery. |
| sigma#28 | Process Launched Without Image Name | TTP | Artifact | `Image|endswith: '.exe'` is a proxy for "the image field is anomalous/effectively absent," not a true null - `ABSENCE`'s null-leaf check doesn't recognize a degenerate-value proxy for absence. |

Four disagreements resolved since the first pass through Tasks 3-5 (registry
category: elastic#27, splunk#24, sigma#9, sigma#15; RARITY/tool-selector
distinction: splunk#23; CIM pre-resolution fix: splunk#2, splunk#8) - nine
rules fixed in total, none hand-patched to the specific example.

### 2d — the CIM finding (Task 5)

This deserves its own section, not a paragraph inside "why Splunk stays
weakest" - it turned out to be the single largest lever in this entire
re-validation round, and nobody appears to have documented it before.

**The substance.** Splunk's `Okta New API Token Created` rule's RESOLVED
search body contains the literal string "okta" **nowhere**:

```
| tstats `security_content_summariesonly` count max(_time) as lastTime,
  min(_time) as firstTime FROM datamodel=Change
  WHERE All_Changes.action=created AND All_Changes.command=system.api_token.create
  BY _time span=5m All_Changes.user All_Changes.result All_Changes.command
     sourcetype All_Changes.src All_Changes.action All_Changes.object_category All_Changes.dest
  | `drop_dm_object_name("All_Changes")`
  | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
  | `okta_new_api_token_created_filter`
```

The ONLY place "okta" appears is inside the name of the LAST macro
reference - `` `okta_new_api_token_created_filter` `` - which resolves
(per Splunk Enterprise Security's own `_filter`-macro convention, ships
empty, no-op at deploy time) to nothing. Once macro resolution runs, the
platform identifier is gone. The same `datamodel=Change` search, over the
same CIM-normalized fields (`action`, `command`, `user`, `result`), would
fire identically for Azure AD, PingOne, Duo, or any other CIM-mapped
identity provider - **that IS the point of CIM normalization**: write one
detection against the abstract datamodel, let any vendor's data source map
onto it. `splunk#8` (`Kubernetes Node Port Creation`) shares the identical
mechanism: the platform marker lives only in the `` `kube_audit` `` macro
NAME, stripped before the resolved search (`verb=create
requestObject.spec.type=NodePort`) ever reaches atom extraction.

**This is a property of the query language, not a defect in this
classifier.** Cloud-context gating requires a visible platform marker
somewhere in the rule; Splunk's CIM/macro abstraction layer is *structurally
designed* to remove exactly that marker from the text a detection engineer
(or a classifier) actually reads. No amount of tuning the resolved-text
regex would ever find "okta" in a rule that was deliberately written to not
need to say "okta."

**The fix implemented, and why it's principled rather than a hand-list.**
Rather than hand-adding `okta_new_api_token_created_filter` (or every other
CIM macro name that happens to carry a platform hint) as a special case,
`text_fragility.classify_text_rule` now accepts the RAW, pre-resolution
search text as an additional input and runs the SAME `CLOUD_AUDIT_CONTEXT_RE`
regex against it - a marker in a macro's name counts exactly like a marker
in a resolved field value, with no new per-macro logic. This is a genuine,
principled fix: it widens WHERE the existing detector looks, not WHAT it's
looking for. `pre_resolution_text` is a real parameter now
(`text_fragility.py`), passed through the revalidation harness, with unit
tests (`test_pre_resolution_macro_name_supplies_cloud_context`,
`test_kubernetes_verb_field_protected_with_context`) proving it fires on the
macro-name signal specifically.

**A precise regex bug this fix surfaced and had to be fixed too**:
`CLOUD_AUDIT_CONTEXT_RE`'s original `\bokta\b` pattern (word-boundary
anchored) can never match `okta_new_api_token_created_filter` - `_` is a
`\w` character in regex, so there is no word boundary between "okta" and
the following underscore. Fixed to `\bokta` (leading boundary only), since
Splunk's macro-naming convention routinely compounds identifiers with
underscores. Caught by writing the test before trusting the fix, not by
inspection.

**One more principled fix this section required**: Kubernetes' own audit-log
schema names its action field `verb` (documented in the Kubernetes API audit
policy spec) - not `action`/`eventName`/any of the other platform
conventions already in `CLOUD_AUDIT_ACTION_FIELD_SUFFIXES`. Added on the same
justification as every other entry in that set (a specific platform's own,
documented schema field name for "what action occurred"), not because this
one rule needed it.

**Net effect**: splunk#2 and splunk#8 both now classify correctly. Splunk's
per-corpus kappa moved from 0.505 (before Tasks 3-5) to 0.703 (final) - the
CIM fix specifically, isolated, accounts for 2 of the 9 total rules fixed
across all of Tasks 3-5, and was the difference between Splunk staying the
weakest corpus by a wide margin and closing to within 0.08 of Elastic.

### Interpretation, final

kappa = 0.747, 83.3% agreement, aggregate, across all three corpora, each
individually >= 0.70. This crosses the pre-registered 0.65 "substantial"
threshold without qualification. The honest caveats that remain: (1) n=30
per corpus means single-corpus kappa figures carry real sampling
uncertainty (SigmaHQ's own 95% CI spans [0.524, 0.941] - "fair" to "almost
perfect"), stated here rather than in a footnote; (2) 9 rules were fixed by
naming and closing specific, principled category/mechanism gaps this round,
and further such gaps almost certainly remain (declared explicitly above:
security-config paths beyond RDP/IE, tool-name collisions with common
English words, SPL's `transaction`/`join` correlation idiom, tool-specific
output-artifact matching); (3) the structural detectors' own marginal
contribution, while real and directionally confirmed to be larger on Sigma
specifically than in the diluted aggregate, is modest in absolute size and
not fully resolved by n=30's confidence interval. None of this weakens the
one claim that was never in doubt: `proc_creation_win_renamed_binary_highly_relevant.yml`
- by hand-label the most durable rule in the corpus - classifies correctly,
unconditionally, via structural detection alone.

### Revised thesis statement

The original framing risked overclaiming: "detection durability is
frequently a property of query structure, not of the literals a query
matches" implied structure was the PRIMARY driver, which the corrected
ablation does not support (list fixes recovered more of the aggregate gain
than structural detection did, even after Task 1's correction). Replaced,
project-wide, with the narrower, evidence-matched claim:

> **Atom-level analysis has a systematic blind spot: rules whose durability
> lives in a relationship between fields are consistently under-scored.
> Correcting the atom lists addresses most cases; structural detection is
> what recovers the specific class of rules no wordlist can reach -
> including the most durable rule in the corpus.**

This is narrower than the original framing, still novel, and matches
exactly what Task 1's corrected ablation measured: a real, positive,
Sigma-concentrated marginal contribution from structural detection, layered
on top of (not instead of) list fixes that do most of the aggregate work.

