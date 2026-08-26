# Validation run: five real repositories

Every external dataset, corpus, or catalogue this project depends on
(rule corpora, STP's own repo and ScoredAnalytics CSV, LOLBAS/GTFOBins/
LOOBins/ATT&CK STIX, pySigma/PyDriller) is registered with its exact
commit/tag/release, retrieval date, and licence in
[`DATASETS.md`](DATASETS.md) - consult it before citing any version number
or count from this document elsewhere. STP's real-world public adoption
(the `stp` tag) is surveyed across every Sigma-format repository found,
with full commit provenance, in
[`STP_ADOPTION_CENSUS.md`](STP_ADOPTION_CENSUS.md) - the sparse-adoption
finding in "Part 2, external validation" below is this document's own
narrow coverage-survey step; the census is the fuller, sourced version of
that same claim.

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

> **Read this before any kappa/tau number below**: Part 2 went through
> several rounds of fixes across this document (Tasks 1-8, then an
> AND/OR rule-combination fix found via external STP validation). The
> section titled **"The AND/OR fix, implemented, and everything re-run"**
> (after the STP validation section) contains the TRUE, final, currently-
> accurate numbers: **STP external validation Kendall's tau = 0.361
> (p=0.001)**, and **LLM development-set kappa = 0.615 aggregate / 0.298
> SigmaHQ-only / 0.780 Elastic / 0.798 Splunk**. Every kappa/tau figure
> that appears BEFORE that section (0.412, 0.636, 0.747, 0.800, and the
> STP section's own first-pass tau=0.032) is a real, historically-accurate
> checkpoint at the time it was measured, kept in place rather than
> rewritten, but is **superseded** - read them as "what was true at that
> point in the investigation," not as the current state of the classifier.

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

**Headline finding, stated first:** raw commit recency rated Elastic (2.7%
stale) and Splunk (5.6%) as the two best-maintained detection-rule corpora
in this entire study, by a wide margin over every other repo tested.
Behavioral staleness shows that 27.4% of Elastic's rules and 36.8% of
Splunk's have never had their detection logic revised since creation. Two
commercially-backed detection engineering teams, each looking healthy by
every metric available before this project, with more than a quarter to
over a third of their logic untouched since the day it was written. This is
the project's strongest empirical result, not SigmaHQ's staleness figure
(SigmaHQ being stale was already the more expected finding going in, for
anyone in the field) - SigmaHQ's 82.5% below is real and reported in full,
but it is now supporting evidence for the same conclusion, not the
headline.

*(A note on framing this result against prior work: the intent was to cite
it against an existing "a green CI/passing build is not the same as a
correct one" line of argument from the software-engineering literature.
That specific citation - attributed to "Bower" - could not be verified: a
search turned up no paper, talk, or post by that name making this claim
with this phrasing. Rather than fabricate an attribution, the citation is
left out. If there's a specific source in mind, providing it will let this
be framed against it properly instead of asserting the connection
unverified.)*

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

**Bug #2 is worth treating as a finding about method, not filing away as a
bug report.** The registered-prediction discipline this project has followed
since Part 0 - write down what the number should look like BEFORE running,
including the explicit bound "if X happens, that's a bug" - did exactly the
job it exists to do here: it turned an otherwise-invisible logic error
(one that would have shipped a systematically wrong percentage into every
downstream Part 3 ranking with no error message, no crash, and a
plausible-looking number) into a same-day, caught-before-any-repo-finished
fix. No test suite would have caught this on its own - the formula was
internally consistent and would have passed a unit test asserting its own
logic. What caught it was stating in advance what the ANSWER should look
like and treating a violation of that bound as disqualifying rather than
as noise to explain away after the fact. This is the single strongest
argument in the whole project for keeping the pre-registration discipline
on every experiment from here forward, including Task 7 below.

**Results, all five repos:**

| Repo | Raw stale (>2yr) | Behavioral stale (>2yr) | Delta | Rules never behaviorally touched | Prediction |
|---|---:|---:|---:|---:|---|
| **Elastic** | **2.7%** | **33.2%** | **+30.5pp** | 533/1,942 (27.4%) | Holds |
| **Splunk** | **5.6%** | **51.9%** | **+46.3pp** | 790/2,144 (36.8%) | Holds - largest delta of the five |
| SigmaHQ | 51.1% | 82.5% | +31.4pp | 1,109/3,144 (35.3%) | Holds directionally - **magnitude far exceeds the predicted 60-70% ceiling** |
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
reasons, to look "actively maintained" by a raw commit-recency measure.
**How this was determined, stated in the same breath, not a later
paragraph**: Elastic and Splunk have no real AST (Stage 1 built one for
Sigma only), so this finding rests almost entirely on medium-confidence
TOML/YAML-key comparison - 99.7% of Elastic's classified touches and 97.9%
of Splunk's, vs. 91.9% high-confidence AST comparison for SigmaHQ. Medium
confidence here means "did the `query`/`search` key change at all," which
is a comparatively low bar to get right and is almost certainly adequate for
the claim actually being made (whether the field existed and changed, not a
semantic judgment about what changed) - but a reader evaluating "a third of
Elastic's rules were never behaviorally revised" should know in the same
breath that this rests on a field-level YAML/TOML diff, not a tree
comparison, before treating the number as being pinned down to Sigma's
level of confidence. This is Part 1's entire thesis made concrete on real
data: "touched recently" and "still maintained" are different claims, and
the gap between them is largest in exactly the two repos raw staleness
rated best.

**Low-confidence (raw-text-diff) fallback usage** - the WEAKEST tier, below
even the medium-confidence YAML/TOML-key comparison above, reported here too
rather than only in a footnote: 0.0% (Elastic) / 1.4% (SigmaHQ) / 1.6%
(Splunk) / 3.1% (mdecrevoisier) / 10.1% (joesecurity). All five are low - the
behavioral classification signal is not being propped up by the weakest
fallback path in the vast majority of cases. joesecurity's 10.1% is the
highest (its small, less-tooled rule corpus produces more malformed
historical YAML), still a small minority of its 129 classified touches.

**Full classification method mix, all five repos** (high-confidence AST vs.
medium-confidence YAML/TOML-key vs. low-confidence raw-text, spelled out in
full): SigmaHQ 19,288 AST / 1,417 yaml_key / 286 raw_text_section (91.9%
high-confidence - Sigma's real AST does almost all the work); Elastic
12,259 yaml_key / 39 ast (99.7% medium-confidence); Splunk 19,376 yaml_key /
322 raw_text_section / 79 ast (97.9% medium-confidence); mdecrevoisier 1,062
ast / 243 yaml_key / 42 raw_text_section; joesecurity 116 yaml_key / 13
raw_text_section.

---

## Part 2 — Structural fragility classifier, v2

### 2a/2b — what changed from v1

v1 tokenized rules into literal atoms and scored a rule as the max tier
among them. Measured against the 90 LLM-labelled rules (30/repo, seed 42):
**57.8% agreement, kappa = 0.412** ("fair-to-moderate") *(v1 baseline,
pre-dates every v2 fix including the AND/OR combination fix - see the
disclosure at the top of this stage; not the current classifier's number)*,
with disagreement overwhelmingly one-directional (36 of 38 cases
under-scoring). Five causes were identified; v2 addresses all five:

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
Corrected LLM-classification of the same corpus gives ~36.7% TTP-tier.

### 2c — re-validation against the same 90 LLM-labelled rules (the actual experiment)

**Disclosure, stated plainly before anything else in this section**: the
`llm_tier` column (`mechanic/data/phase0_llm_labels.csv`) is NOT human
ground truth. These 90 labels were generated by an earlier session of this
same assistant, reading each rule individually and assigning a tier - the
same agent that designed the IOC/Artifact/Tool/TTP taxonomy itself and
built the classifier now being scored against those labels. Labeler,
taxonomy designer, and reviewer were the same agent. Every kappa figure in
this section (and everywhere else in this document prior to the STP
validation section) measures agreement with that LLM-generated proxy label
set, not with human analysts. Treat the 90 rules as a **development set** -
genuinely useful for comparing classifier configurations against each other
under a fixed, consistent reference (which is exactly what the ablation
below does, and remains internally valid for that purpose) - not as
external validation. See the dedicated STP (Summiting the Pyramid)
validation section later in this document for agreement against an actual
external, human-produced standard on the same construct.

No re-sampling, no re-labelling within this set - the CSV's `llm_tier`
column is a frozen reference from the original round, joined back to full
rule identity (path/name) since the original kappa computation only had
anonymous tier pairs.

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
| v2, after Tasks 1/3/4/5 | 0.747 | 83.3% | 16.7% (15/90) | substantial |
| v2, after Task 8 (superseded by the AND/OR fix below) | 0.800 | 86.7% | 13.3% (12/90) | substantial at the time |

*(All three rows above are kappa under the since-corrected AND/OR
combination bug - see the disclosure at the top of this stage. None of
0.412/0.747/0.800 is the classifier's current number; the current,
accurate figures are STP tau=0.361 and LLM-set kappa 0.615
aggregate/0.298 SigmaHQ/0.780 Elastic/0.798 Splunk, from "The AND/OR fix,
implemented, and everything re-run" section. The 0.747 row is what the
rest of THIS section's ablation/Sigma-only/text-only tables are computed
against, since Task 8 - a field-context refinement to the tool-vocabulary
lookup - was requested and run afterward, as its own isolated experiment;
see section 2e for its own before/after.)*

0.747 (and, after Task 8, 0.800) crosses the pre-registered 0.65
"substantial agreement" threshold.
Per the brief's own interpretation bands, this now supports the claim
without qualification on the aggregate kappa itself - though see "Sigma-only
vs. text-only" below for how much of this is real Sigma-side improvement
vs. real Splunk-side improvement from a different mechanism (the CIM fix),
and n=30's honest confidence interval before treating any single-corpus
number as precise.

**Per-corpus breakdown** (v2, after Tasks 1/3/4/5, before Task 8 and before
the AND/OR fix - SigmaHQ's 0.741 in particular is superseded twice over, by
Task 8 first and then by the AND/OR fix; Elastic's 0.780 and Splunk's 0.703
happen to foreshadow their eventual unchanged-by-AND/OR final values, but
that was not yet established at this checkpoint):

| Corpus | n | Agreement | Disagreement | Kappa |
|---|---:|---:|---:|---:|
| Elastic | 30 | 86.7% | 4/30 | **0.780** *(kappa under the since-corrected combination bug; unchanged by that fix - see final numbers)* |
| SigmaHQ | 30 | 83.3% | 5/30 | 0.741 (95% bootstrap CI **[0.524, 0.941]** - see n=30 caveat below) *(kappa under the since-corrected combination bug; SigmaHQ's true final is 0.298, not this)* |
| Splunk | 30 | 80.0% | 6/30 | 0.703 *(kappa under the since-corrected combination bug; see Task 8's 0.798 and the AND/OR-fix section for later checkpoints)* |

All three corpora crossed 0.65 at this checkpoint. Splunk moved the most
(0.505 -> 0.703 across the Task 3-5 fixes below) - the CIM finding (Task 5)
turned out to be its single biggest lever, not a footnote.

**Direction of disagreement**: 11 under-scores vs. 4 over-scores (v2, final)
- still majority under-scoring (73%), down from v1's 36:2 (94.7%).

#### Ablation, corrected (Task 1)

**All kappa figures in this subsection (0.386-0.749 range, including the
0.747/0.741/0.749 "v2 full" cells) are computed under the since-corrected
AND/OR combination bug** - this ablation predates the STP-driven fix and
has not been re-run under the corrected AND=MIN/OR=MAX combination logic.
The qualitative conclusion below (structural detection contributes more on
Sigma-only than text-only) is about the STRUCTURAL DETECTOR layer, which
sits upstream of and is unaffected by the AND/OR combination step, and is
independently expected to still hold; the absolute kappa numbers
themselves are not current and should be read as "under the old
combination logic," not as today's classifier performance.

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

**Statistical significance, stated directly, not implied**: a paired
bootstrap (5,000 resamples) on the Sigma-only structural-detection delta
gives a 95% CI of **[+0.000, +0.226]** (on v1-documented lists) and
**[+0.000, +0.245]** (on v2 lists), with the delta positive in 86.8% of
bootstrap resamples. **86.8% of resamples positive corresponds to
approximately p≈0.13 one-sided - this is NOT statistically significant at
conventional thresholds (p<0.05), at n=30.** Say that plainly rather than
lean on "the CI is mostly positive": a point estimate of +0.09 to +0.10
kappa, on its own, is not strong enough evidence by itself to carry the
structural-detection claim.

**What actually supports the claim is not the point estimate** - it's three
things holding together: (1) the effect is positive and, critically,
**consistently LARGER on Sigma-only across BOTH independent list-states**
(+0.092 on v1-documented lists, +0.102 on v2 lists - two different atom-
classification configurations, same direction and similar magnitude, which
a spurious/noise-driven effect would not reliably reproduce); (2) the same
direction holds in the text-only split too, just smaller (+0.066 / +0.051),
so the Sigma-vs-text ordering itself is consistent, not a single lucky
comparison; and (3) the canonical `FIELD_MISMATCH` test -
`proc_creation_win_renamed_binary_highly_relevant.yml` classifying TTP -
passes unconditionally under every ablation setting, with no sampling
uncertainty at all, because it's a single deterministic test, not a
population estimate. Consistency across independent configurations plus an
unambiguous canonical case is the actual argument for structural detection
mattering here. A non-significant point estimate at n=30 cannot carry that
weight alone, and this report does not ask it to.

**The honest boundary of the structural claim - absolute-performance
parity.** Named here rather than left for a reader to spot in a table:
v2 full scores Sigma-only **0.741** and text-only **0.749** (0.796 and
0.801 respectively after Task 8's field-context fix, section 2e) - the text
corpora are marginally HIGHER in absolute terms, despite having no real
AST at all. Structural detection contributes more marginal LIFT where a
tree exists (the point made above), but the list fixes and the Task 5 CIM
discovery did enough work on the text side that Elastic/Splunk reach
parity with - and now slightly exceed - Sigma without ever building a real
EQL/SPL parser. **Relatedly**: Splunk's 0.505 -> 0.703 jump (before Task 8;
0.798 after) came predominantly from Task 5, which was a bug fix - a
`\bokta\b` word-boundary regex that could never match Splunk's underscore-
compounded macro-naming convention, plus a missing Kubernetes `verb` field.
That is real, correctly-found improvement, and it is debugging, not
evidence for the structural-detection thesis. Do not let Splunk's jump be
read as support for the structural claim; it supports the (separate,
already-established) claim that the list fixes and the CIM discovery matter
a great deal.

#### Sigma-only vs. text-only, restated plainly

Structural detection contributes real, positive, but modest aggregate lift,
concentrated where a real AST exists (Sigma) and measurably smaller where it
doesn't (Elastic/Splunk's regex approximation). The text-side kappa still
improved substantially in absolute terms (0.373 documented-equivalent -> 0.749
final) - but that improvement is now known to come predominantly from the
list fixes and the Task 5 CIM finding, not from FIELD_MISMATCH/RARITY
approximated over flat atom lists.

#### Every remaining disagreement (12, v2 true final [after Task 8] vs. the LLM-labelled development set)

| # | Rule | LLM label | v2 | Boundary |
|---|---|---|---|---|
| elastic#16 | Potential Hex Payload Execution via Command-Line | Artifact | Tool | Over-scoring: a broadened-vocabulary tool-name/cmdlet-pattern match in a long command-line literal. Confirmed NOT fixable by Task 8's field-context gate - the field genuinely IS `CommandLine`, a real process-context field, so the gate correctly does not suppress it. A different, still-open mechanism (see section 2e). |
| elastic#22 | Kernel Driver Load | TTP | Artifact | `auditd.data.syscall` accompanied by other atoms that are *themselves* just boilerplate (`event.action == "loaded-kernel-module"`, `host.os.type == "linux"`) - the "sole criterion" test is too strict to see that none of the co-occurring atoms are substantive alternatives. |
| elastic#23 | Manual Loading of a Suspicious Chromium Extension | Tool | Artifact | `Google Chrome`/`Brave Browser`/`Microsoft Edge` are Tool-tier by the pure Pyramid-of-Pain definition (bound to one specific named app) but aren't LOLBAS/GTFOBins/LOOBins/ATT&CK entries - those catalogs list dual-use/attacker tools, not ordinary consumer applications. |
| elastic#26 | Entra ID Protection Admin Confirmed Compromise | TTP | Artifact | Azure's identity-protection risk field is named `risk_detail`, not one of the `eventName`/`operation`/`action`/`verb`-family suffixes the cloud-audit-action category recognizes - a different platform naming idiom, not yet covered. |
| splunk#3 | Suspicious PlistBuddy Usage | Tool | Artifact | `PlistBuddy` is a disclosed, deliberate gap - present in none of the four tool catalogs as of the fetch date (see `data/SOURCES.md`). |
| splunk#5 | Linux System Reboot Via System Request Key | TTP | Tool | `/proc/sysrq-trigger` is a kernel-magic immediate-action interface - a different mechanism family from the Task 3 security-configuration category (see Task 3 write-up); left a disclosed gap, not folded in. |
| splunk#11 | PingID New MFA Method After Credential Reset | TTP | Artifact | Task 8 fixed the over-scoring mechanism (the spurious `replace` catalog match on a regex-substitution field is now correctly suppressed by field-context gating) - but the rule's genuine durability signal still isn't recognized by any current atom or structural check, so it now under-scores instead. A different disagreement than before, not the same one persisting. |
| splunk#26 | Suspicious Ticket Granting Ticket Request | TTP | Artifact | SPL's `transaction` command performs a genuine temporal join across two EventCodes (4781/4768) - a real multi-event correlation idiom with no detector built for it (Sigma correlation rules get type-based detection; SPL's inline `transaction`/`join`/`streamstats` idioms don't have an equivalent check). |
| sigma#6 | Invoke-Obfuscation Via Use Clip - System | Tool | Artifact | The match is on a tool's *output artifact* (an obfuscation pattern in `ImagePath`), not the tool's name - a different, unimplemented kind of Tool-tier signal. |
| sigma#7 | Register new Logon Process by Rubeus | Tool | Artifact | Same as sigma#6: the detection value is Rubeus's known fingerprint string (`User32LogonProcesss`, a deliberate typo), not the word "Rubeus" itself - "Rubeus" appears only in the rule's title/metadata. |
| sigma#14 | OneLogin User Account Locked | TTP | Artifact | `event_type_id` is a bare numeric SaaS event-type id, structurally equivalent to Okta's `eventType` but with no string action-name to recognize. **Pre-disclosed in the prior investigation** as a known tail-case weakness - confirmed still unresolved, not a new discovery. |
| sigma#28 | Process Launched Without Image Name | TTP | Artifact | `Image|endswith: '.exe'` is a proxy for "the image field is anomalous/effectively absent," not a true null - `ABSENCE`'s null-leaf check doesn't recognize a degenerate-value proxy for absence. |

Eleven of the original 22 disagreements (after Task 1's corrected ablation)
have been resolved across Tasks 3, 4, 5, and 8 combined - registry category
(elastic#27, splunk#24, sigma#9, sigma#15), RARITY/tool-selector distinction
(splunk#23), CIM pre-resolution fix (splunk#2, splunk#8), and field-context
gating (splunk#10, splunk#18, sigma#3 - the Signature field isn't a
process-context field either, so the same fix suppressed the same
mechanism there too as a side effect - and sigma#19 in the AST path, only
after a regression it briefly introduced was caught and fixed, see section
2e) - none hand-patched to the specific example; each traces to a named,
principled category or mechanism, several of which (protected-literal
categories, tool-vocabulary field context) generalize well beyond the one
rule that surfaced them.

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
per-corpus kappa moved from 0.505 (before Tasks 3-5) to 0.703 after this
fix (0.798 after Task 8 on top of it - see section 2e) *(0.505/0.703/0.798
here are all kappa under the since-corrected AND/OR combination bug -
Splunk's true final, post-AND/OR-fix figure is also 0.798, unchanged by
that fix, since the text path can't reach the correction either way)* -
the CIM fix specifically, isolated, accounts for 2 of the 9 total rules
fixed across Tasks 3-5, and was the difference between Splunk staying the
weakest corpus by a wide margin and closing to near-parity with Elastic and
SigmaHQ.

### Interpretation, after Tasks 1/3/4/5 (superseded by Task 8, then by the AND/OR fix - see "The AND/OR fix, implemented, and everything re-run" for the true final numbers)

kappa = 0.747 *(kappa under the since-corrected combination bug)*, 83.3%
agreement, aggregate, across all three corpora, each
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
- by LLM label the most durable rule in the corpus - classifies correctly,
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

---

### 2e — Task 8: field context, not name length, was the right axis

Task 4's short-name suppression (<3 characters without executable context)
was verified to have zero measured effect on the 90-rule set - the real
over-scores were LONGER words (`security`, `replace`, `url`) that are
genuine LOLBAS/LOOBins/ATT&CK catalog entries colliding with ordinary field
values that have nothing to do with a process: a Windows EventLog
`Channel=security`, a regex-substitution argument containing `replace`, a
`location` field holding the word `url`. Name length never discriminated
this - **which field the value came from does**.

**Fix**: the tool-vocabulary catalog lookup (`refdata.is_known_tool_name`)
now only runs when the atom's field plausibly carries a process, image,
command-line, or parent-process value - `Image`, `NewProcessName`,
`CommandLine`, `ParentImage`, ECS's `process.name`/`process.command_line`,
and Splunk CIM's `Processes.process`/`Processes.original_file_name`, matched
uniformly by normalizing away case and underscores
(`fragility.field_carries_process_context`). `CMDLET_RE`/`EXE_RE` stay
unconditional - they're pattern-shaped matches (a value that itself looks
like `Invoke-Something` or `foo.exe`), not a word-list lookup, so the
field-context ambiguity that motivates gating the catalog specifically
doesn't apply to them.

**A regression this fix introduced, caught by testing before trusting the
result** (exactly the discipline this project has tried to hold throughout):
`sigma#19` (`Steganography Unzip Hidden Information From Picture File`,
llm=Tool) briefly broke, because it keys on Linux auditd's `a0` field
(EXECVE-record convention for argv[0], i.e. the executable name) - a THIRD
naming convention for "this is the process" this fix's field list hadn't
covered yet (Windows/Sysmon PascalCase and ECS dotted-path were covered;
auditd's `a0`/`exe`/`comm` weren't). Added, and covered by a regression test
(`test_field_context_covers_auditd_execve_a0`) before moving on.

**Kappa delta from this change alone** (Task 8, isolated - measured after
Task 8 by itself, no other changes since the Task 1/3/4/5 baseline of
0.747). **Every number in this table is kappa under the since-corrected
AND/OR combination bug** - Task 8 predates that fix entirely:

| | Kappa | Agreement | Disagreement |
|---|---:|---:|---:|
| Before Task 8 | 0.747 | 83.3% | 16.7% (15/90) |
| **After Task 8** | **0.800** | **86.7%** | **13.3% (12/90)** |

Per-corpus: Elastic unchanged (0.780 - the elastic#16 case below is field-
context-immune by construction, see below); Splunk 0.703 -> **0.798**
(splunk#10 and splunk#18 both resolved outright; splunk#11 changed FROM an
over-score TO a different, still-open disagreement - the spurious `replace`
Tool-match is gone, but the rule's underlying signal still isn't recognized,
a different problem now); SigmaHQ 0.741 -> **0.796** (95% bootstrap CI
tightened to **[0.599, 0.948]**, now excluding "fair" agreement entirely).

**`elastic#16` (`Potential Hex Payload Execution via Command-Line`,
llm=Artifact, v2=Tool) is confirmed NOT fixed by this change, exactly as
anticipated before running it**: the field there genuinely IS `CommandLine`
- a real process-context field - so field-context gating correctly does
NOT suppress whatever is matching there. This is a different, disclosed
mechanism (an incidental cmdlet/tool-pattern match inside a long, obfuscated
command-line literal used to smuggle a hex payload - not a field-context
problem at all) and stays open.

---

## Part 2, external validation — MITRE's Summiting the Pyramid (STP)

Everything in Part 2 above was validated against an LLM-generated
development set (see the disclosure at the top of section 2c). This section
validates against an actual external, human-produced standard measuring the
same construct: MITRE Center for Threat-Informed Defense's **Summiting the
Pyramid** (STP, currently v4.0) - a published methodology for scoring
detection-analytic robustness against adversary evasion, which SigmaHQ has
formally adopted (the `stp` tag is defined in the official Sigma
specification). mechanic did not invent fragility tiering; MITRE formalized
it first, with industry partners, before this project existed.

### Step 1 — coverage survey

**SigmaHQ's own `stp` tag adoption is far too sparse to validate against.**
(This is a single-repo scan for THIS validation step only - see
[`STP_ADOPTION_CENSUS.md`](STP_ADOPTION_CENSUS.md) for the full
multi-repository census with commit-level provenance, exact release dates,
and the precisely-sourced adoption claim this narrower scan should not be
mistaken for.) Scanned every rule directory in the local SigmaHQ clone
(`rules/`,
`rules-emerging-threats/`, `rules-threat-hunting/`, `rules-placeholder/`,
`rules-compliance/`, `rules-dfir/`) - 3,783 files total. **6 carry an `stp`
tag (0.16%).** Per the brief's explicit instruction ("if the count is very
low (<30), say so plainly and stop before the association test"), no
statistics are computed on these 6.

Their git history makes the reliability picture worse than the raw count
alone suggests: **all 6 tags were added in the exact same commit
(`56ac2380`), by the same author (frack113, co-authored with nasbench),
titled "Update tests to pySigma 0.10.9."** The full commit message clarifies
these were added specifically to exercise newly-added pySigma parsing
support for the tag format ("chore: add Summiting the Pyramid v1.0.0
tags"), not as a broad community labeling initiative - and they're tagged
against **STP v1.0.0**, an earlier version of the methodology than the v4.0
being validated against here. Six tags, one commit, one tagging event, tied
to a superseded methodology version: exactly the "one person in one commit"
reliability concern the brief asked to be checked for, confirmed.

**MITRE's own scored-analytics dataset is the real find.** The STP project
publishes `ScoredAnalytics_05062025.csv` - analytics scored by MITRE's own
researchers directly (not by SigmaHQ contributors), most with a permalink to
the EXACT commit of the source rule (SigmaHQ, and a small number of Elastic
and Splunk rules too) and a free-text justification for the score. **The
CSV itself has 92 raw data rows** (see `STP_ADOPTION_CENSUS.md`'s dataset
table, which reports this same, byte-identical file by that raw count); 2
of those 92 are entirely blank spreadsheet-artifact rows, dropped before
any other count in this section - leaving the **90 non-header rows**
referenced everywhere below. Of those 90, 2 more are section-header marker
rows ("Network Analytics Sigma Directory", "Further Research Required")
that name a section rather than an analytic and are also skipped before
classification - leaving **88 actual candidate rows**. Of those 88, **78
successfully resolved to a real rule file at the exact scored commit and
were classified by mechanic's v2** - 72 from the CSV's main sections
("main" + "network"), plus 6 from the "Further Research Required" section
MITRE itself flagged as provisional (analyzed separately below, not pooled
silently into the primary result). The remaining **10 were excluded**,
each for a stated, checked reason (verified directly against
`scratchpad/stp_validation.py`'s own exclusion counter - a prior draft of
this document said "12 rows excluded," which doesn't match the reasons
listed below and was a plain arithmetic slip, corrected here): 4 have no
permalink at all (MITRE-authored correlation-style examples with no
backing rule file to classify); 3 have a literally ambiguous score in the
source CSV (`"1H or 2H?"`, `"1H?"`, `"?H"` - MITRE's own researchers
marking uncertainty); 2 point to a path that no longer exists at the
commit resolved (permalinks pinned to `master` rather than a fixed hash,
where the current HEAD has since moved the file); 1 points to a third-party
repo (`magicsword-io/LOLDrivers`) not locally cloned for this project.
4+3+2+1 = 10, and 78+10 = 88, closing the chain exactly.

**This 78-row, MITRE-scored, externally-produced set is the primary
validation route for this section - not the sparse SigmaHQ tag sample, and
not (per the brief's own fallback instruction) the Uetz-et-al. evadability
construct, since a usable, larger, better-provenance STP sample was found
before that fallback was needed.**

### Step 2 — scale mapping, decided before any agreement figure

Full reasoning and citations in `mechanic/data/STP_MAPPING.md`, written
before this section's numbers were computed. Summary: STP's five analytic-
robustness levels (1 Ephemeral, 2 Adversary-brought tool, 3 Pre-existing
tool, 4 Some technique implementations, 5 Full technique) map onto
mechanic's four tiers with an acknowledged seam - two candidate mappings are
tested for sensitivity, differing only in where STP level 3 lands (Tool,
under the "still tied to a swappable tool" reading; or TTP, under the "more
constrained than adversary-brought" reading STP's own text suggests). The
**primary, headline statistic is the rank correlation computed directly on
the unmapped ordinal scales** (mechanic's 0-3 tier rank vs. STP's 1-5 score)
specifically so the mapping choice - a real researcher degree of freedom -
is not load-bearing for the headline claim.

**A structural discovery, found while reading the methodology, before
computing any agreement number**: STP's documented rule for combining
multiple observables is `AND -> MIN`, `OR -> MAX` (an AND-linked analytic is
only as robust as its weakest linked observable, since the adversary need
only defeat one; an OR-linked analytic is at least as robust as its
strongest, since the adversary must defeat all). **mechanic's `rule_tier` is
`max()` over every positive atom regardless of AND/OR structure** - correct
for OR-linked rules, but the wrong operator for AND-linked ones (the common
case, since a Sigma `selection:` block combines its fields via implicit
AND). This is a genuine, previously invisible divergence from the standard
mechanic is now being checked against - quantified empirically below, not
silently fixed and re-reported as if it had always worked this way.

**Registered prediction, stated before running, not adjusted after seeing
the numbers:**

> mechanic's fragility tier will correlate positively with STP analytic
> robustness (higher tier <-> higher STP score). If there is no positive
> rank correlation, the taxonomy does not align with the established
> industry standard for the same construct, and that must be reported as
> the primary finding regardless of any internal kappa figure.

### Step 3 — validation run

**Headline result, stated plainly per the pre-registered interpretation:
mechanic's current tier, as actually shipped, does NOT correlate with STP's
analytic robustness score.**

| | n | Kendall's tau-b | Spearman's rho |
|---|---:|---:|---:|
| main + network (primary) | 72 | **0.032** (p=0.767) | 0.035 (p=0.770) |
| + Further Research Required (secondary) | 78 | -0.050 (p=0.630) | -0.055 (p=0.634) |

Both are statistically indistinguishable from zero. Per the prediction
registered above: **this is the "no positive rank correlation" outcome**,
and per the brief's own fixed-in-advance interpretation, it is reported as
the primary finding, not buried under the internal kappa figures below.

Mapped (quadratic-weighted) kappa, both sensitivity mappings, confirms the
same conclusion from a different angle - low regardless of which reasonable
mapping is used, so the near-zero rank correlation isn't an artifact of one
bad mapping choice:

| Mapping | n | Unweighted kappa | Quadratic-weighted kappa |
|---|---:|---:|---:|
| A (STP-3 -> Tool) | 72 | 0.042 | 0.074 |
| B (STP-3 -> TTP) | 72 | 0.004 | 0.026 |

Full contingency table (STP analytic score x mechanic tier, main+network,
n=72 - note mechanic assigned zero rules to IOC in this sample, and STP
assigned zero analytics to score 5):

| STP score | IOC | Artifact | Tool | TTP |
|---:|---:|---:|---:|---:|
| 1 | 0 | 21 | 13 | 2 |
| 2 | 0 | 11 | 7 | 2 |
| 3 | 0 | 7 | 5 | 0 |
| 4 | 0 | 2 | 1 | 1 |
| 5 | 0 | 0 | 0 | 0 |

**Investigating the divergence - is it principled, or an error? It is an
error, and a specific, previously-undiscovered, fixable one.** The STP
mapping exercise (Step 2) surfaced STP's own combination rule (AND -> MIN,
OR -> MAX) before any correlation was computed. Testing it directly: for
every Sigma-only row in this sample (n=70, real AST available), recomputed
each rule's tier using that exact rule - walking the AST, `MIN` across
AND-linked children, `MAX` across OR-linked children (and SELECTOR
quantifiers: "1 of"/"any" as OR, "all of" as AND), filters excluded from
the computation entirely (matching STP's own stated rule that filters don't
affect the score - independently corroborating mechanic's existing
negation-handling design, per the brief's own background note) - instead of
mechanic's current `max()` over every positive atom regardless of AND/OR
structure:

| Scoring method | Kendall's tau-b vs. MITRE score | p-value |
|---|---:|---:|
| mechanic, current (`max()` over all atoms) | **-0.009** | 0.934 |
| STP-aware diagnostic (`AND -> MIN`, `OR -> MAX`) | **+0.300** | **0.0082** |

**This is not a marginal difference - it is the difference between no
signal and a statistically significant positive correlation, on the same
70 rules, with the only change being which operator combines AND-linked
atoms.** 22 of the 70 rows change tier under the corrected logic, and the
pattern is completely one-directional: every single change moves DOWN
(mechanic's current over-scoring is corrected toward the true, weakest-link
value), never up. Two representative cases: `Windows Binaries Write
Suspicious Extensions` (MITRE-scored 1K/Ephemeral, "Depends on the target
file names that can easily be changed") - mechanic's current `max()` finds
a higher-tier atom elsewhere in the same AND-linked selection and reports
Tool; the corrected `MIN` logic correctly reports Artifact, because STP's
own reasoning is that the adversary only has to evade the WEAKEST AND-linked
part, so the filename-dependent condition (the weak link) is what actually
determines robustness, not whatever the strongest co-occurring atom happens
to be. `Direct Syscall of NtOpenProcess` (MITRE 2U) shows the same pattern:
mechanic's `max()` finds a syscall-tier atom and reports TTP; STP-aware
`MIN` correctly reports Artifact, matching MITRE's actual score far more
closely.

**Conclusion: mechanic's core `rule_tier = max(atoms)` design - unchanged
since v1, never revisited across the entire Task 1-8 sequence of fixes
before this validation - is the wrong operator for the common AND-linked
case, and this is very plausibly the single largest reason the taxonomy
failed to correlate with the external standard it claims to automate.**
**UPDATE - fixed, not deferred.** This was originally written up as a
diagnostic-only finding, flagged as the highest-priority next action ahead
of Part 3, on the reasoning that fixing it would invalidate every kappa
figure reported earlier in this document and require re-running the entire
Task 1-8 sequence. On review, the decision was made to fix it immediately
and re-run everything rather than defer - see the dedicated "The AND/OR
fix, implemented, and everything re-run" section immediately following this
one for the real production fix (`fragility._combine_ast_tier`), a second,
immediately-necessary fix it surfaced (data-source-selector fields like
AWS's `eventSource` were being wrongly included in the AND=MIN combination),
and the full, honest before/after numbers - including a large drop in
agreement with the LLM development set that turned out to be its own
finding, not a sign the fix was wrong. The numbers in the table immediately
above (tau=0.032, kappa=0.074) are the PRE-FIX state, kept as the true
historical record of what was found and why it triggered a fix; they are
superseded by the post-fix numbers in the next section.

**Event robustness (mechanic has no equivalent axis - reported as a gap per
the brief).** A weak, non-significant positive relationship: Kendall's tau
= 0.149 (p=0.271, n=50) between STP's A/U/K event-robustness ordering and
mechanic's tier. The network-log subset carries an apparent fourth
category, `H`, not documented on the tag-format page fetched for this
project (inferred, not confirmed, to relate to HTTP/header-visible network
telemetry - noted honestly as unverified rather than guessed at further).
mechanic's atom classification incidentally correlates a little with
telemetry-tamper-resistance because some of the same fields that indicate
kernel-level telemetry (e.g. `auditd.data.syscall`) also happen to trigger
mechanic's EventID/syscall structural handling - but this is coincidental
overlap, not a real second axis. **A dedicated event-robustness dimension,
analogous to STP's, is genuine missing scope** worth adding as future work,
not something mechanic currently captures under a different name.

### Step 4 — repositioning the contribution

**STP is prior art for the taxonomy itself, and is cited as such from here
forward.** mechanic did not invent fragility tiering. MITRE's Center for
Threat-Informed Defense formalized it first, with industry partners,
published as Summiting the Pyramid - a rigorous, versioned (currently v4.0),
publicly documented methodology, now formally adopted into the Sigma
specification itself via the `stp` tag. Every place this document or the
code previously implied mechanic's IOC/Artifact/Tool/TTP scheme was an
original taxonomy, read it instead as: *an independently-arrived-at
approximation of a scheme MITRE had already published* - the schtasks
worked example in STP's own documentation (renaming `schtasks.exe` defeats
the Image-based observable; the commandline argument requires a source-code
change to defeat, so it scores higher; the analytic is only as robust as
its weakest linked part) describes exactly mechanic's Tool-vs-TTP boundary,
arrived at separately.

**But STP is a manual methodology - a human expert reads and scores each
analytic individually - and that is almost certainly why SigmaHQ's own tag
coverage is 0.16% (Step 1).** Manual expert scoring does not scale to a
corpus of thousands of rules across multiple vendors; that scarcity is
itself evidence for the problem mechanic exists to solve, not a reason to
abandon the comparison.

**Revised contribution statement, replacing any earlier framing that
implied a competing or original taxonomy:**

> Summiting the Pyramid defines how to score detection-analytic robustness
> but requires manual expert scoring of each analytic. mechanic automates
> STP-style scoring at corpus scale, validated against the human-scored
> subset, and combines it with behavioral staleness to prioritize which
> rules need attention.

**This is a more defensible claim than the pre-STP framing, made honestly
weaker in one specific respect at the time this section was first
written, since corrected**: Step 3's first pass showed the automation, as
then implemented, did not track the standard at all (tau ~0), with a
specific, evidenced cause identified (the AND/OR combination-rule error).
That fix was then implemented and everything re-run rather than left as
aspirational future work - see "The AND/OR fix, implemented, and everything
re-run" - and the corrected implementation now DOES correlate significantly
with STP (tau=0.361, p=0.001). The contribution statement above is
therefore earned, not aspirational, as of the post-fix numbers - with the
separate, still-open honest caveat (same section) that fixing this
combination-rule bug also revealed additional atom-classification gaps not
yet addressed, and a corresponding drop in agreement with the LLM
development set that is itself a disclosed, investigated finding, not a
sign the fix was wrong.

**Prior art, STP added alongside the existing comparisons**: sigmalint
(syntax/style linting, not fragility), EvoSIEM and Uetz et al. (evasion
generation/testing - a different construct, measuring whether a SPECIFIC
evasion defeats a rule, not scoring the rule's general robustness), GRIDAI
(automated repair, downstream of triage), ARMS (mutation-based testing,
the same AST-conversion idea Stage 1 cited independently), RuleGenie (rule
generation). STP is the only one of these that scores the exact same
construct (analytic robustness against evasion) mechanic targets, and the
only one with a published, versioned, industry-adopted methodology behind
it - it belongs in a category of its own in this list, not alongside the
others as a peer, and README.md's prior-art section should reflect that
distinction, not just append STP to the end of an undifferentiated list.

---

## The AND/OR fix, implemented, and everything re-run

The STP validation above found a real, previously undiscovered bug -
`rule_tier` used `max()` over every atom regardless of AND/OR structure,
where STP's own methodology (and correct logic) says AND-linked atoms
combine via `MIN`. On being asked to fix it and re-run everything rather
than leave it as documented-but-unfixed future work, the following happened,
in order - reported in full, including the parts that made an already-shipped
number look worse, not just the parts that improved.

**The fix**: `fragility._combine_ast_tier` now walks the AST directly -
`AND -> MIN(children)`, `OR -> MAX(children)`, `SELECTOR` quantifier
`"1"`/`"any"` -> MAX (OR semantics) else MIN (AND-like), filters and negated
leaves excluded from the walk entirely (returning `None`, not folded in at
a low value - critical, since including them at a low value would drag an
AND's MIN down for the wrong reason). Multiple `conditions` roots (rare) are
each walked independently and combined via MAX across roots. A
`combine_mode="flat_max"` parameter preserves the old behavior for
before/after comparison only - never the default. 12 new tests, including
the exact AND/OR/SELECTOR-quantifier cases and an explicit reproduction of
the old buggy behavior under `combine_mode="flat_max"`.

**A second, immediately necessary fix, found within minutes of running the
first one for real**: the very first production re-run against the 90-rule
LLM development set showed SigmaHQ's kappa collapsing from 0.796 to 0.188 -
19 of 30 rules flipped, almost all cloud-audit rules. Traced to a specific,
confirmed mechanism before accepting it as "revealed label bias": AWS
CloudTrail's `eventSource` field (e.g. `ec2.amazonaws.com`) was AND-linked
with the substantive, protected `eventName` field, and the new MIN logic
correctly-by-the-letter but wrongly-in-substance dragged the whole rule down
to `eventSource`'s generic Artifact-tier classification. `eventSource` is a
DATA-SOURCE IDENTIFIER - which AWS service emitted the event - not an
independently adversary-evadable observable, exactly the same category
EventID/syscall already excluded from the combination for the same reason.
Generalized `_is_eventid_or_syscall_field` (kept its name for continuity)
to cover this broader "data-source selector" category: `eventSource`,
`event.provider` (Elastic's equivalent), `data_stream.dataset` (ECS),
`sourcetype` (Splunk) - added on the same justification as EventID/syscall
already had, not because this one rule needed it. A new regression test
(`test_data_source_selector_excluded_from_and_combination`) locks this in.
Since `text_fragility.py` imports the same function, this fix applied to
Elastic/Splunk automatically.

### Re-run 1: STP validation (the metric that matters most) - a real win

| | n | Kendall's tau-b | Spearman's rho |
|---|---:|---:|---:|
| Before either fix | 72 | 0.032 (p=0.767) | 0.035 (p=0.770) |
| **After both fixes** | 72 | **0.361 (p=0.0010)** | **0.392 (p=0.0007)** |

This is the outcome the pre-registered interpretation called the strongest
possible validation branch. A moderate, HIGHLY statistically significant
positive rank correlation against MITRE's own human-expert-scored analytics
- not "weak or no correlation" anymore. Mapped quadratic-weighted kappa
moved from 0.074 to **0.316** (Mapping A) alongside it. Full updated
contingency table and disagreement list are in the Step 3 section above (now
current); event-robustness correlation remains near-zero (tau=0.010,
p=0.944, n=50) - unchanged, since mechanic still has no equivalent axis at
all, as already disclosed.

### Re-run 2: the 90-rule LLM development set - kappa dropped, and that itself is a finding

| | Aggregate (n=90) | Sigma-only (n=30) | Elastic (n=30) | Splunk (n=30) |
|---|---:|---:|---:|---:|
| Before either fix (Task 8 final) | 0.800 | 0.796 | 0.780 | 0.798 |
| **After both fixes** | **0.615** | **0.298** | 0.780 (unchanged) | 0.798 (unchanged) |

Elastic and Splunk are exactly unchanged (text_fragility.py has no AST to
apply AND/OR structure to - the fix is a no-op there beyond the shared
data-source-selector list). **SigmaHQ collapsed from 0.796 to 0.298** - the
95% bootstrap CI ([0.132, 0.485]) doesn't overlap the old point estimate at
all. Direction of disagreement flipped hard: 23 under-scores vs. 1
over-score (combined), where the pre-fix state was closer to balanced.

**Investigated rather than accepted at face value, per this project's own
standing rule.** Spot-checked several of the 16 new SigmaHQ disagreements
individually (not just the two that led to the `eventSource` fix). Example:
`Linux Setgid Capability Set on a Binary via Setcap Utility` (LLM label:
Tool) - `Image|endswith: '/setcap'` (Tool, correctly) AND-linked with
`CommandLine|contains: 'cap_setgid'` (classified Artifact - a generic
literal, by mechanic's current lists). Under the corrected MIN logic this
now scores Artifact overall. Is `cap_setgid` actually a weak, freely
renamable link, the way STP's own logic assumes? Arguably not - it's a
POSIX capability NAME defined by the Linux kernel's own `capabilities(7)`
interface, not an adversary-chosen string, which would argue for treating it
as a protected literal mechanic doesn't currently recognize - a **new,
previously-invisible atom-classification gap**, not a flaw in the AND/OR
logic itself.

**The honest conclusion, stated directly**: the pre-fix flat-max design was
partly masking real atom-classification gaps. When any ONE atom in an
AND-linked group scored highly, the whole rule inherited that score
regardless of whether the OTHER AND-linked atoms were themselves
under-classified - so kappa against the LLM set looked better than the
classifier's true atom-level precision actually was. The corrected MIN logic
removes that masking effect and is, by the external STP measure, more
correct - but it also means mechanic's current atom/protected-literal
coverage has more gaps than previously visible (POSIX capability names being
one concretely identified example; likely not the only one).

**Per this project's own explicit, standing instruction, these newly-exposed
atom gaps are NOT being chased and patched against this 90-rule set right
now** - "do not tune the classifier against the 90-rule set until kappa
improves... if tuning is needed, hand-label a separate development sample
and keep the 90 as held-out" applies exactly here, and continuing to
whack-a-mole fix individual atoms this specific investigation happened to
surface (POSIX capabilities, and whatever else a closer look at the
remaining 15 disagreements would find) is precisely the anti-pattern that
instruction exists to prevent. They are logged here as a known, disclosed,
NOT-YET-ADDRESSED body of work for a future round using a fresh, held-out
sample - not silently dropped.

**Which number is "the result" now, stated plainly**: the STP correlation
(external, real, now significant) is the number that validates the
taxonomy and the classifier's core logic. The LLM-set kappa (internal,
self-generated, now shown to have been partly inflated by a masking
artifact in the OLD buggy combination logic) is no longer the headline
figure it was in earlier sections of this document - those earlier 0.747/
0.800 numbers should be read as "kappa under the since-corrected combination
bug," not as the current, true state of the classifier's agreement with the
development set.

---

## Part 3 (pre-work) — the correlation experiment

Part 1 produced this project's headline finding: roughly a third of
Elastic's and Splunk's rules have never had their detection logic revised
since creation, despite raw staleness rating those two corpora the
best-maintained in the study. That finding has an obvious counterargument
with no answer yet: *a rule that was never revised might simply have been
correct the first time.* Part 3's entire premise - that staleness and
fragility should be combined into one priority score - is currently an
assumption. It is testable, because both signals now exist on the same
rules (Part 1's behavioral-commit data + Part 2's fragility tiers).

**Registered prediction, stated before running, not adjusted after seeing
the numbers:**

> Never-behaviorally-revised rules will skew toward the fragile tiers
> (IOC/Artifact/Tool) relative to revised rules. Expected direction:
> positive association. If there is no association, or the association
> runs the other way, Part 3's premise that these two signals should be
> combined is unsupported and the ranking design must change.

Design: contingency table (never-revised vs. revised, by tier) with
chi-square and Cramer's V; the same collapsed into a 2x2 (fragile vs. TTP)
with Fisher's exact for robustness against small expected cell counts;
Spearman correlation between effective days-since-behavioral-change
(days since last behavioral commit, or since creation for never-revised
rules) and tier rank, to check for a gradient a binary split might hide;
run on both the full corpora (automated tiers - good for population-level
statistics, not per-rule verdicts) and the 90-rule LLM-labelled development
set (small n, and - per the disclosure above - not human ground truth
either; still useful here as a second, independently-sampled check, with
any disagreement between the two populations reported rather than resolved
by fiat); and an age control (rule creation date is
the obvious confounder - older rules have had more opportunity to be
revised), via an age-stratified Cochran-Mantel-Haenszel test and an
age-partialled Spearman correlation.

**Interpretation, fixed in advance:**
- Association present and survives age control: the two signals validate
  each other and Part 3's combined ranking rests on evidence.
- No association: reported plainly, not fatal - both signals stay
  individually useful, but the ranking presents them as independent axes
  rather than a combined score.
- Association disappears once age is controlled: reported as the finding -
  raw age is doing the work, not maintenance behavior.

### Task 7 results

Run via `scratchpad/part3_correlation_gather.py` (git-history mining, once
per repo) + `scratchpad/part3_correlation_stats.py` (the pre-registered
design above, executed exactly as written - no test, band, or prediction
was adjusted after seeing these numbers).

**Splunk is not included in this run.** Its git-history mining is blocked
by a reproducible GitPython/Windows threading deadlock (confirmed via three
separate `py-spy dump` stack traces; see the practical-obstacles section).
A subprocess-based (`git diff-tree`) mitigation was benchmarked as viable
(all 28,249 commits diffed in 1,073s) but its deployment is deferred to
after Part 3, per explicit instruction, so as not to block this result any
further. Separately, Splunk's fragility tiers are the least trustworthy of
the three corpora regardless - text-only, no AST, and its kappa was
*exactly* unchanged by the AND/OR combination fix because the correction
cannot reach a path with no parse tree to walk - so its absence here does
not weaken this experiment; including it would have imported the least
validated tier signal into the run that decides Part 3's design. Splunk
should be added as a confirmatory check once mining is unblocked, not
treated as a missing requirement of this result.

Sample: 5,086 mined commit-facts-derived records (SigmaHQ 3,144, Elastic
1,942). After dropping unscoreable/insufficient-information tiers and rows
missing an age or effective-days value: **SigmaHQ n=3,141** (3 excluded: 2
unscoreable, 1 missing creation date), **Elastic n=1,830** (112 excluded,
all unscoreable), **combined n=4,971**. The 90-rule LLM-labelled
development set restricted to sigma+elastic (splunk excluded from this
round) matched all **60/60** rows against the full corpus.

| | n | [1] chi2 (4-tier) | Cramer's V | [2] Fisher's exact (2x2, fragile vs TTP) | [3] Spearman rho (days vs tier rank) | [5a] age-stratified CMH | [5b] age-partialled Spearman |
|---|---:|---|---:|---|---|---|---|
| **SigmaHQ** (primary - externally validated tiers) | 3,141 | p=0.0215 | **0.056** (negligible) | OR=1.43, p=0.070 (n.s.) | rho=+0.037, p=0.041 (**wrong sign** vs. prediction) | p=0.152 (n.s.) | rho=0.007, p=0.685 |
| **Elastic** (secondary - text path, tiers not externally validated) | 1,830 | p=2.99e-16 | **0.203** (real, moderate) | OR=0.51, p=6.3e-10 (**reversed** vs. prediction) | rho=+0.001, p=0.964 (no gradient) | p=0.019 (survives, still reversed) | rho=0.029, p=0.214 |
| Combined (pooling artifact - see below, not a headline number) | 4,971 | p=6.5e-14 | 0.114 | OR=0.82, p=0.023 | rho=-0.276, p=1.6e-87 | p=0.017 | rho=-0.255, p=0 |
| LLM dev-set (sigma+elastic, human/LLM tiers) | 60 | p=0.114 (n.s.) | 0.315 | OR=0.35, p=0.067 (n.s., reversed direction) | rho=-0.267, p=0.039 | p=0.441 (n.s.) | rho=-0.116, p=0.381 |
| Splunk | - | **PENDING** - blocked by the GitPython deadlock above | | | | | |

Full numeric output: `scratchpad/part3_correlation_stats_output.txt`
(generated by `scratchpad/part3_correlation_stats.py`, reproducible from
`scratchpad/part3_correlation_records.pkl`).

**Reading the two primary populations, per the interpretation fixed in
advance - and reading the SIGN, not just the p-value, since a prediction
about direction was registered, not just "some association":**

- **SigmaHQ**: the 4-tier chi-square is nominally significant (p=0.022) at
  n=3,141, but Cramer's V=0.056 is a negligible effect size - the kind of
  result that becomes "significant" from sample size alone, not from a
  meaningful relationship (the project has already been burned once by
  treating a p-value as if it were the finding; this is exactly the trap
  the "green CI is a dangerous green" lesson exists to guard against). The
  2x2 collapse is not even significant (p=0.070), both groups sit at a
  ceiling (95-97% fragile - SigmaHQ has very few TTP-tier rules overall, so
  there is almost no room for a real difference to show up). The one
  significant continuous measure (Spearman rho=+0.037, p=0.041) has the
  **wrong sign** - the prediction was negative (more days since revision ->
  more fragile / lower tier rank). Once age is partialled out, this
  collapses to essentially zero (partial rho=0.007, p=0.685). **Conclusion
  for SigmaHQ: no association survives that would justify combining these
  signals**, and what little was there before the age control was not even
  in the predicted direction.

- **Elastic**: a real, moderate effect (Cramer's V=0.203, an order of
  magnitude larger than SigmaHQ's) that DOES survive the age-stratified CMH
  test (p=0.019). But it runs **opposite** to the registered prediction:
  never-revised rules are *less* likely to be fragile (57.8%) than revised
  rules (72.9%), not more. The continuous gradient measure shows nothing at
  all (Spearman rho=0.001, p=0.964) and the age-partialled version is not
  significant (p=0.214) - so the categorical ("ever revised or not") and
  continuous ("how many days since") measures of the same underlying
  construct disagree with each other, not just with the prediction. A
  plausible mechanism, stated as a hypothesis and not tested here: a rule
  being revised may be evidence that its fragility already surfaced and got
  fixed (drift encountered and patched), rather than evidence the rule is
  robust - the reverse causal story from the one the registered prediction
  assumed. This is offered as one candidate explanation, not a finding.

- **Combined figures are an aggregation artifact and are not used as a
  result.** SigmaHQ and Elastic have very different baseline tier
  distributions (SigmaHQ sits near a fragile-tier ceiling; Elastic has
  substantial TTP-tier mass) and disagree on direction. Pooling them
  produces a large, highly "significant" Spearman correlation
  (rho=-0.276, p=1.6e-87) driven almost entirely by between-corpus variance,
  not a real within-corpus relationship - a textbook aggregation
  (Simpson's-paradox-shaped) artifact. Reported here for completeness, not
  averaged into the interpretation, per instruction not to average away a
  disagreement between corpora.

- **LLM-labelled development set (n=60, human/LLM tiers, not automated)**:
  underpowered at this size (no test reaches significance except the
  gradient measure, p=0.039, itself not surviving age-partialling,
  p=0.381), but directionally it agrees with Elastic, not with the
  registered prediction, on every test that has a sign.

**Verdict, per the interpretation fixed in advance: branch (b) applies -
independent axes, no combined score.** This is not a marginal call: the one
population with any externally validated tiers (SigmaHQ) shows no
meaningful association at all, and the one population with a real,
age-robust association (Elastic) shows it running in the direction that
would argue AGAINST fusing the signals, not for it. A null result would
have been "insufficient evidence to combine"; this result is closer to
"the one place there's real signal, it points the wrong way" - if anything,
a stronger argument against a combined score than a clean null would have
been. Part 3 (`mechanic triage`/`mechanic explain`, below) presents
staleness and fragility as two separate, side-by-side axes, each retaining
its own explanation and confidence, with no weighted or averaged score
between them.

---

## Part 3 — `mechanic triage` / `mechanic explain`, validation

Implementation: `mechanic/priority.py` (the triage computation, no combined
score - see the verdict above) and the `triage`/`explain` commands in
`mechanic/cli.py`. Design rationale and CLI usage: `README.md`'s "Priority /
triage" section.

**Method**: git history for SigmaHQ, scoped to `rules/` (`subdir="rules"` -
matching every other run in this project), is mined once via
`churn.mine_commits_cached` (`scratchpad/run_triage_validation.py`), then
`mechanic.priority.compute_triage` is run at 5%, 10% (default), and 20%
mechanical thresholds, and at both sort orderings (`tier_first`,
`staleness_first` - see "alternative weightings" below), all sharing that
one mining pass.

**Mining is cached to disk**, not just shared in-process: the first
`compute_triage`/`mine_commits_cached` call against a repo writes
`<repo_root>/.mechanic_cache/mine_commits__<fmt>__<subdir>.pkl` (for this
run: `sigma/.mechanic_cache/mine_commits__sigma__rules.pkl`), keyed to the
repo's `git rev-parse HEAD` at write time. Any later call against an
unchanged repo reuses that file instead of re-mining (printed as
`[mechanic] cache HIT: ... - reusing, no mining performed.`); if the repo
has moved forward, the stored HEAD no longer matches and the cache is
treated as a miss - re-mined and overwritten, never silently served stale.
`mechanic triage --refresh` / `mechanic explain --refresh` force a re-mine
regardless of cache state.

This is the fix for an actual problem hit while producing the numbers
below: an earlier, uncached version of this validation job mined the
WHOLE repository root (no `subdir`, a scoping bug in the validation script
itself, since fixed - see the unscoreable-reasons disclosure below) and
was killed mid-run by the harness's own background-task timeout (its true
mining cost, ~1,902s / ~32 minutes, exceeded the ~10-minute ceiling a single
tool invocation enforces even in background mode); on restart it would have
re-paid that cost from zero. Switched to launching the script as a fully
detached OS process (`nohup ... & disown`, output redirected to a log file,
polled via a separate `Monitor` watch) specifically so a single long-running
mining pass isn't bound by any one tool call's timeout. The correctly-scoped
final run mined **10,653 commit-facts in 942.5s (~15.7 minutes)** - paid
once, then reused (`cache HIT`) by every one of the six threshold/ordering
variants below, each of which only re-pays its own staleness/semantic-diff/
fragility computation (5-12 minutes each - real work, since the mechanical-
threshold choice does change which commits are excluded, which changes
Part 1's organic-touch set that Part 1's semantic diff must reclassify; this
part is not cacheable the same way raw mining is). To reproduce from
scratch, delete the `.mechanic_cache/` directory (or pass `--refresh`)
before re-running.

### Top 20, SigmaHQ, default (10%) threshold, `tier_first` ordering

Run scoped to `rules/` (`--subdir rules`, matching every other run in this
project - an earlier attempt that omitted this picked up `.github/`
workflow YAML, `regression_data/` test fixtures, and `unsupported/` example
rules as if they were real detection rules, caught by inspecting the
unscoreable-reasons breakdown and discarded before it reached this
document). 3,144 rule files discovered, 3,142 scoreable, 2 unscoreable.

| # | file | tier | tier confidence | staleness | age (days) | triage hypotheses |
|---:|---|---|---|---|---:|---|
| 1 | `rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml` | IOC | high | 724d since revision | 767 | likely-repairable |
| 2 | `rules/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml` | Artifact | high | NEVER REVISED | 3336 | likely-needs-telemetry-check, likely-retire |
| 3 | `rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml` | Artifact | high | NEVER REVISED | 3114 | likely-needs-telemetry-check, likely-retire |
| 4 | `rules/network/dns/net_dns_susp_telegram_api.yml` | Artifact | high | NEVER REVISED | 3001 | likely-needs-telemetry-check, likely-retire |
| 5 | `rules/windows/builtin/security/win_security_remote_powershell_session.yml` | Artifact | high | NEVER REVISED | 2495 | likely-needs-telemetry-check, likely-retire |
| 6 | `rules/linux/auditd/path/lnx_auditd_ld_so_preload_mod.yml` | Artifact | high | NEVER REVISED | 2491 | likely-needs-telemetry-check, likely-retire |
| 7 | `rules/windows/process_creation/proc_creation_win_cmd_mklink_shadow_copies_access_symlink.yml` | Artifact | high | NEVER REVISED | 2484 | likely-needs-telemetry-check, likely-retire |
| 8 | `rules/windows/builtin/security/win_security_dpapi_domain_masterkey_backup_attempt.yml` | Artifact | high | NEVER REVISED | 2478 | likely-needs-telemetry-check, likely-retire |
| 9 | `rules/windows/builtin/security/win_security_protected_storage_service_access.yml` | Artifact | high | NEVER REVISED | 2478 | likely-needs-telemetry-check, likely-retire |
| 10 | `rules/windows/builtin/security/win_security_sam_registry_hive_handle_request.yml` | Artifact | high | NEVER REVISED | 2478 | likely-needs-telemetry-check, likely-retire |
| 11 | `rules/windows/builtin/security/win_security_susp_add_domain_trust.yml` | Artifact | high | NEVER REVISED | 2455 | likely-needs-telemetry-check, likely-retire |
| 12 | `rules/windows/process_creation/proc_creation_win_mstsc_rdp_hijack_shadowing.yml` | Artifact | high | NEVER REVISED | 2403 | likely-needs-telemetry-check, likely-retire |
| 13 | `rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml` | Artifact | high | NEVER REVISED | 2398 | likely-needs-telemetry-check, likely-retire |
| 14 | `rules/web/proxy_generic/proxy_pwndrop.yml` | Artifact | high | NEVER REVISED | 2319 | likely-needs-telemetry-check, likely-retire |
| 15 | `rules/linux/auditd/lnx_auditd_susp_c2_commands.yml` | Artifact | high | NEVER REVISED | 2288 | likely-needs-telemetry-check, likely-retire |
| 16 | `rules/windows/builtin/security/win_security_not_allowed_rdp_access.yml` | Artifact | high | NEVER REVISED | 2249 | likely-needs-telemetry-check, likely-retire |
| 17 | `rules/windows/registry/registry_event/registry_event_redmimicry_winnti_reg.yml` | Artifact | high | NEVER REVISED | 2244 | likely-needs-telemetry-check, likely-retire |
| 18 | `rules/windows/registry/registry_event/registry_event_bypass_via_wsreset.yml` | Artifact | high | NEVER REVISED | 2146 | likely-needs-telemetry-check, likely-retire |
| 19 | `rules/windows/process_creation/proc_creation_win_lolbin_susp_sqldumper_activity.yml` | Artifact | high | NEVER REVISED | 2145 | likely-needs-telemetry-check, likely-retire |
| 20 | `rules/windows/registry/registry_event/registry_event_disable_wdigest_credential_guard.yml` | Artifact | high | NEVER REVISED | 2140 | likely-needs-telemetry-check, likely-retire |

Note on rank #1: SigmaHQ has essentially no IOC-tier rules (1 out of 3,142
scoreable - matches Task 7's contingency table above), so `tier_first`
ordering surfaces that single rule, then falls through to Artifact-tier
rules tie-broken by staleness (never-revised, oldest first) for the
remainder of the top 20 - see the full worked explanation of rank #1 below.

**Full `mechanic explain` output for rank #1, verbatim** (regenerated
directly from this run's data against the current code, per the
explanation-quality pass below):

> This rule's detection logic has been behaviorally revised 1 time(s), most
> recently 724 days ago. Its fragility tier is IOC: it matches on a raw
> indicator (a hash, an IP address) that an attacker can change without
> altering their actual behavior at all - the least durable kind of match
> possible. This tier was assigned with high confidence: mechanic fully
> parsed the rule's logic as a structured syntax tree and combined its
> conditions using the AND/OR-aware rule validated against MITRE's
> Summiting the Pyramid methodology. The tier comes from matching on:
> IpAddress='127.0.0.1' (classified IOC); EventID=4624 (classified IOC).
> Given both signals together, this rule matches the untested Stage 3
> hypothesis label(s) 'likely-repairable' - a candidate worth a closer look
> for that reason, not a conclusion about the rule's actual quality. Review
> this - none of the above is a verdict that the rule is broken.

This traces correctly against the raw signal data: the rule AND-links an
`EventID=4624`/`LogonType=3` Kerberos-relay detection with
`IpAddress: 127.0.0.1` - a loopback-address literal that reads as an
example/placeholder value rather than a real adversary-controlled field,
and under STP's own AND=MIN combination rule, one IOC-tier condition
floors the whole AND-linked group to IOC regardless of the other,
higher-tier conditions alongside it. That is a substantively correct,
useful thing for a reviewer to be told, not a debug dump.

**Explanation-quality pass, disclosed**: the first version of this
narrative generator picked the first two atoms in list order to explain
"why," which for this exact rule showed `EventID=4624` and `LogonType=3`
- NEITHER of which is the atom that actually produced the IOC tier
(`IpAddress='127.0.0.1'` is). Caught by reading this rule's real output as
prose before shipping it (per instruction), not by inspection of the code.
Fixed in `RuleSignals.narrative` (`mechanic/priority.py`) to select the
atom(s) whose own tier matches the rule's overall assigned tier - i.e. the
one(s) that actually drove the MIN/MAX combination result - preferring a
real content match over a structural placeholder value (an excluded
EventID/data-source-selector floor) when both are available, and falling
back to an explicitly-hedged "contributing values include (not necessarily
the ones that set the final tier)" phrasing on the rare rule where no atom
matches (a SELECTOR/OR combination this simple filter doesn't fully
reconstruct), rather than silently presenting a wrong or misleading "why."
Locked in by `tests/test_priority.py::test_narrative_is_prose_and_mentions_key_facts`
and a manual re-check of this exact rule's output.

**Confirming the Elastic/Splunk caveat renders on the output itself** (not
only in docs): a synthetic text-path rule fed through the same
`RuleSignals.narrative` property produces, verbatim: *"This tier was
assigned with only medium confidence: mechanic could not build a real
parse tree for this rule's query language, so its logic was approximated
from regex-extracted fragments of text instead. Because of that, this tier
does NOT use the AND/OR combination correction that external validation
(against MITRE's STP methodology) showed to be necessary - the correction
requires a real parse tree to walk, which does not exist for this rule's
language here. Treat this tier as less trustworthy than a Sigma/AST-derived
one."* - a reader cannot get an Elastic/Splunk explanation without passing
through that sentence. Locked in by
`tests/test_priority.py::test_narrative_surfaces_and_or_caveat_for_text_path_tiers`
and `test_narrative_omits_and_or_caveat_for_sigma_ast_path` (the negative
case - confirming Sigma's AST-path explanations do NOT carry a caveat that
doesn't apply to them).

### Bucket counts (triage hypotheses) and unscoreable counts, by threshold

| Threshold | scoreable | unscoreable | likely-repairable | likely-needs-telemetry-check | likely-retire |
|---|---:|---:|---:|---:|---:|
| 5% | 3,142 | 2 | 1,926 | 869 | 239 |
| 10% (default) | 3,142 | 2 | 1,932 | 863 | 235 |
| 20% | 3,142 | 2 | 1,933 | 861 | 234 |

(A rule can carry more than one hypothesis label, so columns do not sum to
`scoreable`.) Both unscoreable rules are the same at every threshold
(threshold only changes which commits count as mechanical, not which rules
parse) - `insufficient information: no positive (non-negated, non-filter)
leaves to classify`, for
`rules/windows/process_creation/proc_creation_win_susp_image_missing.yml`
and
`rules/windows/raw_access_thread/raw_access_thread_susp_disk_access_using_uncommon_tools.yml`
- both genuinely all-negated/filter-only rules the classifier is honest
about not understanding, not a defaulted guess.

### Threshold sensitivity: rank correlation between orderings

There is no combined score to vary a weight on (see the verdict above), so
the analogous sensitivity check is (a) how much `mechanic triage`'s SORT
ORDER shifts as `--mechanical-threshold` moves between 5%, 10%, and 20%,
holding the ordering strategy fixed, and (b) how much it shifts between the
two ordering strategies themselves (`tier_first` vs. `staleness_first` -
the closest analogue to "alternative weighting" once no numeric weight
exists), holding the threshold fixed. Both computed via
`scratchpad/triage_threshold_sensitivity.py` against the full 3,142-rule
scoreable set (Spearman's rho and Kendall's tau, restricted to rules
scoreable under both members of each comparison - all 3,142 are scoreable
at every threshold here, so every comparison uses the full set).

**(a) Threshold sensitivity, ordering held fixed** - very high, as expected
(the mechanical-commit filter changes a small number of borderline
exclusions, not the underlying tier or staleness facts):

| Comparison | n | Spearman rho | Kendall tau |
|---|---:|---:|---:|
| 5% vs 10%, tier_first | 3,142 | 0.9969 | 0.9916 |
| 5% vs 20%, tier_first | 3,142 | 0.9968 | 0.9912 |
| 10% vs 20%, tier_first | 3,142 | 1.0000 | 0.9996 |
| 5% vs 10%, staleness_first | 3,142 | 0.9932 | 0.9867 |
| 5% vs 20%, staleness_first | 3,142 | 0.9921 | 0.9848 |
| 10% vs 20%, staleness_first | 3,142 | 0.9989 | 0.9981 |

**(b) Ordering sensitivity, threshold held fixed - the "alternative
weighting" check:**

| Comparison | n | Spearman rho | Kendall tau |
|---|---:|---:|---:|
| 10%, tier_first vs. staleness_first | 3,142 | 0.6903 | 0.6838 |

**This is the more informative of the two sensitivity checks, and it is
NOT a stability result to wave through**: rho≈0.69 means the two
unweighted sort strategies agree only moderately - WHICH axis leads the
sort changes a meaningful fraction of the ordering, not a rounding
difference. This is fully consistent with, and further confirms, Task 7's
finding: if staleness and fragility were the same underlying signal wearing
two hats, tier-first and staleness-first orderings would nearly coincide
(as the three threshold variants of the SAME ordering do, rho > 0.99
above). They don't - which is exactly what "independent axes, no combined
score" predicts, and is reported here as supporting evidence for that
verdict, not as a weakness of the tool.

### What a user can and cannot conclude from this list

**Can**: see every rule's behavioral staleness and fragility tier side by
side, with full reasoning (contributing atoms, structural detector detail,
confidence, and - for Elastic/Splunk - the explicit AND/OR-correction
caveat) via `mechanic explain`; use the tier axis (SigmaHQ only) with the
confidence that it has been checked against an external, human-scored
standard (STP, tau=0.361); use either axis independently for its own
purpose (staleness to find rules nobody has looked at in years; fragility
to find rules whose durability depends on values an adversary can trivially
change); treat triage-hypothesis labels as places to start looking, not as
answers.

**Cannot**: treat the sort order as a validated ranking of "what to fix
first" - it is a scanning convenience, explicitly disclosed as such in
every CLI output and JSON payload; treat a triage-hypothesis label as a
verdict on an individual rule (a rule can be `likely-retire`-flagged and
still be exactly correct - the label reflects an untested, arbitrary
heuristic combination of two axes, not an inspection of the rule's actual
detection logic); trust Elastic/Splunk tiers at the same confidence as
SigmaHQ's (text-path tiers are capped at medium confidence and were never
run through the AND/OR correction, since there is no parse tree to walk);
assume an unscoreable rule is fine, bad, or anything else - it has no tier
by design, not by omission; extend any of this to Splunk, which is not yet
included pending the mining fix described below.

---

## Practical obstacles (environment-level, not detection-logic findings)

Five environment-level obstacles surfaced while gathering Task 7's and Part
3's data (the first four while mining for Task 7; the fifth while running
Part 3's own validation), each diagnosed with a concrete tool rather than
guessed at, none of which appear to be documented anywhere in published
detection-engineering literature. Recorded here while the diagnosis is
still fresh, since this is exactly the kind of material that evaporates
once a workaround ships and nobody writes down why it was needed.

### 1. Windows Defender real-time scanning as a silent, severe I/O bottleneck

**Symptom**: git-history mining that should be CPU-bound (traversing commits,
computing diffs) instead ran at a tiny fraction of one core's worth of
actual work over long wall-clock stretches - SigmaHQ/Elastic mining showed
roughly 1 minute 32 seconds of accumulated CPU time over 45+ minutes of
wall clock (~3% utilization).

**Diagnosis**: `tasklist //FI "IMAGENAME eq python.exe" //V`'s CPU-time
column, compared against wall-clock elapsed time, made the ratio
unambiguous - this is not "slow code," it's a process spending almost all
of its time blocked, and the timing profile (proportional to total file
I/O volume, not to commit count or diff complexity) pointed at something
intercepting every file read, not the mining logic itself. Windows
Defender's real-time scanning is the standard explanation for exactly this
signature on a repository full of small text files being read repeatedly -
each read incurs a synchronous AV scan before the read call returns.
Confirmed by the fix's effect: after a `Add-MpPreference -ExclusionPath`
exclusion was added (run by the user in an elevated shell - this session
had no admin rights to inspect or add exclusions itself, `Get-MpPreference`
returned an explicit permission refusal when tried), CPU time on the same
kind of job jumped from 1:32 to 10:09 within minutes - close to genuine
CPU-bound throughput.

**Did it corrupt any output?** No - this is a pure throughput problem, not
a correctness one. Every mined fact was still correct; the run was just
extremely slow.

**Mitigation**: a Windows Defender path exclusion on the repository root.
Worth flagging specifically for anyone doing corpus-scale git-history
mining of security detection content on Windows: the content being mined
(rule files, and any repository containing real or synthetic malicious
command lines) is exactly the kind of thing real-time AV scanning is
tuned to scrutinize hardest, making this bottleneck more severe here than
on an equivalent source-code repository.

### 2. A rule file containing its own detection target can itself be quarantined

Closely related to (1), but a distinct risk worth naming on its own: a
Sigma/Elastic/Splunk detection rule's `value:`/`query:`/`search:` fields
routinely contain literal encoded-PowerShell patterns, known malware
command-line fragments, or LOLBAS/GTFOBins invocation strings - the exact
content the rule exists to detect. This makes detection-content
repositories a case where the DATA and the THING BEING DETECTED are
textually identical, unlike almost any other software corpus. Real-time
AV scanning treating a rule file as a hit (not just slow, but
quarantined/deleted mid-scan) was a live risk this project ran with
Defender scanning enabled, before the exclusion above was in place; it was
not observed to have actually happened to a tracked file in this project's
own clones, but the risk is structural, not a one-off - anyone mining a
large enough detection-rule corpus without an AV exclusion should expect
to eventually lose a file to this, not just experience slowness.

### 3. GitPython's `Diffable.diff()` populating identical `a_path`/`b_path` for plain ADDs (a correctness risk, caught before it shipped)

**Symptom, found while building creation-date detection for Part 3's
correlation gathering**: code that used `old_path is None` as a
"this commit added the file" test produced wrong results on some real
commits.

**Diagnosis**: verified empirically against real SigmaHQ commits (not
assumed from documentation) that GitPython's diff objects do not reliably
leave `a_path` (`old_path`) as `None` for a plain single-file ADD in every
code path this project exercises - in at least some circumstances both
`a_path` and `b_path` come back populated with the same value. `old_path is
None` is therefore not a reliable "this is a new file" test on its own;
`change_type == 'ADD'` (the field GitPython/PyDriller compute specifically
for this purpose) is the correct, robust test, and is what this project's
own `_FallbackModifiedFile`/`ModifiedFile` handling relies on instead.

**Did it corrupt any output?** This was caught during development, via
direct testing against real commits, before any creation-date or staleness
figure in this document was computed from the affected code path - it did
not silently ship. Named here specifically because it is exactly the kind
of one-character-condition bug (`is None` vs. checking the explicit
`change_type` field) that would have silently and systematically
undercounted "creation" events without necessarily throwing an exception,
and it would have been very easy to trust GitPython's field semantics at
face value instead of checking them against real data first.

### 4. A reproducible GitPython/Windows threading deadlock in commit-diff computation

**Symptom**: git-history mining of `splunk/security_content` (28,249
commits) hung indefinitely - not slow, genuinely stuck - even after the
Defender exclusion above eliminated the I/O bottleneck for every other
repository in this study.

**Diagnosis**: `py-spy dump --pid <pid>` (installed into the project venv
specifically for this) taken on THREE separate occasions across different
fix attempts showed the identical stack shape each time: the main thread
blocked in `join()` inside GitPython's `handle_process_output`, waiting on
background `pump_stream` threads that read the underlying `git` subprocess's
stdout/stderr and never signal completion, for `c.parents[0].diff(other=c,
paths=None, create_patch=False)` on a single-parent commit. This is a
known-shape deadlock in GitPython's threaded diff-computation path on
Windows, not specific to this project's code, but it recurs across MANY
commits in this particular repository's history, not one rare edge case -
confirmed by re-triggering it on a DIFFERENT commit after each fix attempt.

**A self-inflicted bug found and fixed along the way, disclosed rather than
skipped over**: the first mitigation attempt wrapped each diff call in
`concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(...)` with a
15-second `future.result(timeout=...)`. This looked correct (bounded
timeout, clean fallback) but had a real bug: once the FIRST affected
commit's GitPython call deadlocked, that single worker thread was
permanently occupied forever, so the timeout correctly fired for that one
commit - but every SUBSEQUENT commit's `.submit()` call then queued forever
behind a worker that would never free up, silently converting a bounded
per-commit timeout into an unbounded hang starting from the second affected
commit. Confirmed via a second `py-spy dump` showing exactly this queuing
behavior. **Fixed** by replacing the shared executor with a fresh,
`daemon=True` `threading.Thread` + `queue.Queue(maxsize=1)` per call, so a
stuck commit leaks only its own thread rather than blocking every commit
queued after it (`mechanic/churn.py::_modified_files_no_patch`). All 84
project tests pass with this change; a `git diff-tree` subprocess call is
the fallback used when the timeout fires.

**Current status - deliberately not fully deployed yet**: even with the
per-commit-thread fix, a third `py-spy dump` after restarting the mining
job showed the deadlock recurring on a different commit, confirming the
15-second timeout is paid repeatedly across the run, not once - impractical
at full scale as a fallback-only mitigation. A benchmark
(`scratchpad/profile_splunk_subprocess.py`) measured making the `git
diff-tree` subprocess call the PRIMARY method (skipping GitPython's
`diff()` entirely for single-parent commits, rather than trying it first
and falling back on timeout): **all 28,249 commits diffed in 1,073.1
seconds, with the subprocess calls themselves accounting for 1,054.8s of
that** - a predictable, linear, deadlock-free ~37ms/commit average.
Deploying this as `churn.py`'s primary diffing path (replacing the
timeout-and-fallback approach with a direct subprocess call for every
single-parent commit) is scheduled as follow-up work after Part 3, per
explicit instruction not to let this block the project's core contribution
any further - Task 7's correlation experiment above is fully answerable on
SigmaHQ and Elastic alone (n=3,141 and n=1,830 respectively), and Splunk's
tiers are the corpus's least trustworthy regardless (text-only, no AST,
kappa exactly unchanged by the AND/OR fix), so deferring its inclusion
costs breadth, not validity.

**Did it corrupt any output?** No - every fact produced before the hang was
correct; the failure mode was a hang, not silently wrong data. The
`part3_correlation_records.pkl` pickle's incremental-per-repo save design
meant killing the stuck process never lost SigmaHQ's or Elastic's
already-mined data.

### 5. A background tool call's own timeout applies even when the command is meant to run unattended

**Symptom**: a mining job launched via the agent harness's "run this in the
background" tool option was silently killed (`status: killed`, no error, no
partial-progress explanation) approximately 10 minutes in, twice in a row,
each time before the very first progress line past "mining git history"
had a chance to appear.

**Diagnosis**: the harness's background-execution option still enforces
that tool call's own maximum timeout (10 minutes) as a hard ceiling on the
underlying process's lifetime - "background" changes how output is
delivered (polled later rather than blocking the turn), not whether a
timeout applies. SigmaHQ's real mining cost (~15-30 minutes depending on
scope) exceeds that ceiling, so any single such call was destined to be
killed before completion regardless of how many times it was retried
unchanged - confirmed by the CPU-time trend continuing steadily up to the
kill point both times, with no sign of a hang or error, only cut off at a
consistent ~10-minute mark.

**Did it corrupt any output?** No - each kill kept the work already
committed (nothing, since mining reports its result only at completion),
so this was purely a lost-time (not lost-correctness) problem. It cost two
full ~10-minute cycles before being correctly diagnosed as a tooling
ceiling rather than an application bug.

**Mitigation**: launch the long-running process as a genuinely detached OS
process instead - `nohup <cmd> > log 2>&1 < /dev/null & disown`, which
returns control immediately once the process is launched, decoupling its
lifetime from any single tool call's timeout - and separately watch its log
file for progress/completion via a persistent `Monitor` task (which has its
own, much longer or unbounded timeout budget, and is meant for exactly this
"watch a long job and notify on events" pattern). This combination is what
actually let the mining job run to completion.

