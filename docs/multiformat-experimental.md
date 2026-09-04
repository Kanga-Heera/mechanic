# Elastic/Splunk multiformat fragility: quarantined, not deleted

This document is the counterpart to `docs/core-vs-experiment.md` for a
second quarantined tree: `mechanic/experimental/multiformat/`. It covers
what this is, why it doesn't meet the core's bar, exactly what moved and
why nothing about the core's own validated numbers had to be given up to
draw that line, and the concrete path back to core status.

## What this is

Elastic (EQL/KQL/ES|QL) and Splunk (SPL) rule fragility classification,
approximated over **regex-extracted atoms from free text** - there is no
real parser for either query language anywhere in this codebase, and
building one was out of scope for the work that produced this classifier
(see `mechanic/experimental/multiformat/text_fragility.py`'s own module
docstring, unchanged from when this lived in `mechanic/`). Sigma is the
only rule format this project has a real AST for, via pySigma.

**What's in it, and where:**

| Piece | Module |
|---|---|
| Regex-based atom extraction + tier classification (EQL/KQL/SPL) | `mechanic/experimental/multiformat/text_fragility.py` |
| Splunk CIM/macro resolution (needed before SPL text can be tokenized) | `mechanic/experimental/multiformat/splunk_macros.py` |
| Per-file `FragilitySignal` builders (`classify_elastic_file`/`classify_splunk_file`) | `mechanic/experimental/multiformat/multiformat_fragility.py` |
| Triage composition (`compute_multiformat_triage`) | `mechanic/experimental/multiformat/triage.py` |

These four modules are a straight `git mv` + a small composition layer, not
a rewrite - `text_fragility.py`/`splunk_macros.py` are byte-for-byte the
same logic that used to live directly in `mechanic/`; `multiformat_
fragility.py` is `priority.py`'s old `_elastic_fragility`/`_splunk_
fragility` functions, unchanged; `triage.py` is new, but it's a ~15-line
call into the core's own `priority.build_triage_report` engine with these
functions plugged in - see that module's docstring.

## Why this doesn't meet the core's bar

Sigma's real AST is what the STP-validated structural detectors
(`FIELD_MISMATCH`, `ABSENCE`, `RARITY`, `CORRELATION`) and the AND/OR
combination correction (`AND -> MIN`, `OR -> MAX`, validated against MITRE's
Summiting the Pyramid methodology - RESULTS.md) actually walk. Elastic/
Splunk have neither:

- **Negation is a best-effort heuristic** (`!=` operators, textual `not
  (...)` span-finding), not a real parser's polarity flag.
- **FIELD_MISMATCH is approximated** over a flat atom list, not a tree;
  `ABSENCE`/`RARITY`(Sigma correlation-type)/`CORRELATION` structural
  detectors are not attempted at all for this path - they need real
  tree/aggregation structure this approximation doesn't have (SPL's own
  inline `RARITY` idiom, count/dc_* thresholds, is handled separately, see
  `text_fragility.detect_rarity_spl`).
- **The AND/OR combination correction cannot run** - there is no parse tree
  to walk `MIN`/`MAX` over, so every text-path tier is capped at "medium"
  confidence and carries a non-None `caveat` explicitly saying so (see
  `RuleSignals.narrative`, core, unmodified - it already renders this
  caveat into plain prose whenever one is present).

None of this means the text-path classification is *wrong* or useless -
RESULTS.md's Part 1 (behavioral staleness) and the STP validation below
both find real signal in it. It means it does not clear the bar the CORE
holds itself to, and presenting it as equally validated would be
manufacturing confidence the project's own external validation doesn't
support.

## What did NOT have to move: staleness

Git-driven staleness (`mechanic staleness`, `churn.py`/`semantic_diff.py`)
is unaffected and stays fully in the core, for any format - a commit
either touched a file or it didn't, regardless of what query language the
file contains. `semantic_diff.py`'s medium-confidence YAML/TOML-key
comparison for Elastic/Splunk behavioral staleness (RESULTS.md Part 1: 27.4%
of Elastic's rules, 36.8% of Splunk's, never behaviorally revised) is a
real, disclosed, already-caveated finding that was never dependent on
`text_fragility.py`/`splunk_macros.py` - it stays exactly where it was, at
exactly the confidence level it always had. Only the fragility/tiering/
priority axis (`mechanic triage`/`explain`, and `scan`/`report` since those
use the Sigma-only loader) is scoped to Sigma-only. See
`docs/core-vs-experiment.md`, "The staleness-vs-fragility scoping decision".

## The one number this touches, and how it was handled honestly

The core's headline external-validation figure - Kendall's tau-b = 0.361
(p = 0.0010) against MITRE's STP-scored analytics, `RESULTS.md`'s "The
AND/OR fix, implemented, and everything re-run" - was computed over a
72-row sample. That sample is **not purely Sigma**: 70 SigmaHQ rows, 1
Elastic row, 1 Splunk row (`tests/fixtures/stp_validation_frozen.json`).
Quarantining `text_fragility.py`/`splunk_macros.py` out of the core means
the core can no longer, by itself, reproduce that exact 72-row number -
worth stating plainly rather than quietly re-labeling 0.361 as "the core's
own" figure while it still depends on quarantined code.

Rather than either (a) silently keep claiming 0.361 as the core's number
while it secretly depends on experimental code, or (b) drop the STP
validation claim entirely, the Sigma-only subset was re-derived from the
same frozen fixture, using **only** core code (`mechanic.fragility`,
`mechanic.ast_repr`, `mechanic.loader` - zero import of anything
quarantined):

| | n | Kendall's tau-b | Spearman's rho | Mapped quadratic-weighted kappa |
|---|---:|---:|---:|---:|
| Combined (70 Sigma + 1 Elastic + 1 Splunk) - the original 0.361 figure | 72 | 0.3607 (p=0.0010) | 0.3917 (p=0.0007) | 0.316 |
| **Sigma-only (this re-derivation)** | **70** | **0.3117 (p=0.0052)** | **0.3361 (p=0.0044)** | **0.2821** |

The Sigma-only figure is a real, still-significant, moderate positive
correlation - close to but honestly lower than the combined figure (removing
2 of 72 rows changes it, as it should). This is now the number the core
claims as its own external validation, locked by
`tests/test_validated_numbers_lock.py::test_stp_rank_correlation_sigma_only_locked`
(core-only, no quarantined import). The original combined 72-row number
(0.361) is **not deleted or hidden** - it is real, it did happen, and
RESULTS.md still reports it in full - but it is now explicitly labeled as
the historical, mixed-corpus figure that partly depended on the
now-quarantined text-path classifier, re-locked in
`tests/experimental/test_multiformat_validated_numbers_lock.py` instead of
the core's own lock file. Nothing was recomputed to make either number look
better; both are exactly what the same frozen fixture and the same
(unchanged) classification code produce.

This is disclosed here in the interest of the project's own standing rule
against inventing certainty - the task that produced this quarantine
assumed the core's STP validation was purely Sigma already; it was not
quite (70 of 72 rows were), and that gap is now closed with a real
number, not papered over with a relabeling.

## The path back to core status

A real KQL parser exists (`kibana-ql`, used by Kibana itself) that could
replace `text_fragility.py`'s regex-based Elastic atom extraction with a
real AST, at which point Elastic's structural detectors and AND/OR
combination could run for real and Elastic could be re-validated against
STP the same way Sigma was, on its own merits - not assumed to transfer.
EQL and SPL are harder (no equivalently mature, permissively-licensed
Python parser identified as of this writing) and stay unparsed for now.
This is named here as the concrete, deliberate scoping decision it is, not
left as a vague "future work" gesture.

## Using this directly

There is no CLI/console-script entry point for this package on purpose -
see `mechanic/experimental/multiformat/triage.py`'s module docstring for
why. Call it from Python:

```python
from pathlib import Path
from mechanic.experimental.multiformat.triage import compute_multiformat_triage

report = compute_multiformat_triage(
    Path("thirdparty/elastic-detection-rules"), "elastic_toml", subdir="rules"
)
print(report.to_dict()["summary"])
```

Every `FragilitySignal` this produces carries `and_or_corrected=False` and a
non-None `caveat` - `RuleSignals.narrative`/`.to_dict()` (core, unmodified)
already render that distinction into the same JSON/prose shape `mechanic
triage`'s own output uses.
