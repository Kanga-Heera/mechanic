# CORE vs. EXPERIMENT: the boundary, in code and in words

`mechanic` is two things sharing one git repository, and they are not held
to the same bar. This document defines the line between them, why it's
drawn where it is, and how it's enforced — not just claimed.

## The CORE (the reactor)

**What it is**: detection-rule maintenance triage. Given a rule repository,
tell an engineer which rules are structurally fragile (easy for an
adversary to evade with a trivial rename/reorder/substitution) and which
are behaviorally stale (nobody has organically revised them), so they know
what to look at first. This is the gap the project exists to fill — rule
triage, not alert triage, and not manual/academic evadability scoring on
small samples. Nothing else does this at repository scale.

**What's in it**, and where:

| Piece | Module(s) |
|---|---|
| Fault-isolated rule loader | `mechanic/loader.py`, `mechanic/categories.py` |
| Format-agnostic file discovery | `mechanic/discovery.py` |
| Git-driven staleness engine | `mechanic/churn.py` |
| Behavioral (semantic) diff | `mechanic/semantic_diff.py` |
| Rule AST | `mechanic/ast_repr.py` |
| Structural fragility classifier (Sigma-only) | `mechanic/fragility.py`, `mechanic/structural_detectors.py`, `mechanic/protected_literals.py`, `mechanic/refdata.py`, `mechanic/legacy_v1.py` (ablation baseline only) |
| Review-priority triage | `mechanic/priority.py` |
| CLI | `mechanic/cli.py` — `scan`, `staleness`, `ast`, `report`, `triage`, `explain` |

**Validation status**: the fragility taxonomy is externally validated
against MITRE Center for Threat-Informed Defense's Summiting the Pyramid
(STP) — Kendall's tau-b 0.3117, p = 0.0052, on the Sigma-only subset of the
72-row STP fixture (n=70; see "The staleness-vs-fragility scoping decision"
below for why this is now the core's own number, and
`docs/multiformat-experimental.md` for its relationship to the historical
combined 0.361 figure). Staleness reproduces a prior investigation's cited
figures across five real repositories, any format. This is the project's
calibrated, trusted instrument — see Part 4 below for how these numbers are
pinned against silent drift.

## The staleness-vs-fragility scoping decision

The core is **Sigma-only for fragility, tiering, and priority**
(`mechanic scan`/`triage`/`explain`/`report`) but stays **format-agnostic
for staleness** (`mechanic staleness`, and the staleness half of `report`).
This split, not an all-or-nothing "core is Sigma-only" rule, is deliberate:

- **Staleness is git history, and git history is real regardless of rule
  format.** A commit either touched a file or it didn't; `churn.py`'s
  mechanical-commit filtering and organic-commit math don't need to
  understand the rule's query language at all. `semantic_diff.py`'s
  behavioral staleness goes one step further (does the DETECTION LOGIC, not
  just the file, look different) via a format-aware but still
  parser-free YAML/TOML-key comparison for Elastic/Splunk, medium
  confidence, already disclosed as such in RESULTS.md Part 1 (27.4% of
  Elastic's rules, 36.8% of Splunk's, never behaviorally revised - the
  project's own headline finding). None of this depends on the
  quarantined multiformat package.
- **Fragility/tiering/priority need a real parse tree to earn the core's
  validation bar.** The STP-validated structural detectors and the
  AND/OR combination correction (`AND -> MIN`, `OR -> MAX`) walk Sigma's
  real AST - there is no equivalent for Elastic (EQL/KQL/ES|QL) or Splunk
  (SPL) anywhere in this codebase, only a regex-based approximation
  (`mechanic/experimental/multiformat/text_fragility.py`) capped at
  "medium" confidence and explicitly caveated per rule. Shipping that as
  core, alongside output that IS AST-validated, would present two
  different confidence levels as one uniform product.

Concretely: `mechanic scan`/`triage`/`explain`/`report` accept only
`--fmt sigma` (enforced at the CLI's own argument-parsing level - see
`mechanic/cli.py`'s `_SIGMA_ONLY_FMT_CHOICE`); `compute_triage` raises
`priority.UnsupportedFormatError` with a clear message
(`SIGMA_ONLY_FRAGILITY_MESSAGE`) if ever reached with anything else.
`mechanic staleness` keeps the full format registry (`sigma`,
`elastic_toml`, `splunk_yaml`, `yaml_generic`). See
`docs/multiformat-experimental.md` for the quarantined Elastic/Splunk
fragility work itself, and the GUI's Format selector (Sigma-only now) in
`mechanic/gui/static/index.html`.

## The EXPERIMENT (quarantined)

**What it is**: Stage 3's question of whether a fragile rule can be
*repaired* automatically, with the fix proven correct by a real detection
engine rather than asserted by an LLM. It was run in three gated phases
(harness+gate, deterministic evasion transformer, LLM repair generator)
and produced an honest, disclosed result: **3.6% acceptance (1 of 28
sampled rules)**, independence-audited so the number isn't self-graded.
That result is worth keeping — it's a real, honestly-measured finding —
but it is not the core product, and the core's reliability story must
never depend on it.

**What's in it**, and where:

| Piece | Module(s) |
|---|---|
| RSigma verification harness | `mechanic/verify.py` |
| Four-condition acceptance gate | `mechanic/gate.py` |
| Deterministic evasion transformer | `mechanic/evasion.py` |
| Synthetic benign-event baseline | `mechanic/synthetic_benign.py` |
| Model-agnostic LLM client | `mechanic/llm_client.py` |
| LLM repair generator | `mechanic/repair_generator.py` |
| Gate-enforced outcome classifier | `mechanic/repair_outcome.py` |
| CLI | `mechanic/cli_repair.py` — `mechanic-repair verify` (separate console script, separate click group) |
| Batch runner / retry tooling | `scripts/run_phase3_acceptance.py`, `scripts/_generate_repair_worker.py`, `scripts/retry_until_complete.ps1`, `scripts/_clear_run_errors.py` |

**Requirements the CORE must never inherit**: a pinned RSigma binary on
PATH (or `$MECHANIC_RSIGMA_BIN`), network access, and — for repair
*generation* specifically — a live `GROQ_API_KEY`. None of these are ever
required to run `scan`, `staleness`, `triage`, or `explain`.

**A second, separate quarantine**: Elastic (EQL/KQL/ES|QL)/Splunk (SPL)
fragility classification — see `docs/multiformat-experimental.md` for the
full writeup (what it is, exactly why it doesn't meet the core's
STP-validated bar, and the concrete path back via a real KQL parser).
Unlike the repair pipeline, this code was moved into its own subpackage
(`mechanic/experimental/multiformat/`) rather than left flat in
`mechanic/` — both are equally quarantined; the different layout is just
because this one arrived later, after the package already existed as a
pattern to follow.

| Piece | Module(s) |
|---|---|
| Regex-based atom extraction + tier classification (EQL/KQL/SPL) | `mechanic/experimental/multiformat/text_fragility.py` |
| Splunk CIM/macro resolution | `mechanic/experimental/multiformat/splunk_macros.py` |
| Per-file fragility builders (`classify_elastic_file`/`classify_splunk_file`) | `mechanic/experimental/multiformat/multiformat_fragility.py` |
| Triage composition (`compute_multiformat_triage`) | `mechanic/experimental/multiformat/triage.py` |

No CLI/console-script for this one — see `triage.py`'s module docstring for
why a polished CLI surface would itself misrepresent the quarantine. Call
`compute_multiformat_triage` directly from Python instead.

## The enforcement, not just the claim

A stated boundary that nothing checks is not a boundary. Three mechanisms
enforce this one (both quarantines, the repair pipeline and multiformat
fragility, are covered by the same three mechanisms below — `EXPERIMENT_MODULES`
in `tests/test_core_isolation.py` lists both):

1. **Import graph.** `mechanic/cli.py` (the core CLI) contains zero
   imports of `verify`, `gate`, `evasion`, `synthetic_benign`,
   `llm_client`, `repair_generator`, `repair_outcome`, or anything under
   `mechanic.experimental.multiformat` — not lazy imports inside function
   bodies, no imports at all. The only CLI module that imports
   `mechanic.verify` is `mechanic/cli_repair.py`, a separate file
   registered as a separate console script (`mechanic-repair`); nothing
   registers a console script for `mechanic.experimental.multiformat` at
   all (see that package's own note on why). Running
   `mechanic scan`/`staleness`/`triage`/`explain` never triggers Python to
   even parse either experiment's modules, let alone execute them. Every
   core module (`loader`, `churn`, `discovery`, `categories`,
   `semantic_diff`, `ast_repr`, `fragility`, `structural_detectors`,
   `protected_literals`, `refdata`, `priority`, `legacy_v1`) is likewise
   clean — confirmed by direct grep of every `import`/`from mechanic` line
   in each file, not assumed. `mechanic/priority.py` is the one core
   module that used to import `text_fragility`/`splunk_macros` (for its
   now-removed `_elastic_fragility`/`_splunk_fragility` functions, moved
   unchanged to `mechanic/experimental/multiformat/multiformat_fragility.py`)
   — it no longer does; `priority.build_triage_report` is the reusable
   engine both the core's Sigma-only `compute_triage` and the quarantined
   `compute_multiformat_triage` compose with their own fragility function,
   and that direction (experiment importing core) is fine and expected.
2. **Packaging.** `requests` (the only third-party dependency the repair
   experiment side needs beyond core's own list) lives in `pyproject.toml`
   under `[project.optional-dependencies] repair`, not the base
   `dependencies` list — a `pip install mechanic` with no extras cannot
   even reach `mechanic.llm_client` without a `ModuleNotFoundError`,
   before any question of an API key arises. The multiformat quarantine
   needs no new third-party dependency beyond what the core already
   requires (PyYAML, stdlib `tomllib`/`re`), so there is no equivalent
   packaging gate for it — the import-graph and test enforcement below is
   what does the work there.
3. **A test that fails if the boundary is crossed.**
   `tests/test_core_isolation.py` spawns a fresh subprocess (not the
   already-warm test-runner process, which may have imported anything)
   that imports `mechanic.cli` and inspects `sys.modules` — the test fails
   if any experiment module name appears. A second test in the same file
   runs `scan`, `staleness`, `triage`, and `explain` end-to-end against a
   real fixture repo in a subprocess with `GROQ_API_KEY` unset and
   `MECHANIC_RSIGMA_BIN` unset, asserting each command completes with the
   expected exit code — proving the "zero dependency" claim behaviorally,
   not just by import inspection. The multiformat quarantine needs no
   equivalent live-dependency test (it requires no external binary, network
   access, or API key even to use directly) — the import-graph checks above
   are the whole enforcement story for it, plus
   `tests/test_cli.py::test_triage_and_explain_refuse_non_sigma_fmt_at_the_cli_level`
   proving the CLI's own `--fmt` restriction behaviorally.

## What "quarantine" does and doesn't mean here

It does **not** mean the experiment's own code quality standard drops —
Phase 1–3's own gate discipline, known-answer tests, and independence
audit (`docs/stage3-phase3-independence.md`) stand as written and are not
touched by this hardening pass. It means the experiment's presence,
correctness, or failure can **never** cause a core command to crash,
degrade, or require anything the core doesn't already need on its own.
Someone running `mechanic triage` against a repository has no reason to
ever install RSigma, set an API key, or reach the network — and now that's
true by construction, checked by a test, not by convention.
