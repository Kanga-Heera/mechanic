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
| Structural fragility classifier | `mechanic/fragility.py`, `mechanic/text_fragility.py`, `mechanic/structural_detectors.py`, `mechanic/protected_literals.py`, `mechanic/refdata.py`, `mechanic/splunk_macros.py`, `mechanic/legacy_v1.py` (ablation baseline only) |
| Review-priority triage | `mechanic/priority.py` |
| CLI | `mechanic/cli.py` — `scan`, `staleness`, `ast`, `report`, `triage`, `explain` |

**Validation status**: the fragility taxonomy is externally validated
against MITRE Center for Threat-Informed Defense's Summiting the Pyramid
(STP) — Kendall's tau-b 0.361, p = 0.0010 (`RESULTS.md`, "Part 2, external
validation" and "The AND/OR fix"). Staleness reproduces a prior
investigation's cited figures across five real repositories. This is the
project's calibrated, trusted instrument — see Part 4 below for how these
numbers are pinned against silent drift.

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

## The enforcement, not just the claim

A stated boundary that nothing checks is not a boundary. Three mechanisms
enforce this one:

1. **Import graph.** `mechanic/cli.py` (the core CLI) contains zero
   imports of `verify`, `gate`, `evasion`, `synthetic_benign`,
   `llm_client`, `repair_generator`, or `repair_outcome` — not lazy
   imports inside function bodies, no imports at all. The only CLI module
   that imports `mechanic.verify` is `mechanic/cli_repair.py`, a separate
   file registered as a separate console script (`mechanic-repair`), so
   running `mechanic scan`/`staleness`/`triage`/`explain` never triggers
   Python to even parse the experiment modules, let alone execute them.
   Every core module (`loader`, `churn`, `discovery`, `categories`,
   `semantic_diff`, `ast_repr`, `fragility`, `text_fragility`,
   `structural_detectors`, `protected_literals`, `refdata`,
   `splunk_macros`, `priority`, `legacy_v1`) is likewise clean — confirmed
   by direct grep of every `import`/`from mechanic` line in each file, not
   assumed.
2. **Packaging.** `requests` (the only third-party dependency the
   experiment side needs beyond core's own list) lives in `pyproject.toml`
   under `[project.optional-dependencies] repair`, not the base
   `dependencies` list — a `pip install mechanic` with no extras cannot
   even reach `mechanic.llm_client` without a `ModuleNotFoundError`,
   before any question of an API key arises.
3. **A test that fails if the boundary is crossed.**
   `tests/test_core_isolation.py` spawns a fresh subprocess (not the
   already-warm test-runner process, which may have imported anything)
   that imports `mechanic.cli` and inspects `sys.modules` — the test fails
   if any experiment module name appears. A second test in the same file
   runs `scan`, `staleness`, `triage`, and `explain` end-to-end against a
   real fixture repo in a subprocess with `GROQ_API_KEY` unset and
   `MECHANIC_RSIGMA_BIN` unset, asserting each command completes with the
   expected exit code — proving the "zero dependency" claim behaviorally,
   not just by import inspection.

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
