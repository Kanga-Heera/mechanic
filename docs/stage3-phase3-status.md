# Stage 3, Phase 3 status: LLM repair generator — go/no-go on the acceptance rate

This phase's job was to add the first and only probabilistic component to
the pipeline — an LLM that proposes repaired rules — without letting it
judge its own output, without letting it see any of the data it would be
tested against, and without tuning the classifier, the gate, or the
sample to move the resulting number. Full evidence for everything below
is in `RESULTS.md`'s "Stage 3, Phase 3" section; the independence claim is
audited separately in `docs/stage3-phase3-independence.md`, the same way
`docs/kappa-provenance.md` audited κ before it was trusted.

## 1. The model-lookup trail

The task spec required looking up the current Groq model live, not
assuming one from training data — and doing so caught a real discrepancy.
`console.groq.com/docs/models` (checked 2026-08-29) still listed
`llama-3.3-70b-versatile` with no deprecation notice. This account's own
`GET /v1/models` response did not: the first live smoke-test call
returned HTTP 404 `model_not_found`, and the account's actual model list
contained no Llama 3.x model of any kind. `DEFAULT_MODEL` was set to
`openai/gpt-oss-120b` — Groq's own documented recommended replacement,
confirmed present in the live list at the same 131,072-token context
window. The lesson, recorded in `mechanic/llm_client.py`'s docstring and
repeated here because it generalizes past this one model: **a docs page
is not the authoritative source for what a live account can actually
call — `GET /v1/models`, checked at run time, is.** Anyone re-running this
phase later should expect to re-check this, not assume `openai/gpt-oss-120b`
is still current.

## 2. The honest acceptance-rate result, and what it means

**1 of 28 sampled rules (3.6%) received a gate-certified LOGIC_REPAIR.**
This is reported as the finding, not adjusted toward a more flattering
number — no change was made to the classifier, the gate, or the sample
composition after seeing early results.

What the other 27 outcomes actually were matters more than the headline
number: 24 RETIRE (15 of those were nominal PASSes or the model's own
`NO_LOGIC_REPAIR_POSSIBLE` claim, not gate-rejections; 9 were genuine
gate-rejections on `EVASIONS_CAUGHT` or `ORIGINAL_STILL_CAUGHT`), and 3
GENERATION_FAILURE (syntactically-plausible-but-invalid Sigma — an
unsupported modifier, an unparseable condition — never a crash, never
silently folded into RETIRE). Zero TELEMETRY_REPAIR in the final,
corrected run (see §3).

**What this measures, and what it doesn't.** This is a measurement of
`openai/gpt-oss-120b` on Groq's free tier, tightly scoped per the Phase 3
spec (the model sees only the fragile rule and the mechanic's own
fragility diagnosis — no benign events, no evasion variants, no field-
availability hints), against a gate that is intentionally stricter than a
human reviewer might be (`fully_exercised` gates acceptance outright,
per the R5 lesson from Phase 2). A low acceptance rate under these
specific, disclosed constraints is not evidence that LLM-assisted rule
repair is hopeless in general — it is evidence about *this* generator,
*this* prompt scope, and *this* gate, which is exactly what an honest
phase-3 result is supposed to be. The one LOGIC_REPAIR that was found
(`proc_creation_win_bitsadmin_download.yml`, generalizing four fragile
per-subcommand literals into one durable URL-pattern check) shows the
mechanism can work when the model finds a genuinely more general
observable — it is just rare in this sample.

One qualitative observation, not folded into the acceptance rate because
it is a judgement call about prompt design rather than a gate-verifiable
fact: the Part 0 smoke test showed the model declining an easy, textbook
rename-based repair (`Image|endswith` → `OriginalFileName`) with
`NO_LOGIC_REPAIR_POSSIBLE`, and its own captured reasoning trace showed it
genuinely never considered `OriginalFileName` as an option, rather than
having judged it and rejected it. This is a real property of the
tightly-scoped prompt (which, per spec, deliberately withholds field-
availability context) worth carrying into any future prompt-design work,
but enriching the prompt now would have moved the number — exactly what
this phase's rules forbid — so it is recorded here as an open question,
not fixed.

## 3. The narrow-vs-wide projection fix

The first complete run used a template event built only from the
*original* rule's own referenced fields (`verify.flat_event_from_evtx`).
That run produced 3 TELEMETRY_REPAIR outcomes. Inspecting one
(a WMIC-recon repair proposing `Image`/`ParentImage`) against the real
upstream SigmaHQ rule for that log source showed those fields are
legitimately available — the narrow projection simply never tried to
resolve fields the *original* rule hadn't referenced, which is a
measurement-validity bug, not a fact about the repair or the telemetry.
Fixed with `verify.full_flat_event_from_evtx()` (a wide projection of
every field RSigma observes for the record, proven a strict superset of
the narrow projection in `tests/test_wide_flat_event.py`) and re-run in
full. All 3 TELEMETRY_REPAIR cases reclassified to RETIRE once checked
against real fields — 2 to nominal-PASS-but-`fully_exercised=False`, 1 to
an actual gate rejection. The acceptance rate itself did not move (the
one LOGIC_REPAIR case was unaffected), but reporting the narrow run's
TELEMETRY_REPAIR count without this fix would have reported a category
that turned out to be entirely a measurement artefact. Both runs are
preserved (`data/phase3_run_results_run1_narrow.json`,
`data/phase3_run_results_run2_wide.json`) specifically so this comparison
stays checkable rather than asserted.

## 4. Go/no-go: is the acceptance rate trustworthy?

**Go.** `docs/stage3-phase3-independence.md` confirms, by direct
inspection of every code path that can reach a generation call, that the
generator never has structural access to benign events, evasion variants,
or gate results — not merely that the prompt omits mentioning them. The
condition-1 evasions used in every one of the 28 gate runs came
exclusively from Phase 2's deterministic transformer, confirmed absent
any `llm_client`/`chat_completion`/`requests.` reference in
`evasion.py`, `gate.py`, `verify.py`, or `synthetic_benign.py`. This
mirrors the standard `kappa-provenance.md` set: a number is only reported
as validated once its boundary has been checked, not asserted.

Two disclosed limitations bound what "go" means here, carried forward
rather than hidden:

1. **Corpus availability, not a pipeline defect.** SigmaHQ's
   `regression_data/` corpus contains zero IOC-tier rules with EVTX
   fixtures, out of 202 candidates scanned — this phase's sample is
   necessarily silent on IOC-tier repair behavior, not because the
   pipeline can't handle that tier (Phase 2 explicitly covered it via
   R5), but because no scoreable IOC-tier rule exists in this specific
   fixture source. A future phase wanting IOC-tier repair-generation
   evidence needs either a different fixture corpus or hand-curated
   fixtures for that tier.
2. **Infrastructure, not framework.** This development machine's network
   stack made the batch run itself unreliable (unfired `requests`
   timeouts, stuck `CLOSE_WAIT` connections) — worked around with
   OS-level subprocess timeouts and incremental, resumable result-writing,
   documented in full in `RESULTS.md`. No rule's outcome was fabricated
   or skipped to route around this; every `RUN_ERROR` was retried until
   it produced a real outcome. This affected how long the run took, not
   what it measured.

Recommendation: the 3.6% acceptance rate and its full outcome breakdown
are ready to be read as this phase's honest result. Any future work
comparing a different model, prompt, or provider against this baseline
should reuse the same seeded sample (`data/phase3_sample_manifest.json`,
`SEED = 42`) and the same gate, changing only the generator side — exactly
the model-agnostic swap `mechanic/llm_client.py` was built to make a
two-line change.
