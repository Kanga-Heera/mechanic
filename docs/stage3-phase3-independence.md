# Stage 3 Phase 3 Independence Audit: what the repair generator can and cannot see

This audit exists for the same reason `kappa-provenance.md` does, and is
run against the same brief: no claim here is assumed valid, and the claim
is checked by tracing actual code paths, not by re-reading prompt wording.
The κ audit found that an earlier evaluation invisibly graded a classifier
against labels the classifier's own designer produced. The failure mode
this audit checks for is the same shape, one level up: an LLM proposing a
repair that is verified using data or logic the same LLM could see or
influence. Every claim below is either traced to a specific file/line
(**repository proves**) or flagged as a residual limitation. This audit
was run before any Phase 3 acceptance rate is reported as meaningful, per
the Phase 3 task spec's Part 4 instruction.

## 1. Question

Two things, verbatim from the spec:

1. Does `mechanic.repair_generator` (the code that calls the LLM) have any
   code path - not just an absence of prompt wording - through which the
   benign event set, the evasion variants, or the gate's internal results
   could reach the model before or during a repair proposal?
2. Are the condition-1 evasions the gate checks a repair against ever
   produced by the same model that proposed the repair (the definition of
   "the self-grading machine" the spec explicitly forbids)?

## 2. Method

Direct inspection of every function the repair-generation call path passes
through, cross-checked with `grep` across the modules downstream of it
(`mechanic/evasion.py`, `mechanic/gate.py`, `mechanic/verify.py`,
`mechanic/synthetic_benign.py`) for any reference to the LLM client at
all. Nothing here relies on trusting a docstring's claim about itself.

## 3. The call graph, traced end to end

```
scripts/run_phase3_acceptance.py: run_one()
    |
    +--> repair_generator.generate_repair(rule_path, model=, base_url=, ...)
    |        |
    |        +--> build_diagnosis(rule_path)              [rule_path ONLY]
    |        +--> build_prompt(diagnosis)                  [diagnosis ONLY, pure function]
    |        +--> llm_client.chat_completion(messages, ...) [messages ONLY, plus provider config]
    |        -->  returns GeneratedRepair
    |
    +--> (benign_events built separately, see Section 5)
    |
    +--> repair_outcome.classify_repair(rule_path, generated, template_tp_event, benign_events, ...)
             |
             +--> [TELEMETRY_REPAIR check: verify.evaluate() - no LLM]
             +--> evasion.generate_confirmed_evasions_for_rule(rule_path, template_tp_event, ...)  [no LLM - see Section 6]
             +--> gate.run_gate(...)  [no LLM - see Section 6]
```

`generate_repair()` returns before `classify_repair()` is ever called (they
are two separate statements in `run_one()`, not two branches of the same
call) - the generator has finished and returned control before the gate,
the evasions, or the benign event are touched at all in the control flow.

## 4. `generate_repair()`'s reachable inputs - **repository proves**

Every function on the LLM side of the call graph, with its complete
parameter list, from `mechanic/repair_generator.py`:

- `generate_repair(rule_path, *, model=None, base_url=None, api_key_env=..., temperature=0.2, max_tokens=4000)`
  (line 199) - `rule_path` plus provider/sampling configuration only.
- `build_diagnosis(rule_path)` (line 128) - ONE parameter. Body reads
  `rule_path.read_text()` (the rule's own YAML) and calls
  `evasion.fragile_atoms_for_rule(rule_path)` - which itself (see
  `mechanic/evasion.py` lines 125-151) only calls `loader.load_file`,
  `ast_repr.build_ast`, and `fragility.classify_rule` on that same rule
  file. No event data, of any kind, is read anywhere in this function.
- `build_prompt(diagnosis)` (line 151) - ONE parameter, a
  `RepairDiagnosis`. `RepairDiagnosis`'s complete field list (line 92-98):
  `rule_path, rule_id, title, rule_text, tier, fragile_atoms`. None of
  these six fields can carry a benign event, an evasion variant, or a gate
  result - they are exhaustively the rule's own identity, its own text,
  and its own fragility classification.
- `llm_client.chat_completion(messages, *, model, base_url, api_key_env, require_api_key, temperature, max_tokens, timeout, max_retries)`
  (traced in `mechanic/llm_client.py`) - `messages` is exactly
  `build_prompt(diagnosis)`'s return value, passed straight through
  `generate_repair()` with nothing added. Every other parameter is
  provider/request configuration (model id, endpoint, timeout, retry
  count) - none of it is event or verification data.

**Conclusion for Section 4**: there is no parameter, no closure variable,
and no module-level import in this call chain that could carry a benign
event, an evasion variant, or a gate result into the HTTP request body.
This matches `tests/test_repair_generator.py`'s structural tests
(`test_build_diagnosis_signature_has_no_forbidden_parameters`,
`test_build_prompt_signature_has_no_forbidden_parameters`,
`test_generate_repair_signature_has_no_forbidden_parameters`,
`test_repair_diagnosis_dataclass_has_no_forbidden_fields`), which assert
this by `inspect.signature`/`__dataclass_fields__` on every run, not only
at audit time.

## 5. The benign event and template event never touch the generator - **repository proves**

`scripts/run_phase3_acceptance.py`'s `run_one()` builds `benign_events`
(via `mechanic.synthetic_benign.synthetic_benign_event`) and receives
`template_event` from the sample manifest, then calls
`repair_generator.generate_repair(rule_path, model=..., base_url=...)` -
neither `benign_events` nor `template_event` appears anywhere in that call.
They are first used later in the same function, in the separate
`repair_outcome.classify_repair(rule_path, generated, template_tp_event, benign_events, ...)`
call - by which point `generated` (the LLM's output) already exists and is
immutable. There is no code path by which information could flow
backward from the classification step into the generation step within a
single rule's run, and no state is carried between different rules' runs
either (each iteration of `run_one()` is independent - no cache, no
running context, no fine-tuning).

## 6. Condition-1 evasions are never produced by the repair-generating model - **repository proves**

Direct `grep` for the LLM client and the HTTP library across every module
downstream of repair generation, run for this audit:

```
$ grep -n "llm_client\|chat_completion\|requests\." \
      mechanic/evasion.py mechanic/gate.py mechanic/verify.py mechanic/synthetic_benign.py
(zero matches)
```

Confirmed directly: `mechanic/evasion.py` (the Phase 2 deterministic
evasion transformer - `generate_confirmed_evasions_for_rule`, the function
`repair_outcome.classify_repair` calls for condition-1 evidence),
`mechanic/gate.py` (the four-condition gate), `mechanic/verify.py` (the
RSigma harness), and `mechanic/synthetic_benign.py` (the automated
benign-event synthesizer) import only `re`, `dataclasses`, `pathlib`,
`typing`, `json`, `subprocess`, `yaml`, `ipaddress`, and other
`mechanic.*` modules - never `mechanic.llm_client`, never `requests`.
There is no code path, anywhere in the verification stack, by which an
LLM of any kind - let alone the SAME model that proposed the repair -
could generate or influence an evasion, a gate condition, or a harness
outcome. The evasions a repair is judged against are always Uetz-style
deterministic string transforms (`mechanic/evasion.py`'s five technique
generators), confirmed real only by re-running the unmodified ORIGINAL
rule through RSigma (`confirm_real_evasions`, itself with zero LLM
involvement).

This closes the specific failure mode the spec names explicitly: "If the
same model ever generates both the repair and the evasions it's judged
against, that's the self-grading machine." It cannot happen here, because
the two are produced by entirely disjoint code - one crosses the network
to a hosted model, the other is pure Python plus a local RSigma subprocess
call, and neither module imports the other's machinery.

## 7. What the generator returns, and what happens to it

`GeneratedRepair`'s complete field list (line 102-114 of
`repair_generator.py`): `proposed_rule_yaml, raw_model_text, model,
endpoint, no_repair_signal, parse_note, raw_reasoning`. Tracing every one
of these seven fields through `repair_outcome.classify_repair`:

- `proposed_rule_yaml` becomes the CANDIDATE repaired rule, written to a
  temp file and run through the same deterministic gate every hand-made
  Phase 1/2 repair went through - never trusted as-is.
- `no_repair_signal` routes to RETIRE, explicitly reported as NOT
  gate-verified (see `repair_outcome.py`'s own docstring and
  `RepairVerdict.reason` text for that branch) - the one place the
  model's own claim is taken at face value, and it is a claim of absence,
  not a self-grade of a rewrite's quality.
- `raw_model_text`, `model`, `endpoint`, `parse_note`, `raw_reasoning` are
  carried through purely for REPORTING (what did the model say, which
  provider/model produced it, why did parsing fail if it did, what was
  its chain of thought) - none of these five fields is read by any
  `if`/comparison in `classify_repair`'s decision logic. Confirmed by
  inspection of `mechanic/repair_outcome.py`: the only field of
  `GeneratedRepair` that participates in a branch is
  `no_repair_signal` (line ~99) and `proposed_rule_yaml` (line ~110,
  `is None` check). The model's own narrative text is never consulted to
  decide its own outcome.

## 8. Residual limitations (not circularity, but worth naming precisely)

- **Non-determinism.** `temperature=0.2` is low but nonzero; re-running
  `generate_repair` on the same rule can produce a different rewrite
  (Groq's own reasoning-token sampling is also not seeded in a way this
  project controls). This is a reproducibility limitation of the LLM
  itself, not a circularity problem - the audit above is about what the
  model can SEE, not about whether it is deterministic.
- **Prompt scope is a deliberate narrowing, not a leak.** The generator
  never sees a field-availability schema for the rule's logsource beyond
  what's already implicit in the rule's own YAML - per the Phase 3 spec's
  Part 1 ("Input to the LLM: a fragile rule + mechanic's fragility
  diagnosis"), this is intentional scope, not an oversight. It does mean
  the model sometimes reasons itself into `NO_LOGIC_REPAIR_POSSIBLE` for a
  case with a known real repair, for lack of schema awareness (observed
  directly in the Part 0 smoke test's captured reasoning trace, see
  `docs/stage3-phase3-status.md`) - a capability/scoping finding, reported
  as such, not something this audit's independence question is about.
- **The provider account itself.** This audit checks mechanic's own code,
  not Groq's infrastructure - we cannot inspect Groq's servers to confirm
  they don't log or reuse prompts. This is a standard third-party-API
  trust boundary, disclosed here rather than silently assumed away.

## 9. Result

**CONFIRMED, by inspection, not by intention.** The repair-generating
LLM's reachable inputs are exhaustively the rule's own file content plus
mechanic's existing fragility diagnosis of it; no code path anywhere in
`mechanic/repair_generator.py`, `mechanic/llm_client.py`, or the Phase 3
orchestration script carries a benign event, an evasion variant, or a gate
result into the model call. The evasions used to check a proposed repair
are produced exclusively by `mechanic/evasion.py`'s Phase 2 deterministic
transformer, which has zero dependency on `mechanic.llm_client` or any
HTTP library - confirmed directly by `grep`, not inferred. The
self-grading failure mode `kappa-provenance.md` found is structurally
impossible in this pipeline, not merely avoided by convention: the
acceptance rate this phase reports can be treated as a real, non-circular
measurement of what this repair-generation framework achieves against
this evasion space, subject only to the residual limitations named in
Section 8.
