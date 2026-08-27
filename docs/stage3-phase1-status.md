<!-- Title: Stage 3 Phase 1 Status -->
# Stage 3, Phase 1 status: harness + gate, proven by hand — decision point

**Scope of this phase (deliberate):** build and prove a trustworthy
verification harness and a deterministic four-condition gate, validated on
5 repairs made **by hand**. No LLM anywhere in this phase. No repair
generation (the original "Part 5") was built. This document is the
decision point that phase's results feed into: is the loop underneath an
automated repair generator sound enough to build on, or did hand-repairing
5 rules surface problems that should change the plan first?

Full evidence: `RESULTS.md`'s "Stage 3, Phase 1" section (verbatim gate
output, the known-answer test table, reproduction commands).
`docs/stage3-harness-evaluation.md` is the prior investigation that led to
adopting RSigma partially (Recommendation B); this document supersedes one
row of that investigation's Task 2 table (corrected in place there too —
see below).

## 1. Does the harness work?

Yes, on every known-answer case tried, after fixing two bugs the process
itself surfaced. That "after fixing two bugs" is not a footnote — it is
the main empirical result of this phase, more informative than a clean
first pass would have been.

**What Part 2 actually validated, concretely**: three real SigmaHQ
regression fixtures across three different raw-EVTX payload shapes
(`Event.System`/`Event.EventData` for a Security-channel rule,
`Event.System`/`Event.UserData.<Provider>.*` for a WMI-Activity rule,
`Event.System`/`Event.EventData` again but Sysmon-shaped for a
process_creation rule), each matched against SigmaHQ's own declared
`match_count` — not a number mechanic produced and is now checking against
itself. Plus a confirmed-trusted benign no-fire, a confirmed-UNVERIFIABLE
field-mismatch, and a confirmed-fail-loud malformed-JSON case.

**Known limitations, stated plainly, not glossed over:**

- **Multi-record EVTX has no per-event accounting.** The wrapper only
  fully trusts a per-event verdict for EVTX files containing exactly one
  record (true of every fixture used so far). A real multi-event forensic
  EVTX (e.g. a genuine EVTX-ATTACK-SAMPLES file with many records) would
  come back `UNVERIFIABLE` as a whole, by design — this is an honest gap,
  not a silent wrong answer, but it does mean the harness can't yet
  process realistic multi-record forensic captures directly. JSON/NDJSON
  input has no such limit (any number of events, each independently
  trusted or flagged).
- **JSON/NDJSON field mismatches are detected but not auto-repaired.**
  Auto-discovery only runs for EVTX input. A hand-authored JSON event set
  that uses the wrong field names for a given rule will correctly come
  back UNVERIFIABLE, but nothing tries to fix it — reasonable for
  hand-authored test fixtures (get the field names right), less so if a
  future phase feeds it pre-existing JSON logs from an unfamiliar source.
- **Ambiguous field-path discovery uses a tie-break, not a real
  resolution.** None of the fixtures tried hit this (every discovered
  mapping in Part 2 was unambiguous), so the tie-break logic itself is
  currently unexercised by any known-answer case — worth a dedicated test
  before leaning on it.
- **No mechanical Uetz-style evasion transformer was built.** Part 3's
  instructions allowed either a deterministic mechanical transformer (the
  five Uetz et al. techniques as string transforms) or hand-authored
  evasions; this phase used hand-authored evasions for all 5 cases, which
  the instructions explicitly permit, but it means evasion generation is
  still a manual, one-at-a-time process today, not a reusable tool.

**One correction made to the prior investigation, in place:**
`docs/stage3-harness-evaluation.md` originally claimed Sysmon-shaped EVTX
rules "work with zero extra setup" via RSigma's builtin `-p sysmon`
pipeline. That was never actually tested — live testing in this phase
(`test_process_creation_builtin_sysmon_pipeline_does_not_flatten_raw_evtx`)
found it's false: `-p sysmon` does not flatten raw EVTX for a real
process_creation rule at all, and makes things worse by adding its own
unmet `EventID` requirement. The investigation doc has been corrected
rather than left standing with a claim this phase disproved.

## 2. The 5 hand-made repair verdicts

| # | What it tests | Verdict | Why |
|---|---|---|---|
| R1 | A genuine durability fix (filename → `OriginalFileName`) | **PASS** | Repaired catches the rename evasion the original missed, still catches the original TP, no new FPs, intent unchanged |
| R2 | A genuine durability fix (exact substring → order-independent `contains\|all`) | **PASS** | Same shape as R1, different technique (argument-order evasion instead of rename) |
| R3 | A **deliberately bad** repair: widened until it "works" | **FAIL** (condition 3) | Catches the evasion, yes — but also fires on 3/3 ordinary benign PowerShell events. **This is the one that matters most**: the gate rejected it correctly. |
| R4 | A plausible-looking but insufficient repair (fixes a casing variant, misses the real evasion) | **FAIL** (condition 1) | Confirms the gate isn't just an "did it get broader" check — a repair that stayed narrow but still doesn't work also correctly fails |
| R5 | An IOC-only rule with no durable observable underneath it at all | **FAIL** (condition 1), even after a reasonable-looking generalization attempt | Correct disposition is **retire**, not repair — the gate demonstrates this with evidence (the widened /24 still misses a rotated C2 IP) rather than by assertion |

**R3 is the load-bearing result of this whole phase.** The explicit
instruction was: "If the gate accepts the deliberately-bad repair, the
gate is broken — fix it before declaring this phase done." It did not
accept it. `NO_NEW_FALSE_POSITIVES` came back `passed: false` with the
exact three newly-caught benign event indices as evidence
(`RESULTS.md` has the verbatim JSON). No condition was fudged, softened,
or reinterpreted to get that result — it's the direct, first-run output of
`gate.run_gate()` on the rule as written.

## 3. Honest assessment: is this loop sound enough to build on?

**Yes, with one condition: the harness's guard discipline is doing real
work and must not be simplified away later.** Two of the three
silent-zero-shaped bugs found in this whole project (the malformed-JSON
drop and the `-p sysmon` non-flattening) were found *while building the
harness*, not in the original investigation — meaning the investigation's
one-case proof, while necessary, was not sufficient on its own to trust
RSigma's raw output. The guard mechanism (schema-presence + event-count,
both independently checked before anything is called "trusted") is what
caught both, and both would have silently corrupted a gate decision if the
wrapper had trusted RSigma's plain summary output instead. This is the
single most important thing this phase established: **the gate is only as
trustworthy as the harness underneath it, and the harness needed real
engineering, not just a CLI wrapper, to earn that trust.** Anyone extending
this system must keep evaluating everything through `mechanic.verify`,
never call RSigma directly "just this once."

**The gate itself discriminates correctly on realistic failure shapes.**
R3 and R4 are not the same kind of bad repair — one is too broad, one is
too narrow — and the gate rejected both, for the *specific* condition each
one actually violates, not a generic "something's wrong" verdict. That
specificity (which condition, with which evidence) is exactly what an
automated repair-generation loop would need to hand back to an LLM as
useful, checkable feedback, rather than a bare pass/fail. This directly
echoes RuleForge's anti-circularity principle from the original
investigation (ground the judge in real behavior, not in a second model's
opinion) — here the "real behavior" is RSigma's actual fire/no-fire
output, guard-verified, not any model's assessment of the diff.

**What would change the plan, and didn't happen:** if R3 had passed, or if
any of Part 2's known-answer cases had failed on first try with no
findable cause, that would have meant the harness or gate wasn't ready and
this phase would have stopped to fix it rather than write this section.
Neither happened. The two bugs that *were* found were found by the
self-validation discipline working exactly as intended (Part 2 catching
problems before Part 3 depended on them), not by the gate producing a
wrong verdict that had to be explained away.

**What isn't proven yet, and should stay explicit rather than assumed:**
five hand-made repairs against small, hand-picked event sets is enough to
validate the *mechanism* (the gate computes the right thing given trusted
inputs), but not enough to characterize how the harness behaves at real
corpus scale — a large benign baseline (hundreds or thousands of events),
multi-record EVTX forensic captures, or a genuinely adversarial evasion
set generated by something other than this session's own imagination. The
recommendation below is to build automated repair generation next, but
its own verification runs should keep exercising the harness against
larger and more varied inputs as a side effect, not assume Part 2's 7
cases are the last word on harness correctness.

## Recommendation

**Proceed to automated (LLM) repair generation, on top of this harness and
gate, unchanged.** The loop is sound: harness guard discipline is proven
on known-answer cases including two it initially got wrong and then fixed,
and the gate correctly separates a real fix, an over-broad fake fix, an
under-powered fake fix, and a genuinely unrepairable rule — using its own
evidence, not a judgment call. Building repair generation now means every
LLM-proposed repair gets judged by the same mechanism that just correctly
rejected R3 and R4 by hand — which is precisely the point: the gate's job
is to make an LLM's optimism (or an LLM's laziness) irrelevant to the
verdict.

Two follow-ups worth doing *alongside*, not *before*, repair generation:
extend multi-record EVTX support if real forensic captures become a
requirement, and build the mechanical Uetz-technique evasion transformer
if hand-authoring evasions one at a time becomes a bottleneck once
generation is running at corpus scale.
