# mechanic — completed so far

**Detection-rule maintenance triage: an executive summary of Stages 1–3 (Phase 3), what works, and what its limits are.**

This document is a front-matter summary; the full evidence for every claim
below — verbatim command output, tables, contingency matrices, and every
disclosed rejection — is in `RESULTS.md`, reproduced in full after this
summary. Nothing here is asserted without a corresponding section back
there.

## What the project is

`mechanic` is a pipeline for triaging detection-rule maintenance debt in
Sigma (and Sigma-adjacent Elastic/Splunk) rule repositories: which rules
are stale, which are structurally fragile (easy for an adversary to evade
with a trivial rename/reorder/substitution), and — as of Stage 3 — whether
a fragile rule can actually be **repaired**, automatically, with the fix
proven correct by a real detection-engine verification harness rather than
asserted by an LLM.

It was built in three stages, each gated on the previous one's results
actually holding up under external validation before being trusted as a
foundation for the next.

## Stage 1 — infrastructure (fault-isolated loading, git-driven staleness)

**Working.** A fault-isolated Sigma/Elastic/Splunk rule loader (one
malformed file never kills a batch scan) and a git-history-driven
staleness report, validated against five real repositories
(SigmaHQ, Elastic, Splunk, joesecurity, mdecrevoisier). Reproduced a prior
investigation's cited staleness figures almost exactly (SigmaHQ 51.1%,
Elastic 2.7%, Splunk 5.6% stale >2yr) and its largest-mechanical-commit
figures exactly (SigmaHQ 2,931 files, Elastic 1,064 files in one commit).
Mechanical-commit filtering (excluding bulk reformats/migrations before
computing any staleness statistic) is threshold-sensitive but smooth — no
cliff at the chosen 10% default across a 5/10/20% sensitivity sweep on any
of the five repos.

**Limitation, disclosed, not smoothed over.** `ever_revised` is computed
purely from organic (non-mechanical) commits — a rule created inside a
mass-mechanical onboarding commit and tuned exactly once afterward is
indistinguishable, by this metric alone, from a rule created organically
and never touched again. Both show an organic commit count of 1. A
shallow git clone or missing `.git` history fails loudly rather than
silently under-reporting staleness.

## Stage 2 — judgement: fragility tiering, externally validated

**Working, after a real correction.** A structural-fragility classifier
(IOC / Artifact / Tool / TTP tiers) was built and initially validated only
against an LLM-generated development set (kappa 0.80 at best) — flagged
throughout as a self-generated proxy, not ground truth. It was then
checked against MITRE Center for Threat-Informed Defense's **Summiting
the Pyramid** (STP), a published, human-expert-scored external standard
SigmaHQ has formally adopted. The first STP run came back with **no
positive rank correlation at all** (Kendall's tau-b 0.032, p=0.767) —
a genuine early failure, not hidden. Root-caused to a real logic bug (the
classifier's AND/OR combination scored an AND-linked group as the
strongest atom present, when STP's own documented rule takes the
*weakest*). Fixed, and re-run: **tau-b 0.361 (p=0.0010)**, a moderate,
highly significant positive correlation against MITRE's own scored
analytics — the strongest validation branch the project's own
pre-registered interpretation defined in advance.

**Limitation, disclosed as a direct consequence of the fix, not hidden
after the fact.** Fixing the AND/OR bug *dropped* agreement with the
internal LLM-generated development set (SigmaHQ kappa 0.796 → 0.298) —
investigated rather than reverted, and found to be the old bug's flat-MAX
logic masking real atom-classification gaps (e.g., POSIX capability names
like `cap_setgid` are currently treated as generic literals, not the
kernel-defined, non-renamable identifiers they actually are). Per the
project's own standing rule, these newly-exposed gaps were **not**
whack-a-mole patched against the same 90-rule set — they're logged as
open work for a future round using a fresh, held-out sample. A
pre-registered correlation experiment (Task 7) also tested whether
staleness and fragility should be fused into one weighted priority score:
SigmaHQ (the one externally-validated corpus) showed no meaningful
association after controlling for rule age, so `mechanic triage` reports
the two axes **side by side, un-combined** — the absence of a `--weight`
flag is itself a finding, not a missing feature.

## Stage 3 — repair, phased: harness → evasions → LLM

**Phase 1 (working).** A verification harness wrapping RSigma, with
schema-presence and event-count guards that caught two real
silent-corruption bugs (a malformed-JSON drop, RSigma's `-p sysmon`
pipeline silently failing to flatten raw EVTX) *during construction*, and
a four-condition acceptance gate, proven by hand on 5 constructed repairs.
The load-bearing result: a deliberately-bad, over-broadened "repair" was
**correctly rejected** by the gate for firing on 3/3 ordinary benign
events — the gate does not rubber-stamp anything that merely "looks
broader."

**Limitation, carried forward.** Multi-record EVTX had no per-event
accounting yet (closed in Phase 2); an IOC-only rule with no durable
underlying observable was correctly routed to **retire**, not repair —
establishing early that "no repair possible" is a legitimate, expected
outcome the pipeline must be able to report honestly.

**Phase 2 (working, with a load-bearing caveat).** A deterministic
evasion transformer implementing Uetz et al.'s five text-transform evasion
techniques, plus multi-record EVTX accounting. Re-running all 5 Phase-1
repairs through the full gate against *mechanically generated* evasions
held 3 verdicts and **flipped 2** — both informative, not bugs: one
flip found a real weakness a single hand-picked evasion had missed (the
mechanism working as intended); the other flip was an **undeserved PASS**
for an IOC-tier rule, because IOC rotation isn't one of the five
mechanical text-transform techniques and this transformer structurally
cannot produce it. This is exactly why `gate.fully_exercised` exists as a
first-class field: **a PASS is only evidence of evasion-resistance when
every applicable gate condition was actually exercised** — for IOC-tier
rules today, it usually wasn't, and callers must check that flag rather
than trust a bare PASS/FAIL.

**Phase 3 (working, honestly measured — the headline result).** A
model-agnostic LLM repair generator (OpenAI-compatible client, Groq's
`openai/gpt-oss-120b` by default, model looked up live rather than
assumed) that proposes repairs under a tightly-scoped prompt: it never
sees benign events, evasion variants, or gate internals — verified by a
structural independence audit (`docs/stage3-phase3-independence.md`),
not just a prompt-writing promise. Every proposal is judged by the same
gate machinery Phase 1/2 proved by hand — the LLM never asserts its own
success.

Run over a seeded (`SEED=42`), tier-stratified sample of 28 SigmaHQ rules:

| Outcome | Count | Share |
|---|---:|---:|
| RETIRE | 24 | 85.7% |
| GENERATION_FAILURE | 3 | 10.7% |
| **LOGIC_REPAIR** | **1** | **3.6%** |
| TELEMETRY_REPAIR | 0 | 0% |

**The honest acceptance rate is 3.6% (1 of 28)** — reported as the
finding, with nothing tuned afterward to move it. `fully_exercised` was
`False` on 13 of the 28 outcomes, meaning even several nominal PASSes
don't count as durable evidence of evasion-resistance under this
project's own gate discipline. The one accepted repair
(`proc_creation_win_bitsadmin_download.yml`) generalized four fragile
per-subcommand string literals into one durable URL-pattern check and
passed all four gate conditions, fully exercised — proof the mechanism
*can* work, on the rare case where the model finds a genuinely more
general observable.

**Limitations, disclosed rather than absorbed into the headline number:**

- **Measurement-validity bug caught and fixed mid-run.** An early pass
  used a narrow field-projection (only fields the *original*, un-repaired
  rule referenced) and produced 3 false TELEMETRY_REPAIR outcomes for
  fields that were, in fact, available in the real telemetry. Fixed with
  a wide projection (proven a strict superset by test) and the full run
  redone — all 3 reclassified correctly to RETIRE; the acceptance rate
  itself did not move.
- **Corpus-availability gap, not a pipeline defect.** SigmaHQ's
  `regression_data/` corpus has zero IOC-tier rules with EVTX fixtures
  (0 of 202 scanned) — this sample is silent on IOC-tier repair behavior
  because no scoreable fixture exists for that tier in this source, not
  because the pipeline can't handle it.
- **A qualitative prompt-design observation, deliberately not acted on.**
  The model declined an easy, textbook rename-based repair
  (`Image|endswith` → `OriginalFileName`) and its own reasoning trace
  showed it never considered that field, rather than rejecting it after
  consideration — a real property of the deliberately field-hint-starved
  prompt, left as an open question for future prompt design rather than
  fixed now, because fixing it would have moved the reported number.
- **Infrastructure, not framework.** This development machine's network
  stack made the batch run unreliable on its own (unfired HTTP timeouts,
  stuck connections) — worked around with OS-level subprocess timeouts
  and incremental, resumable result-writing. No outcome was skipped or
  fabricated to route around this.
- **What this measures.** This is a result about *one* model
  (`openai/gpt-oss-120b`), *one* tightly-scoped prompt, and *one*
  intentionally strict gate — not a general claim that LLM-assisted rule
  repair is hopeless. `mechanic/llm_client.py` was built model-agnostic
  specifically so a different model/provider can be swapped in as a
  two-line change and compared against this same seeded sample and gate.

## Where this leaves the project

| Stage | Status | Headline evidence |
|---|---|---|
| 1 — loading + staleness | Done, reproduced | 5/5 repos validated against prior figures |
| 2 — fragility tiering | Done, externally validated | STP tau-b 0.361, p=0.0010 (after a disclosed bug fix) |
| 3, Phase 1 — harness + gate | Done | Correctly rejected a deliberately-bad repair by hand |
| 3, Phase 2 — evasion transformer | Done, bounded scope | Found a real weakness + a real coverage gap (IOC tier) |
| 3, Phase 3 — LLM repair generator | Done, honestly measured | 3.6% acceptance (1/28), independence-audited |

All work is committed to git, per-part, with the full commit history
available in the repository. Every stage's own status document
(`docs/stage3-phase{1,2,3}-status.md`) contains its own explicit go/no-go
recommendation, none of which was accepted without a stated reason.

---
