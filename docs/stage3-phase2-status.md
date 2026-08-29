# Stage 3, Phase 2 status: deterministic evasion transformer — go/no-go for a probabilistic repair generator

This phase's job was to close the two gaps `docs/stage3-phase1-status.md`
named — no mechanical evasion transformer, no multi-record EVTX accounting
— and then use the transformer to re-run Phase 1's five hand-made repairs
through the full gate, *before* any probabilistic (LLM) component enters
the pipeline. No LLM was built or run in this phase. Full evidence for
everything below is in `RESULTS.md`'s "Stage 3, Phase 2" section.

## 1. Does the transformer work, and what are its limits?

Yes, within a bounded scope, and that scope is the central fact to carry
forward.

`mechanic/evasion.py` implements Uetz et al.'s five evasion technique
classes (character insertion, synonymous substitution, omission,
reordering, recoding) as deterministic transforms, validated against
known-answer cases (`tests/test_evasion.py`, 8/8 passing) including two
live-harness round trips — one candidate independently confirmed a real
evasion, one correctly discarded because the original rule still caught
it. Field-category gating (`commandline` / `path_identity` / `other`)
means the transformer produces zero candidates for a raw IOC and zero for
a protected registry literal, without any test-specific special-casing —
exactly the "don't manufacture fake evasions" requirement.

**The limitation, stated plainly, because it is load-bearing for the rest
of this document:** these five techniques define both the evasions this
transformer can produce, and — implicitly — the outer bound of what a
repair verified against them has been shown to resist. A PASS built on
mechanical evasions is verified against a **known, bounded evasion space**,
not a creative human adversary. Uetz's own paper used external
expert-crafted evasions as a separate validation arm; this project has not
yet done that, and Part 4 below shows concretely where the gap bites
(R1, R5). Requesting or building that expert-evasion arm remains open
future work, not a nice-to-have.

A second, narrower limitation surfaced only in Part 4, not anticipated
going in: the harness confirms a candidate breaks the *rule's literal-text
match*; it does not confirm the candidate is *operationally realistic* for
the specific interpreter that would run it (see R2 below). Bounded evasion
space and operational realism are two different limitations and both need
to be carried forward separately.

## 2. Did the five repairs' verdicts hold under generated evasions?

Three held cleanly, two flipped — and both flips are genuine findings
about coverage, not bugs in the gate or the transformer.

| # | Phase 1 (hand evasion) | Phase 2 (mechanical evasions) | Held? |
|---|---|---|---|
| R1 | PASS | PASS, but `EVASIONS_CAUGHT` **not applicable** (0 mechanical evasions exist for a bare filename — the real evasion class is *rename*, outside the 5 techniques) | Nominally yes, but weaker: this PASS is no longer (and, on reflection, was already only weakly) evidence the repair resists evasion |
| R2 | PASS | **FAILS** — a character-insertion candidate fragmenting the load-bearing token `-urlcache` evades the repair too, something the single hand-picked reordering evasion never exercised. Operational-realism caveat applies (backtick-insertion is a PowerShell convention; this event's launcher is `certutil.exe`, typically `cmd.exe`-driven) | No — but broader, genuine coverage, with a caveat on this specific candidate's real-world realism |
| R3 | FAIL | FAIL, now against 6 confirmed evasions instead of 1, same failure mode (`NO_NEW_FALSE_POSITIVES`) | Yes, and more strongly evidenced |
| R4 | FAIL | FAIL, now against 6 confirmed evasions, none caught (stronger than Phase 1's 1) | Yes, and more strongly evidenced |
| R5 | FAIL | **PASSES** — 0 mechanical evasions exist for a raw IOC (`DestinationIp`), so `EVASIONS_CAUGHT` is not applicable and the verdict rests entirely on conditions 2-4, which the widened-but-not-durable repair trivially satisfies | No — and this is the important one |

The deliberately-bad R3 "fix" still correctly **FAILS**. The R5 IOC-only
retire case, which Phase 1 correctly rejected using a hand-crafted IOC-
rotation evasion, **flips to an undeserved PASS** once the evasion source
is purely mechanical — because IOC rotation is not one of Uetz's five
text-transform techniques and never could be produced by this transformer.

Investigating both flips: **R2's flip is the mechanism working as
intended** — mechanical generation is more exhaustive than one human's
hand-picked evasion, and it found a real (if caveat-laden) weakness the
hand pass missed. **R5's flip is a genuine coverage gap**, not the gate
misbehaving: given zero evasion events (because zero exist for this field
category), the gate did exactly what Phase 1 proved it does with no
evasion evidence. The gap is upstream, in what evidence is even available
to feed it for IOC-tier rules.

## 3. Is condition 1 (`EVASIONS_CAUGHT`) now soundly exercised by systematic evasions?

**Nuanced answer: yes for commandline/path-identity-tier fragile atoms, no
for IOC-tier atoms.**

For rules whose fragile atom is shell-parsed text (the `Tool` tier in
this project's classifier — R2/R3/R4 above) or an opaque path, the
transformer now provides real, harness-confirmed, multi-technique coverage
that is strictly broader than one hand-picked evasion, per R2's flip. That
is a genuine improvement over Phase 1's condition 1.

For rules whose fragile atom is a raw IOC (the `IOC` tier — R5, and by the
same logic any pure hash/IP/domain-keyed rule), condition 1 has **zero**
coverage from mechanical evasions, by design — none of the five Uetz
techniques semantically apply to a value nothing parses. `EVASIONS_CAUGHT`
degrades to "not applicable," and the overall verdict silently rests on
conditions 2-4 alone unless a caller explicitly checks
`gate.fully_exercised`. R1 (filename-tier, evadable only by rename) shows
the same failure mode at smaller scale — Tool-tier is not uniformly safe
either, only the *shell-parsed-text* subset of it is.

## 4. Go/no-go: is this pipeline ready for a probabilistic repair generator?

**Go, but conditionally — with one required guard, not an optional one.**

The harness, gate, and transformer are all deterministic, validated on
known-answer cases, and now proven end to end on all five of Phase 1's
repairs, including finding and correctly explaining two verdict flips
rather than suppressing either. That is a solid, honest foundation for a
probabilistic component to plug into: it decides nothing itself, it only
generates candidates for repairs and evasions that the same trusted
harness/gate machinery evaluates exactly as it evaluated hand-made ones.

The required guard, made concrete by this phase's own results and now
mechanically checkable via `GateReport.fully_exercised`: **a caller must
never treat a PASS as evidence a repair resists evasion unless
`fully_exercised` is `True` (or the caller has independently supplied a
non-mechanical evasion source for that rule's fragile-atom tier).** For
IOC-tier fragile atoms specifically, a PASS from this pipeline currently
means only "no regression on the given TP/benign set," not "resists
evasion" — R5 is the concrete proof, not a hypothetical. Before a
probabilistic repair generator is trusted to auto-accept or recommend
IOC-tier repairs, this project needs either (a) a supplementary
evasion source for IOC-tier rules (the honest options are a hand-curated
rotation/aliasing set, or deferring to Uetz's external expert evasions
for exactly this tier), or (b) a hard rule that IOC-tier PASSes are always
routed to human review regardless of gate verdict.

Recommendation: proceed to building the probabilistic repair generator,
condition-by-condition exactly as planned, **with `fully_exercised`
wired into its accept/reject logic from day one** — not added later as a
patch once a probabilistic generator produces its own version of the R5
mistake at scale.
