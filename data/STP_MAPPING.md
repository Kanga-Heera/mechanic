# Mapping mechanic's fragility tiers to MITRE's Summiting the Pyramid (STP)

Written and committed to BEFORE any agreement figure in RESULTS.md's STP
validation section was computed, per the Stage 2 brief's requirement that
scale-mapping decisions not be made with the answer already in view.

## What STP actually measures (quoted/paraphrased from the v4.0 docs)

STP's **Analytic Robustness** dimension has five levels
(`center-for-threat-informed-defense.github.io/summiting-the-pyramid/`,
`detection-ttv/levels/*`):

| Level | Name | Definition |
|---:|---|---|
| 1 | Ephemeral Values | The analytic keys on a literal the adversary can trivially change (a filename, a hash, a specific path) without altering their capability at all. |
| 2 | Core to Adversary-Brought Tool | The analytic keys on something intrinsic to a SPECIFIC tool the adversary chose to bring - defeated by switching to a different tool with the same capability. |
| 3 | Core to Pre-Existing Tool | The analytic keys on something intrinsic to a tool ALREADY on the target system (a LOLBin/native utility) - the adversary can still switch which pre-existing tool they abuse, but the pool of pre-existing tools with the needed capability is typically smaller and more constrained than "any tool I can bring." |
| 4 | Core to Some Implementations | The analytic keys on something intrinsic to the underlying technique/sub-technique itself, but only covers SOME of the ways that technique can be implemented. |
| 5 | Core to the Technique | The analytic covers ALL known implementations of the technique - defeating it requires abandoning the technique entirely, not just changing tools or literals. |

**Event Robustness** is a second, independent dimension: Application (A) <
User-mode (U) < Kernel-mode (K) - roughly, how hard the underlying telemetry
itself is to blind/tamper with, independent of what the analytic's LOGIC
keys on. Network-log analytics in the scored dataset also carry an
apparent additional letter, `H`, not documented in the tag-format page
fetched for this project - inferred, not confirmed, to relate to
HTTP/header-visible network telemetry. **mechanic has no equivalent axis at
all** - this is reported as a gap, not silently ignored (see the Step 3
event-robustness section in RESULTS.md).

## The mapping

mechanic's four tiers map onto STP's five levels with an acknowledged
seam - STP's levels 4 and 5 are BOTH "core to the technique," differing
only in implementation coverage, a distinction mechanic's taxonomy does not
attempt to draw at all (mechanic's TTP tier does not distinguish "covers
some implementations" from "covers all implementations"). Similarly, STP's
level 1 covers what mechanic splits into two tiers (IOC vs. Artifact) that
STP does not distinguish.

**Primary mapping (Mapping A - conservative)**:

| STP level | mechanic tier |
|---|---|
| 1 (Ephemeral) | IOC or Artifact (STP does not distinguish these; mechanic's own atom-level classification decides which) |
| 2 (Adversary-brought tool) | Tool |
| 3 (Pre-existing tool) | Tool |
| 4 (Some implementations) | TTP |
| 5 (Full technique) | TTP |

Levels 2 and 3 both collapse to Tool because mechanic's Tool tier is
defined purely as "bound to a specific tool, defeated by switching tools" -
it does not currently distinguish adversary-brought from pre-existing tool
provenance (a real, disclosed gap this comparison surfaces, not previously
visible in the LLM-development-set comparison, which had no equivalent
concept either).

**Alternative mapping (Mapping B - level 3 as TTP)**, tested for
sensitivity per the brief's explicit requirement: STP's own text frames
level 3 as meaningfully more constrained on the adversary than level 2
("core to a tool already on the system" vs. "any tool you care to bring"),
arguably closer in spirit to mechanic's TTP tier (bound to something the
attacker cannot simply swap out at will) than to Tool. Under Mapping B,
level 3 maps to TTP instead of Tool; everything else is unchanged.

| STP level | mechanic tier (Mapping B) |
|---|---|
| 1 | IOC or Artifact |
| 2 | Tool |
| 3 | **TTP** |
| 4 | TTP |
| 5 | TTP |

Both mappings are reported in RESULTS.md's Step 2 sensitivity check.
**Neither mapping is the headline statistic** - per the brief, the rank
correlation computed directly on the two ordinal scales (mechanic's 0-3
tier rank vs. STP's 1-5 analytic score, no mapping applied at all) is
reported as primary, specifically because the mapping above is a real
researcher degree of freedom and rank correlation is not.

## A structural discovery this mapping exercise surfaced, independent of the level mapping itself

STP's documented rule for combining multiple observables within one
analytic (`detection-ttv/combiningobservables/`) is:

> R(A AND B) -> MIN(R(A), R(B)) - the adversary only needs to evade
> whichever of A or B is weaker, so an AND-combined analytic is only as
> robust as its weakest linked observable.
> R(A OR B) -> MAX(R(A), R(B)) - the adversary must defeat BOTH, so an
> OR-combined analytic is at least as robust as its strongest observable.

**mechanic's `rule_tier` is `max()` over every positive atom in the rule,
regardless of whether those atoms are AND-linked or OR-linked.** For a
purely OR-linked rule this is correct by STP's own rule. For an AND-linked
rule - the overwhelmingly common case, since a Sigma `selection:` mapping
combines its `field: value` pairs via implicit AND - **mechanic's `max()`
is the wrong operator under STP's own stated methodology; the correct
operator is `min()`.**

This is a real, previously-undiscovered divergence between mechanic's
scoring logic and the standard it is now being validated against, found
BY DOING the validation, not introduced to explain a bad result after the
fact - the STP documentation was read and this rule extracted before any
mechanic-vs-STP agreement number was computed. See RESULTS.md's STP
validation section for: whether this divergence is empirically large
enough to matter on the scored sample (a diagnostic AND/OR-aware
recomputation for the Sigma-only subset, using the real AST mechanic
already builds), and the explicit recommendation that a real fix
(propagating AND/OR/quantifier structure through `rule_tier` instead of
flattening to a global atom-max) is out of scope for this validation pass
and should be scoped as dedicated follow-on work, not retrofitted here
under time pressure with everything else this pass already changed.
