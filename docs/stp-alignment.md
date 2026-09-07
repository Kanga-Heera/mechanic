# Aligning mechanic's tiers with Summiting the Pyramid v4.0

This document is the deeper follow-on to `mechanic/data/STP_MAPPING.md`
(written *before* any agreement figure was computed, per the Stage 2
brief's requirement that scale-mapping decisions not be made with the
answer already in view). That file states mechanic's headline scale-mapping
decision and reports it as a sensitivity check. This document goes further:
it pins the STP version story down precisely, quotes STP v4.0's level
pages directly (not paraphrased from memory - every quote below was
fetched live from the page cited beside it), and uses those citations to
pin down exactly where mechanic's four-tier taxonomy is a faithful
projection of STP's five-level model and where it is a lossy one - then
applies that mapping to the three rows that moved in the script-content
fragility fix (see `RESULTS.md`, "Bug fix: script-content field durability
inversion") to determine whether that tau-b drop was a real classification
problem or an artifact of the lossy projection.

**Rule followed throughout:** this document changes no tier LOGIC and no
validated number. Where it identifies a genuine simplification worth
reconsidering (the Tool tier's Level 2/3 collapse), that is written up as
proposed future work with its own justification, not implemented here.

---

## Part 1 — Version provenance: is there actually a mismatch?

**The question:** SigmaHQ's `stp` rule tags reference STP v1.0.0. STP's
live methodology is v4.0.0 (confirmed live: the level-system overview page
states `**Version:** v4.0.0` -
<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/>).
mechanic's docs cite "v4.0" as the current standard. Is the ground truth
mechanic validates against actually scored under the same version mechanic
designs toward?

**What was already established** (`STP_ADOPTION_CENSUS.md`, this project's
own prior research, sourced from the STP repo's own changelog and git tag
history, not a blog paraphrase):

| Version | Changelog date | Nearest git tag/commit |
|---|---|---|
| 1.0 | 2023-09-14 | `v1.0.0`, 2023-09-13T23:12:20Z |
| 2.0 | 2024-12-17 | `v2.0.0`, 2024-12-13T14:06:35Z |
| 3.0 | 2025-05-08 | `v3.0.0`, 2025-05-10T01:29:26Z |
| 4.0 | 2026-02-20 | *(no git tag as of 2026-08-22)* |

Two scored-analytics CSVs exist in the live STP repo: `ScoredAnalytics_12062024.csv`
(87 rows, referenced from the repo README) and `ScoredAnalytics_05062025.csv`
(92 rows, referenced from the actual methodology page and byte-identical to
this project's cached copy). **mechanic uses the 92-row file** - dated
**2025-05-06**, two days *before* v3.0's 2025-05-08 release. So the ground
truth mechanic validates against was almost certainly scored under **v2.0's**
methodology (released 2024-12-17), not v1.0 (the version the sparse SigmaHQ
tags reference, and which mechanic's own RESULTS.md already declined to use
as the primary validation source for exactly this staleness reason - Step 1
of the STP validation section), not v3.0, and not v4.0.

**What changed between v2.0 (the CSV's likely era) and v4.0 (current),
per the changelog fetched live**
(<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/changelog/>):

> "Version 3.0 - May 8th, 2025: This release includes our 'Ambiguous
> Techniques' research, which defines what makes a technique ambiguous,
> identifies examples of ambiguous techniques in MITRE ATT&CK, and
> contributes new best practices for building robust detections for
> ambiguous techniques."
>
> "Version 4.0 - February 20th, 2026: ...three major improvements:
> restructuring the website for improved navigation alignment with CTID's
> Detection Engineering work, introducing Telemetry Strategy & Readiness
> content regarding minimum telemetry requirements, and adding Telemetry
> Confidence scoring methodology with use case examples and AI/LLM
> automation approaches."

**No changes to level definitions, level names, or the total number of
levels are documented across any of these versions.** v2.0 added the
network-detection scoring elements (the columns dimension, Part 3 below)
and formally defined "robustness" as a term; v3.0 added guidance for
ambiguous techniques (a different concern - which technique an observable
implies, not how robust an observable is); v4.0 restructured navigation and
added an unrelated Telemetry Confidence methodology. **The five-level
Analytic Robustness model itself (Ephemeral / Adversary-Brought Tool /
Pre-Existing Tool / Some Implementations / Full Technique) has been stable
since v1.0.0 (2023-09-14).**

**Finding, stated plainly - and it is not the finding the brief
hypothesized:** there is no substantive version mismatch in the thing that
actually matters for mechanic's tier design (the level definitions). The
CSV's ~v2.0-era scoring, the v1.0-tagged SigmaHQ sample (unused as primary
validation for unrelated staleness reasons already documented), and the
v4.0 documentation mechanic's tier definitions are now grounded in (Part 5)
are all describing the **same underlying 5-level taxonomy**. The version
story is a red herring for the specific tau-b drop under investigation;
the real seam is structural (Part 2), not a version drift.

---

## Part 2 — Mapping mechanic's four tiers onto STP's five levels

Every quote below was fetched live from the URL beside it (STP v4.0), not
recalled from training data or copied from mechanic's own earlier
paraphrase in `STP_MAPPING.md`.

### Level 1 — Ephemeral Values

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/ephemeral/>

> "Observables that are trivial for an adversary to change, or that change
> even without adversary intervention." ... "high accuracy" but "often easy
> to evade" and "cannot be relied on to identify adversary behavior."

Examples given, with the exact Sysmon/EID fields STP assigns to each:
Hashes; SourceIp/DestinationIp; DestinationPort/SourcePort;
**"Image (Sysmon)," "Parent image (Sysmon)," "CurrentDirectory (Sysmon),"
"Extension (Sysmon)," "TargetFilename (Sysmon)"** (filenames);
SourceHostname/DestinationHostname (domains); ProcessGuid/ProcessId/etc.
(process identifiers); **Pipe Names (Sysmon)**, evasion guidance "Change
the name of the pipe."

**This is materially broader than mechanic's IOC tier.** mechanic's IOC
tier (`fragility.is_raw_ioc`) covers exactly two shapes: a hash-length hex
string and an IPv4 literal. STP's Level 1 additionally includes bare
filenames (explicitly `Image`), domains, ports, and generic pipe names -
every one of which mechanic tiers as **Artifact**, not IOC. STP does not
distinguish these two mechanic tiers at all; **both are Level 1 under
STP's own definition.** This confirms and sharpens `STP_MAPPING.md`'s
existing note ("STP's level 1 covers what mechanic splits into two tiers")
with the exact field list that makes it concrete.

### Level 2 — Core to Adversary-Brought Tool

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/adversary_tool/>

> "Observables associated with tools that are brought in by an adversary
> to accomplish an attack." ... positioned "outside boundary" because
> "adversaries control them entirely, can recompile them, and modify
> source code to circumvent detection strategies."

Example observable categories: **Command-Line Arguments** (`CommandLine`,
`ParentCommandLine`, Sysmon), **Process Creation** (`OriginalFileName`,
Sysmon), Tool-Specific Configurations (Integrity level), Metadata,
Binaries. Evasion: "renaming arguments (requiring recompile), editing PE
headers, reconfiguring tool settings, recompiling tools."

### Level 3 — Core to Pre-Existing Tools or Inside Boundary

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/preexisting_tool/>

> "Observables associated with a tool or functionality that existed on the
> system pre-compromise, may be managed by the defending organization, and
> is difficult for an adversary to modify." "Inside boundary" - "the
> adversary controls only the originator endpoint and has not yet achieved
> control of the target endpoint."

Example observable categories (verbatim table): **Command-Line Arguments**
(`CommandLine`, Process Command Line, `ParentCommandLine`) - **the same
field names as Level 2** - plus Signatures, Tool-Specific Configurations,
User Session, Authentication, Network Connection, Named Pipe Connection.
Evasion: "change the tool/configuration, edit PE headers, pivot to
different tools, raise permissions."

**The decisive finding for mechanic's Tool tier**: `CommandLine` and
`OriginalFileName` are listed as *example observables at both Level 2 and
Level 3*. STP's own documentation confirms the split is **not determined
by which field is matched** - it is determined by **which tool generated
the value**: an adversary-brought binary's command line is Level 2: the
exact same field, sourced from a pre-existing/native binary, is Level 3.
**This is a provenance judgment STP itself says requires knowing whose
tool produced the observable, not something derivable from the field name
or literal value alone.**

mechanic's Tool tier (`fragility.is_tool_value`) has no such provenance
axis - it fires on a catalog hit (`refdata.all_tool_names`, itself a
LOLBAS/GTFOBins/LOOBins/ATT&CK-software merge that already straddles
"pre-existing OS binary" and "attacker-brought named tool") or a
cmdlet/exe-shaped pattern, regardless of whether the underlying tool was
native to the system or brought in by the adversary. **mechanic's Tool
tier is a deliberate, disclosed collapse of STP Levels 2 and 3.**

### Level 4 — Core to Some Implementations of (Sub-)Technique

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/implementations/>

> "Observables associated with low-variance behaviors of the
> (sub-)technique, unavoidable without a substantially different
> implementation."

Worked examples include: `TargetImage = lsass.exe` with
`GrantedAccess: 0x1010 OR 0x1410` (LSASS memory access); Event 5145/Sysmon
18 `PipeName = atsvc` for remote Scheduled Task creation; `PipeName =
winreg` for remote registry access.

**This directly corroborates mechanic's `protected_literals.windows_rpc_named_pipes`
category** (svcctl, atsvc, lsarpc, samr, netlogon, winreg, ... -
unconditionally protected, TTP tier). STP itself scores the exact same
named pipes - `atsvc`, `winreg` - at **Level 4**, using the *specific,
protocol-fixed pipe name* as the discriminator, in direct contrast to
Level 1's generic "Pipe Names (Sysmon)" example ("change the name of the
pipe"). **The same observable TYPE (a pipe name) lands at wildly different
STP levels depending on whether the exact VALUE is protocol-fixed (Level
4) or attacker-chosen/arbitrary (Level 1).** This is a general STP
principle worth stating explicitly because it validates mechanic's design
philosophy directly: mechanic's `protected_literals` module is
value-specific (a fixed, closed list of protocol-defined literals), not
field-generic, for exactly this reason - a generic "PipeName field is
present" rule would be Level-1-fragile; mechanic's actual rule (does the
value match one of the specific, protocol-fixed pipe names) is what earns
the higher tier, and STP's own Level 1 vs. Level 4 pipe-name examples
confirm that distinction is the right one to be making.

The same pattern holds for `Image`/`TargetImage`: a **bare** filename
value is Level 1 (the Level 1 page lists `Image (Sysmon)` directly), but
`TargetImage = lsass.exe` **combined with** `GrantedAccess` is Level 4 -
the elevation comes from the *relationship* between two observables, not
from the filename literal itself. This directly corroborates mechanic's
own design choice to promote `FIELD_MISMATCH` (an `Image`-vs-`OriginalFileName`
*relationship*) to TTP via a structural detector that runs *before*
atom-level literal classification, rather than trying to make a bare
`Image` literal itself carry more weight than STP says it should.

### Level 5 — Core to Sub-Technique or Technique

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/technique/>

> "Chokepoints" or "invariant behaviors" ... "generate identical artifacts
> regardless of how they're executed" ... Level 5 "captures invariant
> behaviors present across ALL implementations, whereas Level 4 addresses
> observables... meaning only some execution methods produce those
> artifacts."

Examples: the Scheduled Tasks registry key `TaskCache`/`TaskCache\Tree`
(any new task, any implementation, writes here); DCSync's `drsuapi`
RPC endpoint with `DRSReplicaSync`/`DRSGetNCChanges` operations (any DCSync
implementation must invoke this RPC interface).

**mechanic's TTP tier does not distinguish "covers some implementations"
(Level 4) from "covers all implementations" (Level 5).** Every structural
detector promotion (`FIELD_MISMATCH`, `ABSENCE`, `RARITY`, `CORRELATION`)
and every `protected_literals` match lands at the same TTP tier regardless
of whether the underlying mechanism is Level-4-scoped (works for some
implementations of the technique) or genuinely Level-5-invariant (no
implementation can avoid it). This is the mirror image of the Tool-tier
collapse above: **mechanic is under-granular at both ends relative to STP**
(one Tool tier for STP's two tool levels, one TTP tier for STP's two
technique levels) and correspondingly **over-granular at the bottom**
(two tiers, IOC and Artifact, for STP's one Ephemeral level).

### Summary table

| mechanic tier | STP level(s) | Correspondence |
|---|---|---|
| IOC | 1 (Ephemeral) | Lossy: mechanic draws a finer line (raw hash/IP pattern only) inside a single STP level that also includes filenames, domains, ports, generic pipe names |
| Artifact | 1 (Ephemeral) | Same STP level as IOC - the residual bucket for everything Level-1-shaped that isn't a raw hash/IP pattern |
| Tool | 2 (Adversary-Brought) + 3 (Pre-Existing) | Lossy: STP splits by tool PROVENANCE (who brought the tool), a judgment mechanic's field/value-only classifier cannot make; mechanic collapses both to one tier |
| TTP | 4 (Some Implementations) + 5 (Full Technique) | Lossy: STP splits by IMPLEMENTATION COVERAGE (some vs. all); mechanic's structural detectors and protected literals do not currently distinguish which they've found |

This table sharpens (does not replace) `STP_MAPPING.md`'s Mapping A/B -
the two files agree on the headline mapping; this document adds the exact
field-level citations behind the Level 2/3 split specifically, because
that split is the prime suspect for the script-content seam (Part 5).

---

## Part 3 — The columns dimension: scope decision

STP scores a second, independent dimension alongside the five Analytic
Robustness levels - host columns (Application / User-Mode / Kernel-Mode)
and network columns (Payload Visibility / Header Visibility):

> "The model uses these analytic robustness categories alongside three
> columns for host-based events (Application, User-Mode, Kernel-Mode) and
> two columns for network traffic (Payload Visibility, Header Visibility)
> to evaluate detection strength."
> - <https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/levels/>

And from the scoring-methodology page:

> "analytic components that are ANDed together will fall to the score of
> the lowest observable" ... "sensor data placement... directly determines
> the column letter of the final score." (Worked example: a kernel-level
> Sysmon minifilter event yields a final score of "1K.")
> - <https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/detection-ttv/scoringanalytic/>

**Decision: out of scope for mechanic, documented as a known limitation -
not silently ignored.** Modeling which OS layer (application / user-mode
kernel-boundary / true kernel-mode) generated every observable mechanic's
AST walk touches would require a sensor/telemetry-provenance model
mechanic does not have and Sigma's own schema does not encode per-field
(a Sigma rule's `logsource` names a product/category/service, not a
per-field telemetry layer) - a large, separate modeling task, not a
tiering fix.

**How much of the STP disagreement this might explain - quantified, not
guessed:** this was already measured directly in a prior validation pass
(`RESULTS.md`, Step 3): a Kendall's tau of **0.149 (p=0.271, n=50)**
between STP's own A/U/K event-robustness ordering and mechanic's fragility
tier - weak, not statistically significant, indistinguishable from no
relationship. Two things follow from this:

1. **mechanic's headline STP correlation (tau-b vs. MITRE's score) is not
   contaminated by the columns dimension in the first place** - it is
   computed directly against the CSV's "Analytic Robustness Score" column
   alone (`scratchpad/stp_validation.py`'s `analytic_score` field), never
   against STP's combined "Final Score" (which folds in the column
   letter). The columns axis and mechanic's headline number are simply
   orthogonal measurements; mechanic's number cannot be distorted by an
   axis it never touches.
2. Because that correlation is already near-zero and non-significant,
   there is no evidence mechanic's tier is *accidentally* tracking (or
   fighting) the columns dimension through some other field either -
   it's close to pure noise from mechanic's perspective, consistent with
   mechanic genuinely having zero information on this axis, not a
   confound.

**Conclusion for Part 5 below: the columns dimension cannot explain the
3-row tau-b drop from the script-content fix**, because the statistic that
drop was measured against never includes columns to begin with.

---

## Part 4 — Combining observables, D3, and spanning sets

### Combining observables: does mechanic's AND/OR logic actually match STP v4.0?

Verbatim, fetched live:
<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/detection-ttv/combiningobservables/>

> "R(A AND B) → MIN(R(A), R(B))" - "an attacker needs only evade one, so
> the robustness equals the weaker observable's level."
>
> "R(A OR B) → MAX(R(A), R(B))" - "an adversary must evade both
> observables, so robustness equals the stronger observable's level.
> Exception: two Level 4 observables covering all implementations can
> elevate to Level 5."
>
> "R((A AND B) | A) → R(B))" - when B is predicated on A, robustness
> reduces to B's level alone, since A's observation is guaranteed.
>
> "R(NOT A) → R(A)" - negating an observable does not change its
> robustness level.
>
> Filter negation: "R(A) and NOT(FILTER C AND FILTER D) → R(A) AND
> (NOT(FILTER C) OR NOT(FILTER D))" - NOT distributes, flipping AND to OR.

**Confirmed: mechanic's core AND=MIN/OR=MAX design matches STP v4.0's
documented rule exactly**, quoted here directly rather than assumed from
an earlier paraphrase - this is the fix `fragility._combine_ast_tier`
implements (see RESULTS.md, "The AND/OR fix, implemented, and everything
re-run"), and it is the correct operator per STP's own current
documentation, not an inferred or superseded version of the rule.

**Two documented STP rules mechanic does NOT implement, found by this
comparison, neither previously disclosed:**

1. **The Level-4-pair-elevates-to-Level-5 exception.** mechanic's OR
   combination is a plain `max()` with no elevation logic. In practice
   this exception is close to *moot* for mechanic specifically because
   mechanic's TTP tier already collapses Levels 4 and 5 (Part 2) - two
   "TTP"-tier atoms OR'd together are already at mechanic's ceiling, so
   there is no separate "Level 5" slot to elevate into. This is a direct
   consequence of the same Level 4/5 collapse already documented as a
   deliberate simplification, not a new gap.

2. **Negation handling diverges from STP's literal rule.** STP says
   `R(NOT A) → R(A)` - a negated observable keeps its own level and
   participates in the surrounding AND/OR combination at that level.
   mechanic's `_combine_ast_tier` instead **excludes every negated leaf
   from the combination entirely** (`if node.get("negated"): return None`)
   - contributing nothing, rather than its own (unchanged) level. For a
   rule shaped `selection AND NOT excluded_filter`, STP's formula would
   compute `MIN(R(selection), R(excluded_filter))`; mechanic computes
   `R(selection)` alone. **These agree only when the excluded filter's own
   literal is not more ephemeral than the positive selection it's
   attached to** - if a filter literal happens to be Level-1-shaped
   (e.g. excluding a specific benign filename) attached to a
   higher-tier positive selection, STP's formula would pull the whole
   analytic down to Level 1, while mechanic's exclusion leaves it at the
   positive selection's tier. This is a genuine, previously undocumented
   divergence between mechanic's combination logic and STP's literal rule
   - found by this comparison, not fixed here (per the brief: assess,
   don't build). It is a defensible, deliberate design choice, not an
   oversight: Sigma's own `filter*` naming convention distinguishes
   "noise reduction on a positive hit" from "the negation IS the
   detection" (mechanic's separate `ABSENCE` structural detector already
   owns the latter case), a semantic distinction STP's abstract `R(NOT A)`
   rule does not itself draw. Reconciling this precisely - computing
   `R(NOT A)` for an excluded filter and folding it into the MIN, while
   keeping ABSENCE's separate promotion for genuine absence-based
   detection - is proposed as **future work**, not implemented here.

The `"R((A AND B) | A) → R(B)"` conditional-combination rule has no direct
analogue in mechanic's current AST walk - Sigma's condition language does
not expose an equivalent "B is only meaningful given A" predicate as a
first-class construct the way STP's abstract notation does. The closest
existing mechanic concept is `structural_detectors.py`'s relationship-aware
detectors (Part 2's `FIELD_MISMATCH`/`GrantedAccess`-style compound
observables), which is exactly the D3/spanning-set territory below.

### D3 and spanning sets: a citable basis for mechanic's deferred relationship layer?

<https://center-for-threat-informed-defense.github.io/summiting-the-pyramid/analytic-design/detection-diagram/>

> The Detection Decomposition Diagram (D3) is "a visual aid designed to
> showcase significant observables that exist across various
> implementations of a technique." A **spanning set** is an observable
> that "appears consistently across multiple implementations of a
> technique" - STP's own worked example is `TargetImage: "lsass.exe"` as a
> spanning set for LSASS credential dumping, refined by adding
> `GrantedAccess` masks "to reduce false positives while maintaining
> coverage," then further refined with environmental exclusions.

**Assessment: this is a documented, citable basis for mechanic's deferred
relationship/context layer, and a tractable *future direction*, not a
large research task on its own** - but only for a narrow slice of what D3
covers. D3's actual purpose is *analytic design* (helping a human build a
new, robust detection from scratch by decomposing a technique into
observables and refining them) - it is a design-time methodology for
authoring rules, not a scoring rubric for classifying rules that already
exist. mechanic's job is the latter (classify an existing rule's
fragility), not the former. The concrete, tractable piece mechanic could
plausibly borrow: D3's "spanning set" idea - a specific field/value
combination that recurs across a technique's known implementations - is
conceptually the same shape as `structural_detectors.py`'s existing
`FIELD_MISMATCH` detector (a hand-curated, single, well-evidenced spanning
set: `Image` vs. `OriginalFileName` for renamed-binary detection). A
tractable future direction is authoring a small library of ADDITIONAL,
STP-documented spanning sets as new structural detectors (the Level 4
examples fetched in Part 2 above - `TargetImage=lsass.exe` + `GrantedAccess`,
`PipeName=atsvc`/`winreg` for remote scheduled-task/registry access - are
themselves exactly this: pre-vetted, citable spanning sets mechanic could
encode directly, the same way `windows_rpc_named_pipes` already encodes a
citable, closed set of protocol-defined literals). This is bounded,
incremental, and grounded in specific STP examples already fetched here -
not a general research program to reconstruct D3 as a live analysis tool.
What is NOT tractable as a near-term addition: a general, automated
spanning-set DISCOVERY process (finding new spanning sets mechanic doesn't
already know about, across arbitrary techniques) - that is D3's actual
research contribution and requires the kind of cross-implementation
technique corpus analysis STP's own authors did by hand; encoding
STP's *already-published* spanning sets as detectors is the tractable
piece, discovering new ones is not.

---

## Part 5 — Grounding the tier definitions, and re-checking the seam

### Grounded tier definitions (the one permitted code change: explanations, not logic)

`mechanic/priority.py`'s `RuleSignals.narrative` now cites STP v4.0
directly for each tier's explanation (see `_STP_TIER_GROUNDING` in that
module) - the sentence a `mechanic explain`/GUI reader actually sees now
states plainly which STP level(s) the tier corresponds to and, for Tool
and TTP, that STP itself splits what mechanic collapses into one tier,
with a pointer to this document. No tier assignment, `TIER_RANK` value, or
`PRIORITY_MATRIX` cell changed - only the prose explaining what a tier
means.

### Re-examining the 3 script-content rows through this mapping

The three rows that moved Tool → Artifact in the script-content fragility
fix (`RESULTS.md` Part 4): *Dump Credentials from Windows Credential
Manager With PowerShell*, *Clear PowerShell History - PowerShell*,
*AADInternals PowerShell Cmdlets Execution - PsScript*. All three: MITRE
score **2** (Level 2, Adversary-Brought Tool), event-robustness column
**A** (Application).

**Is the drop explained by the L2/L3 tool split, the columns dimension, or
an actual misclassification? Worked through directly:**

- **Columns: ruled out (Part 3).** mechanic's headline tau/rho/kappa are
  computed against the pure Analytic Robustness Score, never against a
  column-inclusive final score. All three rows carry the same column (A)
  as most of the other PowerShell rows in the sample that did NOT move
  tier - column identity does not distinguish the moved rows from the rest
  of the sample, and it isn't part of the compared statistic regardless.
- **The L2/L3 tool-provenance split is directly relevant, and resolves the
  apparent tension.** All three rules match on `ScriptBlockText` content -
  PowerShell.exe itself is a **pre-existing, native Windows component**
  (Level 3 territory by STP's own "inside boundary" framing - the
  interpreter was not brought in by the adversary). But STP scored these
  rules Level 2 ("Adversary-Brought Tool"), not Level 3. Read against
  Level 2's own definition - "observables associated with tools that are
  brought in by an adversary" - the resolution is that **the SCRIPT is the
  adversary-brought tool, not the interpreter that runs it.** The
  cmdlet/method names matched inside `ScriptBlockText` are content the
  adversary authored and brought into the environment (a script payload),
  even though it executes via a pre-existing interpreter - the same
  "outside boundary, adversary controls it entirely, can recompile /
  modify it" reasoning STP gives for Level 2 in general applies to the
  script's own text, not to PowerShell.exe. This is consistent with, and
  independently corroborates, MITRE's own free-text justification for
  these exact rows already quoted in RESULTS.md Part 4 ("everything being
  within adversary control... requires a change of the script").
- **mechanic's fix correctly demotes these below Tool tier for a reason
  that maps to Level 2's *own* evasion guidance**, not a level mechanic
  invented: STP's Level 2 evasion guidance is "renaming arguments
  (requiring recompile), editing PE headers, reconfiguring tool settings,
  recompiling tools" - all describing an adversary who must rebuild a
  *binary*. A `ScriptBlockText` match requires none of that - it is
  defeated by editing a **text file** (the script itself), with no
  recompilation, no PE-header edit, nothing outside the adversary's
  editor. This is measurably EASIER to evade than STP's own Level 2
  examples describe, which is exactly why mechanic's fix demotes it below
  Tool (Level 2/3) rather than merely re-labeling it - **mechanic's
  Artifact tier is the more STP-consistent placement here, not merely a
  more conservative one.**
- **So: this is a lossy-projection-plus-genuine-fix case, not a pure
  either/or.** The underlying bug (Tool tier from an unconditional
  cmdlet-shaped pattern match, Part 1 of the prior fix) was a real
  misclassification, confirmed independently by MITRE's own justification
  text. The residual tau-b drop after fixing it is explained by mechanic's
  Tool tier being a coarser instrument than STP's Level 2/3 split to begin
  with (Part 2) - MITRE's Level-2 score for these rows sits at the
  *boundary* mechanic's single Tool tier was never built to resolve, and
  a small number of comparably-worded MITRE rows scored inconsistently
  across Level 1 vs. 2 in the same rule family (RESULTS.md Part 4) adds
  scale-boundary noise on top. Both effects point the same direction:
  **the drop is not evidence of a new misclassification mechanic should
  chase**, and RESULTS.md's decision to re-pin the lock numbers rather
  than revert or tune the fix stands, now with a more precise account of
  *why* the correlation cost was real but small and structurally expected.

### Proposed future work (not implemented here)

1. **Tool provenance (Level 2 vs. 3) as a genuinely separate axis** -
   distinguishing "adversary-brought binary" from "pre-existing/native
   binary" would need something mechanic doesn't currently model: whether
   the matched process/tool is a known native OS component (a LOLBAS/
   GTFOBins/LOOBins entry specifically, which by definition already exists
   on the system) versus an unrecognized or ATT&CK-software-catalog name
   (more likely adversary-brought). `refdata.py` already separates these
   catalogs internally (`lolbas_names`/`gtfobins_names`/`loobins_names` vs.
   `attack_software_names`) but `all_tool_names()` merges them into one
   undifferentiated set before `is_known_tool_name` ever sees it - a
   plausible, bounded starting point for a real Tool→{Tool-native,
   Tool-brought} split, with its own dedicated validation pass, not a
   quick fix to move tau-b.
2. **TTP implementation-coverage (Level 4 vs. 5)** - would need a
   per-detector or per-protected-literal annotation of whether the
   underlying mechanism is known to be technique-invariant (Level 5,
   e.g. the DCSync RPC operations) or implementation-specific (Level 4,
   e.g. a specific GrantedAccess mask). Most of mechanic's current
   structural detectors and protected-literal categories are closer to
   Level 4 in STP's own terms (a documented mechanism for one specific
   sub-behavior) than Level 5 (invariant across the whole technique); this
   is a real, disclosed simplification worth stating even before any
   code changes toward fixing it.
3. **A small library of D3-derived structural detectors** for STP's
   already-published Level 4/5 spanning sets not yet encoded in mechanic
   (the LSASS `GrantedAccess` mask compound observable; the `atsvc`/
   `winreg` remote-service named-pipe compounds already partially covered
   by `protected_literals` but not yet paired with their STP-documented
   companion conditions) - see Part 4.
4. **Negation-combination reconciliation** - computing `R(NOT A)` for an
   ordinary exclusion filter per STP's literal rule and folding it into
   the AND/OR walk via `MIN`, while keeping `ABSENCE`'s separate promotion
   for genuine absence-based detection untouched (Part 4).

None of the above is implemented in this pass. Each would need its own
validation (a fresh STP re-run, reported honestly whether it helps or
hurts, the same discipline this pass and the script-content fix both
applied) before being adopted.
