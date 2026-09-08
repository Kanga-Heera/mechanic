# mechanic: what it is and how it works

This document explains the tool itself — what problem it solves, how its
analysis actually works internally, and what it deliberately does and does
not claim. It does not cover command syntax (`docs/cli.md`) or the web GUI
(`docs/gui.md`).

## What it is

`mechanic` is a **Sigma detection-rule maintenance triage tool**. Point it
at a Sigma rule repository and it tells you which rules need a human look
first, along two independent axes:

- **Structural fragility** — how easy is this rule for an attacker to
  evade with a trivial change (renaming a file, reordering an argument,
  substituting an equivalent value) that doesn't change their actual
  behavior at all?
- **Behavioral staleness** — has anyone actually revised this rule's
  detection logic recently, or has it sat untouched while the environment
  around it (tooling, attacker technique, telemetry) moved on?

It fills a gap alert-triage tools don't: telling an engineer which
detection *rules* — not which alerts — deserve review, at the scale of an
entire repository (thousands of rules), with a stated reason attached to
every judgment.

Everything runs locally against a git checkout: no network access, no API
key, no external service, ever.

## The analysis pipeline

```
rule files on disk
      |
      v
  discovery + fault-isolated loading   (one bad file never kills the batch)
      |
      v
  rule AST                             (selections/filters/AND/OR/NOT as a tree)
      |
      v
  structural fragility classifier -----> IOC / Artifact / Tool / TTP tier
      |
      |         git history
      |              |
      |              v
      |    mechanical-commit filtering
      |              |
      |              v
      |    organic commit counting -----> staleness band
      |              |
      |              v
      |    behavioral vs. cosmetic diff (per organic commit)
      |
      v
  priority matrix (tier x staleness band) -> review-priority label + full reasoning
```

Every step's output is kept and shown alongside the final label — nothing
is collapsed into an opaque score.

## 1. Discovery and fault-isolated loading

A naive batch load of untrusted YAML dies on the first malformed file.
`mechanic` isolates every failure to the single file (or, one level
deeper, the single validator call on one rule) that caused it, and turns
each into a structured record — a category, a message, and a fix hint —
instead of a stack trace. One broken rule in a 3,000-rule repository never
blocks analysis of the other 2,999.

Discovery itself is a small format registry: each supported format
(`sigma`, `elastic_toml`, `splunk_yaml`, `yaml_generic`) knows which file
extensions and directory conventions to look for. Only Sigma's loader goes
on to build a real AST — the other formats exist only so `staleness` (see
below) can walk their git history.

## 2. The rule AST

A successfully-loaded Sigma rule is converted into a syntax-independent
tree: named selection/filter nodes, AND/OR/NOT as structure, and an
explicit polarity (negated or not) on every leaf field/operator/value
triple. This is representation only — no scoring happens here — but it's
the substrate every downstream structural check and the fragility
classifier itself walk directly, rather than re-parsing condition strings
by hand.

## 3. Structural fragility classifier

Every scoreable rule is assigned one of four tiers, worst to best:

| Tier | Meaning |
|---|---|
| **IOC** | Matches a raw, swappable indicator (a hash, an IP address) — the adversary can change this with zero effort and zero behavior change. |
| **Artifact** | Matches a specific file/registry/network artifact of the technique — replaceable, but requires slightly more adversary effort. |
| **Tool** | Matches a specific tool or utility name — durable against variation within that tool, defeated by switching tools entirely. |
| **TTP** | Matches the actual technique/behavior, largely tool-independent — the hardest kind of match to evade. |

Classification order for each rule:

1. **Unscoreable check first.** A rule with no literal atoms at all (pure
   aggregation/statistical logic with no discrete match to classify) gets
   its own bucket with a specific reason — never a guessed tier.
2. **Four structural detectors, checked before any literal-level scoring**,
   because durability often lives in a *relationship between fields*, not
   in any single literal:
   - **FIELD_MISMATCH** — the rule fires when one field disagrees with
     another (e.g. a process's actual name doesn't match its claimed
     original filename) — the strongest known durability signal, since
     every literal involved can look completely ordinary. Promotes to TTP.
   - **ABSENCE** — the rule fires on something *not* being present (a
     null field, a missing expected value), as its own detection logic
     rather than as a filter trimming an otherwise-positive match.
   - **RARITY** — statistical/threshold logic (event count, frequency,
     first-seen, outlier) — expressed in base Sigma via correlation rules.
   - **CORRELATION** — logic spanning multiple events or a temporal
     relationship, rather than a single event's fields.
3. **Otherwise, walk the AST directly** rather than flattening it to a
   list of literals and taking the max tier. Each literal atom is
   classified individually (raw IOC, known tool name via LOLBAS/GTFOBins/
   ATT&CK reference data, a "protected" literal that structurally can't be
   trivially renamed, etc.), then **combined per MITRE's own Summiting the
   Pyramid methodology**: an AND-linked condition is only as durable as
   its *weakest* linked observable (`MIN`), since an adversary only needs
   to defeat one of them; an OR-linked condition is at least as durable as
   its *strongest* (`MAX`), since the adversary must defeat all of them.
   Getting this combination rule right (rather than a flat max over every
   literal in the rule, which over-scores the common AND-linked case)
   measurably changed the tool's external validation — see "Validation"
   below.

Negated leaves (exclusion filters) and data-source-identification fields
(`EventID`, `eventSource`, `sourcetype`, and similar — a field that says
*which platform emitted this event*, not something the adversary
independently controls) are excluded from the combination entirely, so
they can't drag an otherwise-durable, AND-linked rule down to a spuriously
low tier.

If no positive leaves survive this walk, the result is "insufficient
information" — never a forced guess.

## 4. Staleness: mechanical-commit filtering and organic churn

Raw commit counts on a rule file are a poor maintenance signal: a single
bulk reformat, schema migration, or CI housekeeping commit can touch
thousands of files at once and make every rule in the repository look
"actively maintained" on the same day. `mechanic` mines full git history
via PyDriller, then excludes any commit that touches more than a
configurable fraction of the *current* rule count (10% by default) as
mechanical, before computing anything. Every exclusion is reported, so the
cutoff is auditable rather than a hidden magic number.

What's left — organic, non-merge commits — drives staleness: days since
last organic touch, total organic commit count, and whether a rule has
*never* been organically revised since creation.

Staleness is the one axis that works on **any** rule format
(`sigma`, `elastic_toml`, `splunk_yaml`, `yaml_generic`) — git history is
real regardless of what language a rule happens to be written in.

## 5. Behavioral vs. cosmetic diff

Knowing a rule was *touched* isn't the same as knowing its *detection
logic* changed — a commit fixing a typo in the description counts
identically to one that rewrites the actual match conditions if you only
look at "was this file modified." For every organic commit, `mechanic`
classifies the change into one of:

- **behavioral** — the actual detection logic (or `logsource`, since
  e.g. `product: windows` → `product: linux` changes what the rule means
  entirely) changed.
- **semantic_metadata** — ATT&CK tags, status, or severity level changed,
  but the logic didn't. A real meaning shift, kept distinct from cosmetic
  because it isn't detection-logic maintenance.
- **cosmetic** — only title/description/author/references/whitespace/key
  order changed. No functional difference.

Classification uses the strongest method available for each pair of file
versions, each downgrading the reported confidence when it has to fall
back:

1. **AST comparison** (`high` confidence) — both versions parsed to a real
   rule object and compared structurally. Immune to reordering, quoting,
   and formatting noise. Sigma-only.
2. **Parsed-YAML key comparison** (`medium`) — used when a version won't
   construct as a valid rule object but is still valid YAML, or for
   Elastic/Splunk (which have no AST in this codebase at all — their
   detection logic lives under different key names entirely, tracked
   separately so it isn't silently misread as cosmetic).
3. **Raw text diff** (`low`) — a last-resort, line-based scan for which
   top-level key block changed, used only when a version isn't even valid
   YAML. How often this weakest method is needed is itself reported, so
   the overall signal's reliability stays visible rather than hidden
   inside an aggregate number.

If none of the three can identify what changed, the result is `unknown` —
disclosed as insufficient information, not forced into a bucket.

## 6. The priority matrix — not a combined score

Fragility tier and staleness band are looked up in a small, fixed 4×3
matrix to produce one of four priority labels (CRITICAL / HIGH / MEDIUM /
LOW). This is a **lookup table, not a formula** — the two axes are
deliberately never averaged, weighted, or otherwise fused into a single
computed number. A pre-registered correlation experiment found no
statistical association between the two axes reliable enough to justify
fusing them; every rule keeps both underlying signals, in full, next to
its label.

A rule is marked `uncertain` (label withheld) rather than given a
best-guess label whenever either axis couldn't be determined — an
unscoreable rule, or one whose creation date can't be resolved. The label
is never displayed without the tier and staleness band that produced it.

On top of the matrix, a small set of **triage hypotheses**
(`likely-repairable`, `likely-needs-telemetry-check`, `likely-retire`) are
derived from simple, arbitrary threshold combinations of the two axes —
explicitly labeled as untested candidates for a human to look into, never
as conclusions about an individual rule.

## Scope, stated plainly

Fragility, tiering, and the priority matrix are **Sigma-only** — Sigma is
the one rule format this project has a real AST for, and therefore the
only one where the structural detectors and the AND/OR combination logic
described above actually run. Pointing any of that at an Elastic or
Splunk repository is refused with a clear message rather than silently
downgraded to a lower-confidence result presented at the same visual
weight as a real one.

A separate, quarantined experiment applies a regex-approximated version of
this same classification to Elastic/Splunk text — kept working and
tested, but explicitly capped at medium confidence and excluded from the
core's own claims. See `docs/core-vs-experiment.md` and
`docs/multiformat-experimental.md` for what that is and exactly why it's
kept out.

## Validation

The fragility taxonomy is externally validated against MITRE Center for
Threat-Informed Defense's **Summiting the Pyramid (STP)** methodology —
the same construct this classifier's IOC/Artifact/Tool/TTP tiers were
designed to measure, arrived at independently. Against the Sigma-only
subset of a frozen, published STP-scored fixture: **Kendall's tau-b =
0.3117 (p = 0.0052, n = 70)** between mechanic's tier assignment and
MITRE's own human-expert robustness score.

Getting the AND/OR combination rule right (see "Structural fragility
classifier" above) was not a minor tweak — it moved this correlation from
statistical noise (tau-b ≈ -0.01, uncorrelated) to a real, significant
signal. See `RESULTS.md` for the full investigation, every intermediate
number, and every disclosed limitation — not just the headline figure.

Staleness reproduces a prior investigation's cited figures across five
real repositories, independent of rule format.

## What this tool deliberately does not claim

- No combined fragility+staleness score — see "The priority matrix" above.
- No ATT&CK technique-coverage judgment, and no claim to catch every
  possible evasion.
- No verdict on whether an individual rule is "good" or "bad" — every
  output is framed as "review this," never as a conclusion.
- No automated rule repair (an earlier experiment explored this; it has
  been removed from the codebase — see `README.md`'s historical note).

## Further reading

- `README.md` — the project pitch, full validation writeup, and prior art.
- `RESULTS.md` — every experiment, every number, every disclosed limitation.
- `docs/core-vs-experiment.md` — the Sigma-only scoping decision and how
  it's enforced.
- `docs/cli.md` / `docs/gui.md` — how to actually run this.
