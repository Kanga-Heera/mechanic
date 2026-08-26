# STP adoption census, with full provenance

**Context.** A claim was forming that public STP adoption is near-zero. The
underlying argument is sound but earlier phrasing ("~90-rule public corpus",
"three years later") was imprecise. This document sources, dates, and makes
reproducible every figure behind that claim, across every Sigma-format
repository this project could locate and obtain - not just SigmaHQ.

All figures below were measured on **2026-08-22** against the exact commits
listed. Re-running the same scan against a later commit will produce
different, larger numbers as new rules and tags are added - that is
expected, not a discrepancy.

## Method

`stp` tags follow the format confirmed against `SigmaHQ/sigma-specification`
(`specification/sigma-appendix-tags.md`): `stp.X` (analytic-robustness only,
`X` in 1-5) or `stp.XY` (complete score, `Y` in `{a,u,k}` for
Application/User-mode/Kernel-mode). Census regex: `^stp\.(\d)([auk])?$`,
case-insensitive, matched against each rule's `tags:` list (Sigma/native
YAML) or, for Elastic/Splunk, checked against every plausible tag-bearing
field before concluding absence (see below - this was not assumed).

Every hit was confirmed by direct file inspection, not trusted from a raw
substring match. An unanchored `grep "stp\."` was run first as a coarse
pass and produced **false positives** in Elastic (12 files) and Splunk (7
files) - re-run with the anchored pattern `stp\.[0-9]`, both dropped to
**zero**. This is reported because it is exactly the kind of error a
sloppier census would have shipped as a false "STP tags found in
commercial detection content" result.

## B1: repository-by-repository results

| Repository | Format | Rule files scanned | `stp`-tagged | % | Commit/pin scanned |
|---|---|---:|---:|---:|---|
| SigmaHQ/sigma | Sigma YAML | 3,783 | **6** | 0.16% | `da9bb07d642a2826e89702445d32c795209ec108` |
| Yamato-Security/hayabusa-rules | Sigma YAML (derivative) | 4,774 (`sigma/` tree only; excludes the separate `hayabusa/` native-format tree, which is not Sigma) | 9 (raw file count) | 0.19% raw | `efb0e9a3f5504989d3d4581fd8d2db384ae998dc` |
| joesecurity/sigma-rules | Sigma YAML | 119 | 0 | 0% | `cb91be06c8c95ce63aa9aa5006a7835678136a96` |
| mdecrevoisier/SIGMA-detection-rules | Sigma YAML (`.yaml`) | 351 | 0 | 0% | `d61408af8769c74c96296b7ccc92d4bc3abb15af` |
| tsale/Sigma_rules | Sigma YAML | 52 | 0 | 0% | local clone, scanned 2026-08-22 |
| The-DFIR-Report/Sigma-Rules | Sigma YAML | **0** (see note) | 0 | n/a | local clone, scanned 2026-08-22; confirmed against live GitHub API contents listing |
| magicsword-io/LOLDrivers | Sigma YAML (`detections/sigma/` subtree) | 6 | 0 | 0% | local clone, scanned 2026-08-22 |
| P4T12ICK/Sigma-Rule-Repository *(found via wider search, not in original candidate list)* | Sigma YAML | 12 | 0 | 0% | local clone, scanned 2026-08-22 |
| elastic/detection-rules | TOML (non-Sigma) | 2,061 | 0 (confirmed after ruling out a false-positive substring match) | 0% | `a9208f465f486bf87dd614c463eb5e790d559a52` |
| splunk/security_content | YAML (non-Sigma) | 2,144 | 0 (confirmed after ruling out a false-positive substring match) | 0% | `0d6f6bfb28bbd8f1a8ac059864178f15d66b72e2` |
| **Combined Sigma-format total** | | **9,097** | **15 raw / 6 distinct** | **0.16%** | |

**The-DFIR-Report/Sigma-Rules is not a populated corpus.** Its live GitHub
contents listing (checked directly via the API, independent of any local
clone) returns exactly two files: `LICENSE` and `README.md`. The README
states: *"Rules generated from our public reports are now directly
contributed to the SigmaHQ project... We also have a private Sigma ruleset
for customers."* This repository was deliberately retired in favor of (a)
upstreaming into SigmaHQ directly - meaning any DFIR-Report-originated
rules are already inside the SigmaHQ row above, not a separate population
- and (b) a private, paid ruleset that is by definition not observable from
public data. This is direct, primary-source evidence for the "absence of
public tags is not evidence of absence of scoring" caveat in B3 below, not
just a hypothetical.

**hayabusa-rules' 9 hits are not independent adoption.** hayabusa-rules'
own README states it is built by taking a subset of upstream SigmaHQ rules
and de-abstracting their `logsource` field into concrete Windows event
channels - "Compared with the upstream Sigma repository, these rules:
include only rules that most Sigma-native tools can parse; de-abstract the
`logsource` field...; add converted `process_creation` and `registry`
rules." Its 9 `stp`-tagged files collapse to exactly the same **6 distinct
rule titles** as SigmaHQ's own 6 tagged rules (three of the six appear
twice - once under `sigma/builtin/`, once under `sigma/sysmon/` - because
hayabusa's de-abstraction step produces both a builtin-log and a
Sysmon-log variant of the same source rule, both inheriting the same `stp`
tag). Verified by direct filename/title comparison, not inferred:

| SigmaHQ source rule (tag) | Appears in hayabusa-rules as |
|---|---|
| `win_security_access_token_abuse.yml` (`stp.4u`) | 1 copy |
| `pipe_created_hktl_cobaltstrike_susp_pipe_patterns.yml` (`stp.1k`) | 1 copy |
| `posh_ps_get_acl_service.yml` (`stp.2a`) | 1 copy |
| `proc_creation_win_hktl_cobaltstrike_bloopers_cmd.yml` (`stp.1u`) | 2 copies (builtin + sysmon) |
| `proc_creation_win_pua_adfind_susp_usage.yml` (`stp.1u`) | 2 copies (builtin + sysmon) |
| `proc_creation_win_schtasks_creation.yml` (`stp.1u`) | 2 copies (builtin + sysmon) |

So the true count of **independently-tagged** Sigma-format repositories in
this census is **one** (SigmaHQ itself), and the true count of distinct
`stp`-tagged rules across all 9,097 files scanned, across every repository
found, is **6** - not 15.

**Wider-ecosystem search.** GitHub topic search on `sigma` and
`sigma-rules`, sorted by star count, was run to check whether the
candidate list above was missing any corpus of comparable scale. It
surfaced nothing not already in scope; the largest unlisted candidate
(`mdecrevoisier/SIGMA-detection-rules`, 444 stars) was already included.
One small additional repository, `P4T12ICK/Sigma-Rule-Repository` (93
stars, last pushed 2020-06-18 - predating STP's 2023-09-14 methodology
release entirely), was checked for completeness given it surfaced in an
earlier phase of this project's own research; it carries no `stp` tags, as
expected for a repository that predates the tag's existence.

## B2: precise figures

**STP release history**, sourced from the project's own changelog
(`docs/changelog.rst` in `center-for-threat-informed-defense/summiting-the-pyramid`),
not a blog paraphrase:

| Version | Changelog-stated date | Nearest git tag/commit | Tag/commit date | Content |
|---|---|---|---|---|
| 1.0 | September 14, 2023 | `v1.0.0` | 2023-09-13T23:12:20Z (tag) | "The initial release... model, methodology, definitions, and worked examples." |
| 2.0 | December 17, 2024 | `v2.0.0` (lightweight tag, no tag message) | 2024-12-13T14:06:35Z (commit) | Defines "robustness," quantification/improvement; adds network-detection scoring elements. |
| 3.0 | May 8, 2025 | `v3.0.0` | 2025-05-10T01:29:26Z (tag) | "Ambiguous Techniques" research. |
| 4.0 | February 20, 2026 | *(no git tag exists for this version as of 2026-08-22)* | - | Site refactor; Telemetry Strategy & Readiness content; Telemetry Confidence (TC) scoring methodology, "shared our methodology for automating the process using AI/LLM augmentation." |

Note the small (3-5 day) gaps between each changelog-stated date and its
corresponding git tag/commit timestamp - both are reported rather than
silently reconciled to one number, since the discrepancy itself is a fact
about how this project manages releases (the changelog entry appears to
predate the version-bump commit slightly, or vice versa; not investigated
further as it does not change any conclusion here).

**Elapsed time**: from STP v1.0's changelog-stated release (2023-09-14) to
this census (2026-08-22) is **1,073 days** (≈2.94 years, or 2 years 11
months 8 days), computed directly (`date(2026,8,22) - date(2023,9,14)`),
not rounded to "three years."

**`stp` tag's entry into the formal Sigma specification**: commit
`0c857d07da0e71eaaab2d667b3cce6f2c8469578`, authored by `frack113`,
2025-09-12, message "Release/2.1.0 (#183)", in
`SigmaHQ/sigma-specification`. Found via `git log -S"Namespace: stp"`
(pickaxe search - finds the commit that introduced the literal string) on
`specification/sigma-appendix-tags.md`. The tag existed as an *informal*
convention in SigmaHQ rules for some time before formal specification
(the SigmaHQ rules bearing `stp` tags today were not all authored after
September 2025), but did not become part of the citable, versioned Sigma
specification until roughly **two years** after STP's own v1.0 release.

**MITRE ScoredAnalytics CSV**: two versions exist in the live repository,
not one:

| Filename | Referenced from | Data rows | Retrieved |
|---|---|---:|---|
| `ScoredAnalytics_12062024.csv` | `README.md` ("Getting Involved" table) | 87 | 2026-08-22 |
| `ScoredAnalytics_05062025.csv` | `docs/analytics/index.rst` (the actual methodology page) | 92 | 2026-08-22, md5 `3ba7108f7b77d2ce2cf8743097ecfda0`, byte-identical to this project's already-cached `scratchpad/refdata/stp_scored_analytics.csv` |

**The repository's own top-level README still links the older, smaller
CSV.** A reader following only the README - not the methodology docs -
would retrieve the stale 87-row file. This project's STP validation work
uses the newer, 92-row file, matching the methodology page rather than the
README.

*(RESULTS.md's STP validation section refers to "90 non-header rows" from
this same file - not a discrepancy: 2 of these 92 raw rows are entirely
blank spreadsheet artifacts, dropped before RESULTS.md's own count begins.
See that section for the full 92 -> 90 -> 88 -> 78 chain.)*

Of the 92 rows in the current CSV: **81** link to SigmaHQ permalinks, 1
each to magicsword-io/LOLDrivers, elastic/detection-rules, and
splunk/security_content, 7 have no permalink at all, and 1 reads "Further
Research Required" instead of a URL. Of the 81 SigmaHQ-linked rows, **79**
resolve via `git show <pinned-commit>:<path>` against the exact historical
commit each permalink names (the correct method - a plain current-HEAD
path-existence check is the wrong tool here and understates resolution,
since it fails on any file SigmaHQ has since renamed even though the
historical blob is still perfectly retrievable; an initial naive
HEAD-existence check run while compiling this census found only 60/81 and
was discarded in favor of this git-show-based re-check once the
discrepancy was noticed). The 2 genuine failures are both rows whose
permalink points at `master` rather than a pinned commit hash (`CobaltStrike
Named Pipe Patterns` and `Eventlog Cleared`) - for those two, no exact
historical blob is addressable at all, and the path no longer exists at
current HEAD either; resolving them would require rename-chain inference
with no commit anchor to start from, which is a materially weaker claim
than the git-show resolution the other 79 get for free, so they are left
unresolved rather than guessed at.

**CrowdStrike's "over 50 analytics" figure**, exact quote from
https://www.crowdstrike.com/en-us/blog/crowdstrike-joins-mitre-engenuity-summiting-the-pyramid/,
confirmed against the raw page HTML directly (not a paraphrase or a search
summary):

> "The team scored and placed over 50 analytics from the public Sigma
> rules repository, leveraging the Sigma rules to showcase the Pyramid of
> Pain against publicly accessible analytics as a way of demonstrating its
> value. They improved four analytics based on observables placed in a
> robustness table (and submitted to Sigma) and created an additional
> three analytics to be submitted to Sigma."

**This figure's date could not be precisely sourced, and that is reported
rather than guessed.** The page's `dateModified` metadata reads
`2025-03-05T16:31Z`. The earliest Wayback Machine capture of this URL is
`2024-10-09`. A first automated extraction attempt returned
"September 14, 2023" (the same day as STP's own v1.0 release) as the
publication date; this could **not** be corroborated by page metadata,
Wayback Machine history, or any other primary source, and is therefore
explicitly **not** used. What can be said with confidence: CrowdStrike
scored "over 50" analytics and explicitly contributed only **7** of them
back toward Sigma (4 improved existing + 3 new) - meaning this figure
describes CrowdStrike's *internal* scoring effort, of which only a small,
specific fraction was ever intended for publication, which is itself
material to interpreting why so few CrowdStrike-attributable tags appear
in the public SigmaHQ corpus today.

**MITRE's public request for community-contributed scores**, exact
wording from `README.md` in the summiting-the-pyramid repository, under
"Getting Involved":

> "Create your own analytics and observables. We encourage you to use the
> methodology to work through analytics or observables and send your
> results to [SigmaHQ](https://github.com/SigmaHQ/sigma) that we can make
> them available to the entire community."

## B3: the claim, stated with its limits

> Public, community-contributed STP scoring in open rule repositories is
> near-zero: **6 of 9,097** Sigma-format rule files across **8**
> Sigma-format repositories carry a genuine, independently-authored `stp`
> tag (one repository, hayabusa-rules, carries 9 additional tagged files
> that are confirmed downstream copies of the same 6 SigmaHQ rules, not
> independent tagging). Two further, non-Sigma-format repositories
> (Elastic, Splunk - included for completeness since the task explicitly
> asked "check anyway") were also scanned and confirmed at zero, after
> ruling out false-positive substring matches. The largest publicly
> available set of STP-scored analytics is
> MITRE's own ScoredAnalytics CSV (92 rows, dated `05062025`, i.e. 2025-05-06).
> This measures published, public scoring. It does not, and cannot, measure
> internal enterprise practice - The DFIR Report's own README, encountered
> directly in this census, states they maintain "a private Sigma ruleset
> for customers" alongside their (now-empty) public repository, which is
> direct evidence that at least one professional team scores/maintains
> rules outside public view, exactly the blind spot this claim must not
> paper over.

**Context, not counted as evidence against the claim above:** STP is
listed **first** among six lines of effort in CTID's own 2026 roadmap
Executive Summary (https://ctid.mitre.org/roadmap/, retrieved 2026-08-22):
*"Summiting the Pyramid: Increase detection robustness by advancing
methodologies, scoring, and telemetry analysis that raise adversary costs
and make evasion measurably harder."* STP v4.0's changelog (2026-02-20)
independently describes MITRE's own move toward **automating** Telemetry
Confidence scoring via AI/LLM augmentation. Read together: the methodology
itself is active, well-supported, and MITRE is already moving toward
automation on an adjacent scoring axis - the gap this census documents is
specifically in manual, public, community application at scale, not in
the project's institutional health or future direction.

## Corrections and disclosures made while compiling this census

- An unanchored grep produced false-positive `stp.` matches in Elastic (12)
  and Splunk (7); the anchored pattern confirmed both are genuinely zero.
  Reported rather than silently dropped, per this project's standing
  disclosure discipline.
- `The-DFIR-Report/Sigma-Rules` was assumed, going in, to be a populated
  rule corpus (it is named and described as one). Direct API inspection
  found it contains only a LICENSE and README - a materially different,
  and more informative, finding than a routine "0 tags."
- hayabusa-rules' raw 9-file hit count would overstate independent adoption
  by exactly 3x if reported without the title cross-reference against
  SigmaHQ's own 6 tagged rules; both the raw count and the corrected
  distinct-rule count are reported above, not just the smaller one.
- The CrowdStrike blog's publication date could not be verified and is
  reported as unverifiable rather than asserted. A prior automated
  extraction attempt suggested a specific date (matching STP's own release
  day, which made it superficially plausible) that could not be
  corroborated and was discarded rather than used.
- The 21 unresolved SigmaHQ CSV permalinks are reported as unresolved, not
  assumed resolved and not assumed lost.
