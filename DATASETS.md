# Dataset and source registry

Every external dataset, corpus, catalogue, and tool this project depends on,
with exact provenance. All URLs below were checked to resolve on
2026-08-22. Every entry that can be commit- or tag-pinned is pinned that
way rather than by date — a git repository's state "as of a date" is not
reproducible without knowing the exact commit; a date alone lets two people
running the same command get two different answers.

Where an entry's pin differs from what an earlier snapshot (`SOURCES.md`)
recorded by date only, that is called out explicitly rather than silently
corrected.

## Rule corpora

| Repo | URL | What it is | Used for | Licence | Pin |
|---|---|---|---|---|---|
| SigmaHQ/sigma | https://github.com/SigmaHQ/sigma | The reference Sigma rule corpus. | Primary Sigma-format target repo for staleness, semantic diff, and fragility classification (Parts 0-3). | Detection Rule License (DRL) 1.1 (GitHub reports `NOASSERTION`; the repo's own `LICENSE.Detection.Rules.md` is DRL 1.1, not a standard OSI licence — attribution/no-sale terms, not permissive). | commit `da9bb07d642a2826e89702445d32c795209ec108` (local clone HEAD, 2026-08-22) |
| elastic/detection-rules | https://github.com/elastic/detection-rules | Elastic's own detection rules (TOML, EQL/KQL). | Second target format for staleness/fragility (text-path classifier, no AST). | Elastic License 2.0 (`NOASSERTION` on GitHub's detector; repo's `LICENSE.txt` is Elastic License 2.0). | commit `a9208f465f486bf87dd614c463eb5e790d559a52` (local clone HEAD, 2026-08-22) |
| splunk/security_content | https://github.com/splunk/security_content | Splunk's detection content (YAML + SPL). | Third target format for staleness/fragility (text-path classifier). | Apache-2.0 | commit `0d6f6bfb28bbd8f1a8ac059864178f15d66b72e2` (local clone HEAD, 2026-08-22) |
| joesecurity/sigma-rules | https://github.com/joesecurity/sigma-rules | Joe Security's malware-sandbox-derived Sigma rules. | STP `stp`-tag adoption census (Task B). | GPL-3.0 | commit `cb91be06c8c95ce63aa9aa5006a7835678136a96` |
| mdecrevoisier/SIGMA-detection-rules | https://github.com/mdecrevoisier/SIGMA-detection-rules | ~350+ community Sigma rules mapped to ATT&CK. | STP tag adoption census. | CC0-1.0 | commit `d61408af8769c74c96296b7ccc92d4bc3abb15af` |
| Yamato-Security/hayabusa-rules | https://github.com/Yamato-Security/hayabusa-rules | Curated, de-abstracted Sigma-derivative rules for the Hayabusa/Velociraptor engines. Per its own README, built FROM upstream SigmaHQ (subset + logsource de-abstraction), not an independent corpus. | STP tag adoption census - used to confirm inherited-vs-independent tag provenance. Detection Rule License (DRL) 1.1 (`LICENSE.md`, same licence family as SigmaHQ itself; GitHub's detector reports `NOASSERTION`). | commit at time of scan: `efb0e9a3f5504989d3d4581fd8d2db384ae998dc` |
| tsale/Sigma_rules | https://github.com/tsale/Sigma_rules | Personal community Sigma rule collection. | STP tag adoption census. | GPL-3.0 | local clone (`thirdparty/tsale-sigma-rules`), scanned 2026-08-22 |
| The-DFIR-Report/Sigma-Rules | https://github.com/The-DFIR-Report/Sigma-Rules | Rules generated from The DFIR Report's published incident investigations. | STP tag adoption census. Note: not `TheDFIRReport/rules` (that repo/org spelling does not exist) - confirmed the correct org is `The-DFIR-Report` (hyphenated) and the rules repo is named `Sigma-Rules`. | GPL-3.0 | local clone (`thirdparty/dfir-report-sigma-rules`), scanned 2026-08-22 |
| magicsword-io/LOLDrivers | https://github.com/magicsword-io/LOLDrivers | Catalogue of known vulnerable/malicious Windows drivers. Also ships supplementary Sigma/Yara/ClamAV/Sysmon detections under `detections/sigma/` - not primarily a rule corpus, but does contain scoreable Sigma rules, and is the source of the one non-SigmaHQ, non-Elastic, non-Splunk permalink in MITRE's own ScoredAnalytics CSV. | STP tag adoption census (`detections/sigma/` subtree only). | Apache-2.0 | local clone, scanned 2026-08-22. Note: full clone includes git-lfs-tracked binary driver samples that failed checkout in this environment (`smudge filter lfs failed` on one `.bin` file) - irrelevant to the `detections/sigma/` YAML content, which checked out and read cleanly. |

## Ground truth and validation

| Repo | URL | What it is | Used for | Licence | Pin |
|---|---|---|---|---|---|
| center-for-threat-informed-defense/summiting-the-pyramid | https://github.com/center-for-threat-informed-defense/summiting-the-pyramid | MITRE Center for Threat-Informed Defense's "Summiting the Pyramid" (STP) methodology: scores detection analytics on a 1-5 analytic-robustness scale plus an Application/User/Kernel event-robustness dimension. Formally part of the Sigma specification via the `stp` tag namespace. | External validation of mechanic's fragility tiers (rank correlation against STP-scored rules); source of the `stp`-tag census (Task B). | Apache-2.0 | tag `v3.0.0` (commit `e133cbf1b566db65a7306e015a0925374b0240d9`, tagged 2025-05-10) is current at time of writing; changelog additionally documents an untagged "Version 4.0" (2026-02-20) website/content update with no corresponding git tag as of 2026-08-22 |
| — ScoredAnalytics CSV (in above repo) | https://github.com/center-for-threat-informed-defense/summiting-the-pyramid/blob/main/docs/analytics/ScoredAnalytics_05062025.csv | MITRE's own STP-scored analytics: 92 data rows (93 lines incl. header), 81 pointing at SigmaHQ permalinks, 1 each at LOLDrivers/Elastic/Splunk, 7 empty, 1 "Further Research Required". Of the 81 SigmaHQ-linked rows, 60 resolve directly to a file at the exact commit-pinned path today; the remaining 21 require rename-chain resolution (not yet re-verified against the current rename map - see RESULTS.md). | Primary external ground truth for STP rank-correlation validation. | Apache-2.0 (repo licence) | filename is exact and self-dated: `ScoredAnalytics_05062025.csv`, byte-identical (md5 `3ba7108f7b77d2ce2cf8743097ecfda0`) to the copy already cached at `scratchpad/refdata/stp_scored_analytics.csv`. **Note:** the repo's own `README.md` still links to the older `ScoredAnalytics_12062024.csv` (87 data rows) under "Getting Involved" - only `docs/analytics/index.rst` (the actual methodology page) links the current 05062025 file. A reader following only the top-level README would retrieve the stale, smaller CSV; this project uses the newer one, referenced from the methodology page. |
| fkie-cad/amides | https://github.com/fkie-cad/amides | Uetz, Herzog, Hackländer, Schwarz, Henze, "You Cannot Escape Me: Detecting Evasions of SIEM Rules in Enterprise Networks," USENIX Security 2024 (Distinguished Artifact Award). ML-based system estimating which SIEM rule an evasive event was targeting. | Referenced as prior art (evasion-testing category) in README's "Prior art" section; not currently a runtime dependency. | GPL-3.0 | The repo's own README states plainly: "Due to ethical concerns, most of the evasions are not available in this repository." It does **not** state the full set is available on request - that claim was in an earlier draft of this document and is not supported by the primary source, so it has been removed. |

## Tool and binary catalogues

| File / source | Canonical URL | What it is | Used for | Licence | Pin |
|---|---|---|---|---|---|
| `toolnames_lolbas.json` | https://lolbas-project.github.io/api/lolbas.json (generated; source repo: https://github.com/LOLBAS-Project/LOLBAS) | Windows living-off-the-land binaries. | Tool-tier promotion in the fragility classifier (Windows). | CC0-1.0 (LOLBAS-Project/LOLBAS repo licence) | **Was date-pinned only** (`2026-08-21`, 240 entries). The `api/lolbas.json` endpoint is a GitHub-Pages-generated artifact with no git history of its own - it is built from the source repo's `yml/` tree, not checked into any branch. Closest verifiable proxy: source repo commit `9c5e3841081cac342e7603093253cb51512c8369` (master HEAD at 2026-08-21T20:34:35Z, "Add Applaunch.yml (#519)"). Re-fetching the *live* endpoint today returns 241 entries (one more than recorded) - direct, measured evidence that date-only pinning of a generated artifact drifts, which is exactly why this entry needed fixing. Future re-derivation should fetch source YAML at a pinned commit and rebuild, not hit the live API endpoint. |
| `toolnames_gtfobins.json` | https://github.com/GTFOBins/GTFOBins.github.io (`_gtfobins/` directory listing) | Linux/Unix GTFOBins binary names. | Tool-tier promotion (Linux). | GPL-3.0 | commit `acd524623f9c` (2026-05-27T12:01:45Z) - directory listing at this commit returns exactly 478 entries, matching the recorded count exactly. Repo has had no further commits since, so this pin is also simply "current HEAD." |
| `toolnames_loobins.json` | https://github.com/infosecB/LOOBins (`LOOBins/` directory listing) | macOS LOLBAS-equivalent binary names. | Tool-tier promotion (macOS). | GPL-3.0 | commit `2843d33291c8` (2026-07-23T12:52:11Z) - directory listing at this commit returns exactly 62 entries, matching the recorded count exactly. |
| `attack_software.json` | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json | MITRE ATT&CK Enterprise STIX bundle; `malware` + `tool` objects. | Named-attacker-tool vocabulary (Mimikatz, Rubeus, Cobalt Strike, ...) for tool-tier promotion. | Apache-2.0 (mitre-attack org's standard licence for STIX data) | tag `v19.2` (commit `6cda5ad8462c`, "feat: add ATT&CK v19.2", 2026-08-05) - this is also the `master` branch's current HEAD, so `master` and `v19.2` currently coincide. Future re-derivation should pin to the `v19.2` release asset or this commit explicitly, not `master`, since `master` will move again at the next ATT&CK release. |

## Stage 3 dependencies

| Repo | URL | What it is | Licence | Pin |
|---|---|---|---|---|
| wagga40/Zircolite | https://github.com/wagga40/Zircolite | Standalone Sigma-based detection tool for EVTX/auditd/Sysmon-for-Linux logs. | NOASSERTION on GitHub; repo's own LICENSE is MIT. | latest tag `v3.8.1`; not yet vendored into this project - listed for Stage 3 planning only. |
| sbousseaden/EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | Sample EVTX files exercising specific attack techniques, for detection testing. | GPL-3.0 | repo has not been pushed to since 2023-01-24; not yet vendored - listed for Stage 3 planning only. |

## Libraries

| Package | URL | Used for | Licence | Pin (as actually installed in this project's venv) |
|---|---|---|---|---|
| pySigma | https://github.com/SigmaHQ/pySigma | Sigma rule parsing/AST construction (`ast_repr.py`, `loader.py`). | LGPL-2.1 | **1.5.0** (`pip show pysigma` in `D:\sigma-research\venv`); `pyproject.toml` declares `pysigma>=1.5.0`. This is also the latest upstream tag (`v1.5.0`) as of 2026-08-22 - installed version and upstream latest currently coincide. |
| PyDriller | https://github.com/ishepard/pydriller | Git history mining (`churn.py`, `semantic_diff.py`). | Apache-2.0 | **2.10** (`pip show pydriller`); `pyproject.toml` declares `pydriller>=2.6`. |

## Specifications

| Spec | URL | What it is | Licence | Pin |
|---|---|---|---|---|
| SigmaHQ/sigma-specification | https://github.com/SigmaHQ/sigma-specification | The Sigma rule format specification, including the tag appendix (`specification/sigma-appendix-tags.md`) that formally defines the `stp` namespace. | NOASSERTION on GitHub; repo carries a CC-BY-4.0-style attribution notice in its own docs, not a SPDX-detected licence. | The `stp` namespace was added in commit `0c857d07da0e71eaaab2d667b3cce6f2c8469578` (2025-09-12, author `frack113`, "Release/2.1.0 (#183)") - i.e. roughly two years after STP methodology v1.0's own release (2023-09-14), the tag entered the formal Sigma spec only in September 2025. Current repo HEAD otherwise unpinned (documentation reference only, not vendored). |

## Corrections made while compiling this registry

- `TheDFIRReport/rules` (as might naively be guessed) does not exist. The
  correct repository is `The-DFIR-Report/Sigma-Rules` (hyphenated org name).
  Verified via `gh api repos/The-DFIR-Report/Sigma-Rules` (200, non-archived,
  GPL-3.0, last pushed 2026-07-08).
- AMIDES's "evasion set available on request" framing is not supported by
  the primary source; the README only states evasions are withheld "due to
  ethical concerns," with no request mechanism described. Corrected above.
- Three of the four tool-name catalogues (`SOURCES.md`) were pinned by
  fetch date only. Two (GTFOBins, LOOBins) were re-verified against a
  specific commit and their recorded counts matched exactly. The third
  (LOLBAS) could not be pinned exactly because its `api.json` is a
  generated artifact with no independent git history; the closest
  reproducible proxy (source-repo commit) is documented above, along with
  measured evidence (241 vs. 240) that the live endpoint has already
  drifted by one entry since the original fetch - this is reported as a
  limitation, not silently resolved.
- The wider-ecosystem search for additional Sigma corpora (GitHub topic
  search on `sigma` and `sigma-rules`, sorted by star count) surfaced no
  corpus of comparable scale or maintenance status to the ones already
  listed above; the largest unlisted candidate found,
  `mdecrevoisier/SIGMA-detection-rules`, was already in scope. One small,
  unmaintained personal repository (`P4T12ICK/Sigma-Rule-Repository`, 93
  stars, last pushed 2020, predating STP's 2023 release entirely) was
  checked for completeness and found to carry no `stp` tags, as expected
  given its age.
