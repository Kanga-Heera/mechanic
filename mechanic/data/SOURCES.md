# Reference data sources (Stage 2, Part 2)

v1's fragility classifier used a hand-curated, Windows-only tool-name list
and hand-curated protected-literal list. Both were identified as root causes
of its poor agreement (kappa 0.412) with the LLM-generated development-set
labels used to evaluate it (see RESULTS.md for the disclosure that these
are not human ground truth). Stage 2
replaces them with lists *derived from existing external sources*, fetched
once and checked in as static, documented data rather than fetched at
runtime (mechanic must stay deterministic and offline-reproducible).

| File | Source | Fetched | Count | Notes |
|---|---|---|---|---|
| `toolnames_lolbas.json` | [LOLBAS project](https://lolbas-project.github.io/) API dump: `https://lolbas-project.github.io/api/lolbas.json` | 2026-08-21 | 240 | Windows living-off-the-land binaries. `Name` field only (e.g. `"AddinUtil.exe"`); descriptions/commands/MITRE mappings discarded, only the binary name matters for tier promotion. |
| `toolnames_gtfobins.json` | [GTFOBins](https://gtfobins.github.io/) repo directory listing: `https://api.github.com/repos/GTFOBins/GTFOBins.github.io/contents/_gtfobins` | 2026-08-21 | 478 | Linux/Unix binary names, one file per binary in the repo's `_gtfobins/` directory - the directory listing IS the name list, no per-binary content needed. |
| `toolnames_loobins.json` | [LOOBins](https://www.loobins.io/) (LOLBAS-style project for macOS) repo directory listing: `https://api.github.com/repos/infosecB/LOOBins/contents/LOOBins` | 2026-08-21 | 62 | macOS-specific binaries GTFOBins doesn't cover well (`launchctl`, `osascript`, `plutil`, `dscl`, ...). Added specifically because v1's LLM-labelling round found macOS rules (e.g. `Suspicious PlistBuddy Usage`) among the disagreements the Windows-only list caused. |
| `attack_software.json` | [MITRE ATT&CK](https://attack.mitre.org/) Enterprise STIX bundle: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | 2026-08-21 | 825 | `malware` (733) + `tool` (95) STIX objects, minus 3 revoked/deprecated. Each entry keeps `id` (Sxxxx), `type`, `name`, `aliases` (`x_mitre_aliases`). This is the named-attacker-tool vocabulary (Mimikatz, Rubeus, PsExec, Cobalt Strike, ...) - distinct from LOLBAS/GTFOBins, which are *built-in OS* binaries, not attacker tooling. |

**Regenerating these files**: `scratchpad/build_toolnames.py` and
`scratchpad/extract_attack_software.py` (repo-external, not shipped) contain
the exact extraction logic against the raw downloads. Re-running means
re-fetching the three URLs above and re-running both scripts; the file counts
above should be treated as a point-in-time snapshot, not something the tool
re-derives itself at runtime.

**What this list is NOT**: it does not include cloud-provider CLI tools
(`aws`, `az`, `gcloud`), which are common in legitimate automation and were
deliberately left out of the "Tool" tier promotion - a rule keying on `aws`
alone is closer to noise than signal. It also does not include generic
interpreters' *language* names as bare tokens (e.g. matching on the word
"python" as a natural-language word rather than a process name) - matching
is always against a field recognizable as a process/image/parent-image name,
never free text.

**Known, disclosed gap**: `PlistBuddy` (used in Splunk's `Suspicious
PlistBuddy Usage` rule, one of the 90 LLM-labelled rules) is in none of the
four sources above - it's a narrow Xcode developer utility, not cataloged by
GTFOBins, LOOBins, or LOLBAS's macOS-adjacent entries as of the fetch date.
Rather than hand-add it (exactly the anti-pattern v1 was criticized for),
this is left as an honest, visible coverage gap - see RESULTS.md's re-run of
the 30-rule LLM-labelling round for whether it still causes a disagreement.

## Protected-literal category provenance

Unlike the tool-name lists above, the protected-literal categories in
`protected_literals.py` aren't a single fetched dataset each - they're regex
patterns over a specific external, citable definition of an OS/protocol
mechanism. Full rationale for each lives in that module's docstring; this
table is the same provenance discipline applied to categories that are
*derived from a document* rather than *fetched as a file*:

| Category | External definition it's derived from |
|---|---|
| `windows_autorun_registry` | Microsoft-documented autorun locations (Run/RunOnce/RunServices, Winlogon Userinit/Shell/Notify, IFEO Debugger value, AppInit_DLLs, LSA package lists, Safe Boot keys). |
| `windows_rpc_named_pipes` | [MS-RPCE] well-known named-pipe endpoints, cross-checked against SigmaHQ's own `win_security_lm_namedpipe.yml` false-positive list (independent convergent evidence, not the source itself). |
| `windows_well_known_sids` | Microsoft Learn, "Well-known security identifiers in Windows operating systems." |
| `ad_schema_attributes` | The Active Directory/LDAP schema itself (`servicePrincipalName`, `userAccountControl`, `adminCount`, ... are schema-defined attribute names, not conventions). |
| `linux_persistence_paths` | `crontab(5)`, `systemd.unit(5)`, `ld.so(8)`, `sudoers(5)` man pages. |
| `macos_persistence_paths` | `launchd(8)` / `launchd.plist(5)` man pages. |
| `windows_security_subsystem_config` | Microsoft Learn, "IE security zones and protocol restrictions registry entries" (ZoneMap); Terminal Services/RDP registry layout as documented for `WinStations\RDP-Tcp` (auth policy) and `Terminal Server Client\Servers` (connection history) - both same-prefixed, same Microsoft-defined registry area. Added after Part 2c's re-validation found four separate disagreements sharing this one root cause - see RESULTS.md. |
