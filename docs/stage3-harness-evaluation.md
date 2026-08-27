# Stage 3 harness evaluation: does RSigma replace Zircolite?

**Status:** Investigation only. No mechanic code was changed. Stage 3 was not built.
**Date:** 2026-08-27
**Tool evaluated:** [timescale/rsigma](https://github.com/timescale/rsigma), pinned to **v0.21.0** (released 2026-08-05, the latest tag at time of writing). Docs at [rsigma.io](https://rsigma.io/).

---

## Recommendation: **B — RSigma partly covers Stage 3's harness need. Use it, but plan for a pipeline-authoring step Zircolite doesn't require.**

RSigma's `engine eval` is a genuine, standalone, per-event fire/no-fire evaluator — it is not locked inside the `rule tune` workflow. That was the make-or-break question (Task 1) and it resolves in RSigma's favor. It was proven live on a hand-verified known-answer case (Task 4), not just asserted from docs.

But the live test also surfaced a real cost that the docs don't foreground: RSigma's EVTX ingestion does **not** auto-flatten `Event.System.*` / `Event.EventData.*` into the flat field names most SigmaHQ "builtin" (Windows Security/TaskScheduler/WMI-Activity channel) rules expect. Getting a correct match required hand-authoring a pySigma-style field-mapping pipeline. Zircolite's EVTX-to-JSON conversion does this flattening by convention, for free, for exactly this rule category. That is a real, non-trivial integration cost RSigma introduces that the original Zircolite plan did not have.

Net effect on Stage 3: RSigma can replace the "run a rule against events and tell me what matched" primitive (this doc's Task 1/2 core need) and is a better fit than Zircolite for `process_creation`/Sysmon-shaped and flat-JSON rules. For the builtin/security-channel rule category specifically, it needs one reusable flattening pipeline built once and applied everywhere — not a per-rule cost, but a real one-time cost that must be built and validated before Stage 3 can trust it across the whole SigmaHQ corpus (which includes many builtin-category rules). Recommend: adopt RSigma's `engine eval` as the harness, budget one task for authoring and validating that flattening pipeline against a handful of builtin-category regression fixtures before relying on it corpus-wide.

---

## Task 1 — Can RSigma evaluate a rule against events, per-event, standalone?

**Yes.** `rsigma engine eval` is documented as a fully independent subcommand under the `engine` group (not nested under `rule tune`):

> "One-shot evaluation of Sigma rules against events from a file, stdin, or an inline argument." — [rsigma.io CLI reference, `engine eval`](https://rsigma.io/cli/engine/eval/)

Exact command forms, quoted from the CLI reference:

```
rsigma engine eval [OPTIONS] --rules <RULES>

# Single inline event
rsigma engine eval -r rules/ -e '{"CommandLine":"cmd /c whoami"}'

# NDJSON file
rsigma engine eval -r rules/ -e @events.ndjson

# EVTX file
rsigma engine eval -r rules/ -e @Security.evtx

# CI negative-test gate (exit 1 if anything fires, 0 if quiet)
rsigma engine eval -r rules/ --fail-on-detection -e @ci/negative.ndjson
```

Output format: JSON `EvaluationResult` objects per matched event by default (`--output-format` also supports `table`, `csv`, `tsv`). Verbosity of the per-match detail is controlled by `--match-detail {off|summary|full}`. The docs did not publish a field-by-field schema for `EvaluationResult`, but the live run (Task 4) shows its actual shape:

```json
{
  "rule_title": "Important Scheduled Task Deleted/Disabled",
  "rule_id": "7595ba94-cf3b-4471-aa03-4f6baa9e5fad",
  "level": "high",
  "matched_selections": ["selection"],
  "matched_fields": [
    { "field": "Event.System.EventID", "value": 4701, "selection": "selection", "matcher": "one_of", "pattern": "= 4699, = 4701" },
    { "field": "Event.EventData.TaskName", "value": "\\Microsoft\\Windows\\SystemRestore\\SR", "selection": "selection", "matcher": "one_of", "pattern": "...", "case_sensitive": false }
  ]
}
```

This is per-event, per-field match detail — exactly the shape the four-condition gate needs (which rule fired, on which event, on which field). `--fail-on-detection` additionally gives a binary exit-code gate for CI use, which is a nice bonus not in the original Zircolite plan.

**Conclusion: standalone per-event evaluation exists and is not coupled to `rule tune`. Task 1's gating condition is satisfied — proceed to Tasks 2-4.**

---

## Task 2 — Capability map

| Stage 3 need | RSigma covers? | Command / reference | Notes |
|---|---|---|---|
| Evaluate one rule against a labelled event set, per-event fire result | **Yes** | `rsigma engine eval -r rule.yml -e @events.ndjson` | Confirmed live (Task 4). Per-event, per-field match output. |
| Report false positives against a benign baseline corpus | **Yes** | `rsigma rule backtest -r rules/ --corpus corpus/ --expectations expectations.yml` | Purpose-built for this: "replay an event corpus against a ruleset, diff the per-rule fire counts against declared expectations." Expectations file supports `exactly: 0` (must never fire) and `at_least`/`at_most` bounds. Also flags `unexpected[]` — rules that fired without any declared expectation — which is a direct false-positive-against-baseline signal. Better fit than a hand-rolled Zircolite wrapper would have been. |
| Confirm known true positives still fire after a rule change (gate condition 2) | **Yes, by design** | `rsigma rule tune -r rules/ --rule <id> --fp fps.ndjson --tp tps.ndjson` | Per docs: "every supplied FP and TP must fire the unfiltered target rule" (pre-check) and "no covered FP may fire and every TP must still fire" (post-check, after the proposed filter is applied). This is condition 2 of the four-condition gate, built in as a hard invariant rather than something mechanic would need to re-implement. **Not independently re-run live in this investigation** (see caveat below) — confirmed from CLI reference + example output only. |
| Input formats: EVTX and JSON | **Yes, format-wise; partial for field semantics** | `--input-format {auto,json,syslog,plain,logfmt,cef}`; EVTX via `-e @file.evtx` (requires the `evtx` build feature, present in the release binary) | Format ingestion itself is confirmed working (Task 4: rsigma read the real EVTX file, extracted 28 distinct field paths). But raw EVTX fields land as nested `Event.System.*`/`Event.EventData.*` paths, not the flat names most SigmaHQ rules use — see Task 4 finding. JSON events are flat as given, no such issue. |
| Does it require conversion/pipeline setup per rule, or evaluate raw Sigma directly? | **Partly — depends on rule category** | `-p, --pipeline` (builtin: `ecs_windows`, `fibratus_windows`, `sysmon`, or a custom YAML) | Rules against flat JSON or against Sysmon-shaped EVTX (`-p sysmon`) work with zero extra setup. Rules in the `builtin` category (Security/TaskScheduler/WMI-Activity channels — a real, sizeable slice of SigmaHQ) need a hand-authored field-mapping pipeline; none of RSigma's three shipped builtin pipelines cover this shape. Confirmed live in Task 4, not merely inferred from docs. |

---

## Task 3 — What RSigma explicitly does NOT do

All three checked explicitly against the CLI reference; none found in RSigma.

- **Repair generation for fragile rules (rewriting to durable observables): absent.** Nothing in `rule draft`, `rule tune`, or any other `rule` subcommand rewrites an existing detection's *logic* toward more durable fields. `rule tune` only ever adds a `filter` block that suppresses named false positives — it never touches or rewrites the original rule's `selection`/`condition`. This is a fundamentally different operation from mechanic's repair goal (turning a fragile IOC-tier rule into a durable behavioral one).
- **Evasion generation/testing: absent.** No subcommand generates adversarial variants of an event to test whether a rule can be evaded. `rule backtest` and `rule tune` both consume a corpus the user already has; nothing manufactures evasions.
- **Fragility classification / Pyramid-of-Pain tiering: absent.** `rule coverage` maps rules to MITRE ATT&CK technique IDs (a different axis — "what does this rule claim to detect," not "how durable is what it keys on"). `rule hygiene` flags retirement candidates by operational signal (silent/noisy/untagged/unowned), not by structural fragility of the matched observables. Neither is Pyramid-of-Pain tiering, and neither substitutes for it.

**`rule draft` vs. mechanic's repair scope, confirmed distinct:** `rule draft` generates a brand-new rule from exemplar events plus an optional baseline corpus (profiles fields, drops volatile ones, infers `startswith`/`endswith`/`contains` modifiers, verifies the draft matches every exemplar). Per the CLI reference itself: **"This command only creates brand-new rules from examples — it does not repair or rewrite existing rules. That's a separate operation."** This confirms the task's framing exactly: drafting from logs is not repairing an existing fragile rule. No overlap with mechanic's scope found.

**Bottom line for positioning:** none of mechanic's actual contribution (fragility classification, repair generation, evasion testing) exists in RSigma. Nothing here changes mechanic's positioning — RSigma is candidate plumbing for Stage 3's verification layer, not a competitor to Stage 3's substance.

---

## Task 4 — Proof on one known case

Task 1 confirmed standalone eval exists, so this ran.

**Environment note:** no Rust toolchain (`cargo`/`rustc`) and no Docker are available in this environment. Installed instead via the official prebuilt release binary, which is the release channel `rsigma.io`'s own install docs list as equally valid (`cargo install`, Docker, or "prebuilt binary from GitHub releases"):

```
gh release download v0.21.0 -R timescale/rsigma -p "rsigma-x86_64-pc-windows-msvc.zip" -p "SHA256SUMS"
sha256sum rsigma-x86_64-pc-windows-msvc.zip
# e5db02e95e102d59c051dea5db02afc84fa2f9dda5eceef82ea92b48c1be7bb5 — matched published SHA256SUMS exactly
unzip rsigma-x86_64-pc-windows-msvc.zip
./rsigma.exe --version   # rsigma 0.21.0
```

**Pinned version: v0.21.0** (commit-tagged release, published 2026-08-05, checksum-verified against the project's own published `SHA256SUMS`).

**Known-case substitution, disclosed:** EVTX-ATTACK-SAMPLES is not present in this environment. Rather than bulk-cloning a large third-party repo just to pick one file, I used a known-answer artifact already in this project's local `sigma` corpus that is *stronger* than an arbitrary EVTX-ATTACK-SAMPLES pick: SigmaHQ's own regression-test fixture, where the rule author pairs a specific rule with a specific `.evtx` file and a declared expected match count.

- **Rule:** `sigma/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable.yml` (id `7595ba94-cf3b-4471-aa03-4f6baa9e5fad`) — fires on Windows Security EventID 4699/4701 (scheduled task deleted/disabled) when the task name matches a short list of security-critical paths (SystemRestore, Defender, BitLocker, WindowsUpdate, etc.), with one built-in exclusion filter for routine Defender-update churn.
- **Known-positive event:** `sigma/regression_data/rules/windows/builtin/security/win_security_susp_scheduled_task_delete_or_disable/7595ba94-cf3b-4471-aa03-4f6baa9e5fad.evtx`. Its own `info.yml` declares: `match_count: 1`. This is the rule author's own hand-verified ground truth, not my assertion.
- **Known-negative event:** a synthetic flat JSON event with the same field shape but a benign task name: `{"EventID": 4701, "TaskName": "\\Microsoft\\Windows\\CustomApp\\Cleanup", "SubjectUserName": "jdoe"}` — should not match any of the six required substrings.

**First attempt — raw EVTX, no pipeline:**
```
$ rsigma.exe engine eval -r rule.yml -e @positive.evtx --pretty
Processed 1 EVTX records, 0 matches.
```
**0 matches — wrong.** `--observe-fields` showed why: rsigma parsed the EVTX into `Event.System.EventID`, `Event.EventData.TaskName`, etc. (28 nested field paths), while the rule references flat `EventID`/`TaskName`/`SubjectUserName`. The rule's three referenced fields were reported as `missing` — a genuine field-mapping gap, not a rule bug (this is the exact rule SigmaHQ itself ships and regression-tests).

**Fix — hand-authored pySigma-style mapping pipeline** (RSigma's pipeline format is documented as pySigma-compatible):
```yaml
name: Manual EVTX flatten test pipeline
priority: 100
transformations:
  - id: map_eventid
    type: field_name_mapping
    mapping:
      EventID: Event.System.EventID
      TaskName: Event.EventData.TaskName
      SubjectUserName: Event.EventData.SubjectUserName
```

**Second attempt — with the pipeline:**
```
$ rsigma.exe engine eval -r rule.yml -p flatten_pipeline.yml -e @positive.evtx --pretty --match-detail full
Processed 1 EVTX records, 1 matches.
```
✅ **1 match — correct, matches SigmaHQ's own declared `match_count: 1` exactly.** Matched fields reported: `Event.System.EventID = 4701`, `Event.EventData.TaskName = \Microsoft\Windows\SystemRestore\SR` — a real, correct hit on the SystemRestore-task path the rule is designed to catch.

**Benign event, no pipeline needed (flat JSON given directly):**
```
$ rsigma.exe engine eval -r rule.yml -e @benign.json
Processed 1 events, 0 matches.
$ rsigma.exe engine eval -r rule.yml -e @benign.json --fail-on-detection; echo $?
Processed 1 events, 0 matches.
0
```
✅ **0 matches — correct.** `--fail-on-detection` exit code confirms the CI-gate path also works as documented (exit 0 = quiet).

**Verdict on the known-case test: RSigma got the right answer on both the malicious and benign event once given a correct pipeline, and got the malicious event wrong (silently — 0 matches, no error) without one.** That silent-zero failure mode is the important part to carry into Stage 3: RSigma does not warn "your rule's fields don't exist in this event" by default; you have to know to run `--observe-fields` to find that out. Any Stage 3 wrapper around RSigma must run rules through a validated pipeline (or use `--observe-fields` as a build-time sanity check) rather than trusting a bare `0 matches` result at face value — a naive integration would silently under-report true positives for the entire builtin/security-channel rule category.

---

## RuleForge (arXiv:2604.01977) — anti-circularity prior art for Stage 3 Part 5

Not a component to reuse (it detects web-app vulnerabilities from Nuclei/CVE templates, not host/network Sigma-style detections), but its LLM-as-judge design is directly relevant prior art for repair-generation review in Stage 3. RuleForge's judge is evaluated on **sensitivity and specificity measured against real production HTTP traffic outcomes** (reporting AUROC 0.75, and a 67% false-positive reduction versus a synthetic-test-only baseline) rather than on the LLM judge's own stated confidence — i.e., the check that stops the judge from rubber-stamping LLM-generated rules is grounding it in an external, non-model signal (does this rule actually behave correctly against real traffic) instead of asking a second LLM call whether the first LLM call's rule "looks right." The paper also explicitly flags LLM overconfidence as a risk and keeps a human-in-the-loop step rather than trusting the judge alone. For Stage 3 Part 5 (verifying an LLM-generated *repair*), the transferable principle is the same one the κ-provenance audit already surfaced for this project: never let the same model (or a peer model with no independent signal) grade its own work — ground the verdict in RSigma/Zircolite's actual fire/no-fire behavior against the labelled event set, not in a judge's opinion of the diff.

---

## Caveats and what wasn't done

- `rule tune`'s TP-preservation and FP-suppression behavior is confirmed from the CLI reference and its worked example output, **not** independently re-run live in this investigation — the eval-command test (Task 4) was prioritized as the harness-critical primitive per Task 1's gating instruction, and building a second live test scenario (needing both genuine FP and TP event sets, not just one TP fixture) was judged out of scope for a doc-and-one-case investigation. If RSigma is adopted, re-verify `rule tune` live before depending on it for gate condition 2.
- `rule backtest`'s per-corpus false-positive reporting was assessed from documentation only, not run live, for the same reason.
- No Rust toolchain or Docker was available in this environment; the prebuilt release binary was used instead and checksum-verified — this is a documented, equally-supported install path, not a workaround.
- EVTX-ATTACK-SAMPLES specifically was not fetched; SigmaHQ's own regression-test EVTX fixture was substituted as a known-answer case, disclosed above. The finding about raw-EVTX field flattening is a property of RSigma's EVTX parser and the rule's field-naming convention, not of which EVTX corpus supplied the file, so it should generalize.

## Final summary block

- **Core question (Task 1):** CONFIRMED — `rsigma engine eval` is a standalone, per-event evaluator, independent of `rule tune`.
- **Capability coverage (Task 2):** Mostly covered; the "does it require pipeline setup" need answers **yes, for the builtin/security-channel rule category**, confirmed live, not just from docs.
- **Scope check (Task 3):** CONFIRMED absent — no repair generation, no evasion generation, no fragility/Pyramid-of-Pain tiering anywhere in RSigma. Mechanic's contribution is unchanged.
- **Known-case proof (Task 4):** RAN LIVE. Correct on both malicious and benign events — but only after a hand-built field-mapping pipeline; failed silently (0 matches, no warning) without one.
- **Recommendation (Task 5):** **B — partial adoption.** Use RSigma's `engine eval` (and likely `rule backtest`/`rule tune`) as the Stage 3 harness, but budget for and validate a field-mapping pipeline for the builtin/security-channel rule category before trusting it corpus-wide. This is lower-risk than a full from-scratch Zircolite wrapper and lower-risk than adopting RSigma blind — it is based on evidence that RSigma both works and has a specific, now-documented sharp edge.
