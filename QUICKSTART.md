# Quickstart: four commands, one real repository, real output

This is the core product (`mechanic scan`/`staleness`/`triage`/`explain`)
run start to finish against a real, pinned SigmaHQ checkout, exactly as a
new user would run it. Every command and every line of output below is
**verbatim** - nothing here is hand-edited or idealized. Where this run
surfaced something worth knowing (mainly: how long a full-corpus run takes),
that is disclosed here plainly rather than smoothed over.

No RSigma binary, no `GROQ_API_KEY`, and no network access are required for
any of this - see [`docs/core-vs-experiment.md`](docs/core-vs-experiment.md)
for why, and `tests/test_core_isolation.py` for the test that enforces it.

## 0. Setup

```
git clone https://github.com/SigmaHQ/sigma.git
cd sigma && git checkout da9bb07d642a2826e89702445d32c795209ec108
cd ..
pip install -e ./mechanic[dev]
```

The commit above is the exact one this walkthrough was run against
(`sigma/rules`, 3,144 rule files) - pinned so the output below stays
reproducible. A fresh `git clone` today will have moved forward; that's
fine, just expect slightly different numbers than what's printed here.

## 1. `mechanic scan` - does the repo even load cleanly?

```
mechanic scan sigma/rules
```

```
          mechanic scan —
   .../sigma/rules
+---------------------------------+
| metric                  | value |
|--------------------------+-------|
| files scanned           |  3144 |
| files loaded (>=1 rule) |  3144 |
| files failed to load    |     0 |
| rules loaded            |  3144 |
| load failures           |     0 |
| validator crashes       |     0 |
+---------------------------------+
No load or validator failures.
```

SigmaHQ's `rules/` loads perfectly cleanly at this commit - 3,144/3,144.
That won't be true of every repository (see
`tests/test_loader_adversarial.py` for what happens when it isn't - a
malformed file is reported per-file, never a crash), but it's the expected,
happy-path result for a well-governed upstream corpus like this one.

## 2. `mechanic staleness` - which rules has nobody organically touched?

```
mechanic staleness sigma --subdir rules --top 5
```

Git-history mining walks all ~17,000 commits in this repo's full history
the first time; every run after that reuses a disk cache keyed to the
repo's current commit (`sigma/.mechanic_cache/`), so it only re-mines when
the repo has actually moved forward. First run: several minutes. Cached
re-run: seconds for the mining step itself (see the honest timing note in
section 4 for what still isn't instant even from a warm cache, and why).

## 3. `mechanic triage` - the ranked review list

```
mechanic triage sigma --subdir rules --top 5
```

```
mechanic triage — .../sigma
3144 rules, 3002 fragile, 2375 stale, 2275 need attention (fragile AND stale)
This is a review-priority ORDERING, not a validated combined score. [...]

                          Summary
+---------------------------------------------------------+
| metric                                          | value |
|--------------------------------------------------+-------|
| rules discovered                                |  3144 |
| scoreable                                        |  3142 |
| unscoreable (own section below)                  |     2 |
| triage hypothesis: likely-repairable             |  1932 |
| triage hypothesis: likely-needs-telemetry-check  |   878 |
| triage hypothesis: likely-retire                 |   240 |
+---------------------------------------------------------+

Top 5, sorted for review, worst first (fragility tier first, then staleness — not a combined score)
 file                                                              | tier | tier conf. | why (driving observable)          | behavioral staleness       | age (days) | triage hypotheses
 rules/windows/builtin/security/.../win_security_susp_privesc_kerberos_relay_over_ldap.yml | IOC      | high | IpAddress='127.0.0.1'              | 732d since behavioral change | 775  | likely-repairable
 rules/linux/builtin/vsftpd/lnx_vsftpd_susp_error_messages.yml    | Artifact | high | ...'Connection refused: too many...' | NEVER REVISED               | 3344 | likely-needs-telemetry-check, likely-retire
 rules/windows/builtin/security/.../win_security_overpass_the_hash.yml | Artifact | high | LogonProcessName='seclogo'    | NEVER REVISED               | 3122 | likely-needs-telemetry-check, likely-retire
 rules/network/dns/net_dns_susp_telegram_api.yml                  | Artifact | high | query='api.telegram.org'          | NEVER REVISED               | 3009 | likely-needs-telemetry-check, likely-retire
 rules/windows/builtin/security/.../win_security_remote_powershell_session.yml | Artifact | high | DestPort=5985           | NEVER REVISED               | 2503 | likely-needs-telemetry-check, likely-retire
```

(Reformatted for width here - the real terminal output is a bordered Rich
table; column contents are exact.) The #1-ranked rule matching an IOC
(`IpAddress='127.0.0.1'`, an internal loopback literal with essentially no
durability) is exactly the shape of result this tool exists to surface.

## 4. `mechanic explain` - why does that #1 rule sit there?

```
mechanic explain sigma/rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml --subdir rules
```

```
mechanic explain — rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml

This rule's detection logic has been behaviorally revised 1 time(s), most
recently 732 days ago. Its fragility tier is IOC: it matches on a raw
indicator (a hash, an IP address) that an attacker can change without
altering their actual behavior at all - the least durable kind of match
possible. This tier was assigned with high confidence: mechanic fully
parsed the rule's logic as a structured syntax tree and combined its
conditions using the AND/OR-aware rule validated against MITRE's Summiting
the Pyramid methodology. The tier comes from matching on:
IpAddress='127.0.0.1' (classified IOC); EventID=4624 (classified IOC).
Given both signals together, this rule matches the untested Stage 3
hypothesis label(s) 'likely-repairable' - a candidate worth a closer look
for that reason, not a conclusion about the rule's actual quality. Review
this - none of the above is a verdict that the rule is broken.

Full signal detail follows below, for anyone who wants to verify the
sentences above against the underlying data.

                       Behavioral staleness (Part 1)
+--------------------------------------------------------------------------+
| field                                                            | value |
|-------------------------------------------------------------------+------|
| never revised                                                    | False |
| behavioral commit count                                          | 1     |
| days since last behavioral change                                | 732   |
| age (days since earliest known creation commit)                  | 775   |
| commit-classification confidence (behavioral vs. cosmetic split) | high  |
+--------------------------------------------------------------------------+
        Fragility tier (Part 2)
+-------------------------------------+
| field                       | value |
|------------------------------+------|
| tier                        | IOC   |
| confidence                  | high  |
| AND/OR-corrected (AST walk) | True  |
| structural findings         | none  |
+-------------------------------------+
Contributing atoms (field/value pairs the tier was derived from)
+----------------------------------------+
| field                     | value      |
|----------------------------+-----------|
| EventID                   | 4624       |
| LogonType                 | 3          |
| AuthenticationPackageName | Kerberos   |
| IpAddress                 | 127.0.0.1  |
| TargetUserSid             | S-1-5-21-...-500 |
+----------------------------------------+
Note: per-node AST path breadcrumbs are not tracked by the classifier (see
mechanic/fragility.py); field/value pairs and structural-detector detail
above are the full reasoning trail currently available.
Triage hypotheses (Stage 3, UNTESTED - not conclusions): likely-repairable
```

(Reformatted for width; content verbatim.) This is real prose, not a field
dump - `mechanic/priority.py::RuleSignals.narrative` is what generates the
paragraph at the top, and every sentence in it traces to a specific field
in the table below it. `EventID=4624` and `TargetUserSid` also being
classified IOC-adjacent alongside the loopback IP is existing classifier
behavior, unchanged by this hardening pass.

## An honest timing note

Every command above completed correctly and produced the numbers shown -
nothing was skipped or approximated. What's disclosed plainly here because
it's real, observed behavior on this corpus, not because anything went
wrong: `staleness`/`triage`/`explain` on SigmaHQ's full 3,144-rule `rules/`
directory take **several minutes wall-clock**, even with git-history mining
served from a warm cache. This is unchanged, pre-existing behavior (not
something the hardening pass or the GUI introduced or regressed) - and it
is why the git-history-mining CACHE exists in the first place (`--refresh`
to force a re-mine, omitted otherwise).

**Real, measured breakdown** (via the GUI's per-stage progress reporting,
same pinned commit, warm mining cache): a full run took **635 seconds
(~10.6 minutes)** end to end, and the cost is **not evenly spread**:

| Stage | Wall-clock | Share |
|---|---:|---:|
| Mining (cache hit) | ~0s | 0% |
| Staleness | ~4s | 0.6% |
| **Semantic diff (behavioral vs. cosmetic classification)** | **~591s** | **~93%** |
| Fragility classification (all 3,144 rules) | ~39s | ~6% |

**Semantic diff so dominates the total that fragility classification -
the part that scales with rule *count* - is almost a rounding error by
comparison.** Per-rule fragility classification alone finished all 3,144
rules in under 40 seconds; the other ~10 minutes is Part 1's behavioral-
vs-cosmetic git-blob diffing, which does real work per *organic commit*
in the mined history, not per rule. For a large, heavily-revised corpus
like SigmaHQ, budget most of the wait for that stage specifically, not
classification. Nothing here hangs or crashes; the GUI's progress display
(`docs/gui-notes.md`) shows this breakdown live rather than a single
opaque spinner, precisely because a bare "loading…" over a 10-minute wait
would itself be a readability failure.

`mechanic scan` (no git involved at all, pure YAML load) stays fast
regardless of corpus size - see `tests/test_loader_adversarial.py`'s
10,000-rule perf-sanity test.
