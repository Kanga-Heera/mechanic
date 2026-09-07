# Field-aware literal classification: the field-semantics registry

`mechanic/field_semantics.py` resolves a Sigma leaf's FIELD to a bounded,
documented ROLE that governs how the classifier treats a literal VALUE in
that field - one mechanism, replacing the ad-hoc single-field special case
the ScriptBlockText fix originally shipped, and fixing a second,
opposite-direction bug (`GrantedAccess`) with the same mechanism instead of
a second special case.

## The bug, confirmed in both directions

The classifier decided a literal's tier from the value's SURFACE FORM
alone (a catalog hit, a regex-shaped pattern, a hash/IP pattern). That is
wrong whenever the FIELD the value appears in changes what the value
actually means:

- **`ScriptBlockText='Invoke-WebRequest'` scored Tool tier - wrongly
  DURABLE.** Fixed first, ad hoc, as a single-field special case (see
  RESULTS.md, "Bug fix: script-content field durability inversion").
  `Invoke-WebRequest` is attacker-authored PowerShell script text; `iwr`
  (a built-in alias) defeats the match with no tool switch at all.
- **`GrantedAccess='0x1010'` scored Artifact tier - wrongly COSMETIC.**
  `0x1010` is `PROCESS_VM_READ | PROCESS_QUERY_(LIMITED_)INFORMATION`, the
  exact Windows access rights LSASS credential dumping requires (see
  Microsoft's "Process Security and Access Rights" documentation, the same
  source SigmaHQ's own canonical LSASS rules cite). Changing the bit
  pattern forfeits the access - it is not a stylistic choice the way a
  filename is, and the classifier had no notion that a field's value can
  be FUNCTIONALLY REQUIRED rather than freely chosen.

**Both are the same bug**: tier decided from `value` alone, when it must
be decided from `(field, value)` TOGETHER. `fragility.classify_atom`
resolves a field's role from this registry BEFORE any surface-form
classification runs, and the role governs what happens next.

## Design principle: field-level, never a value wordlist

Matches `protected_literals.py`'s own discipline (see that module's
docstring). Sigma's field taxonomy - the Sysmon / Windows-Security-auditing
/ ATT&CK data-component field names a rule can actually key on - is
finite, documented, and small. A VALUE wordlist is the opposite: unbounded,
and the exact trap v1's tool-name list already fell into once (see
`fragility.py`'s "five causes" list, cause 1). Every field in the registry
is looked up in a bounded, cited set; nothing in this layer matches on the
free-text CONTENT of a value - `protected_literals.py` and `refdata.py`
already do that, for the specific values that need it, one layer below
this one.

A field whose role is genuinely unclear resolves to `GENERIC` - never
guessed into a more specific role. `GENERIC` falls through to ordinary
surface-form classification (Part 2 below governs what that means when
nothing matches).

## The five roles

| Role | Policy | Fields (provenance) |
|---|---|---|
| `BINARY_IDENTITY` | A known value is relatively durable - renaming the running binary is the evasion. Existing tool-vocabulary/protected-literal logic applies as-is; this role changes no behavior, it only names it. | `Image`, `ParentImage`, `TargetImage`, `OriginalFileName`, `CommandLine`, `process.name`, auditd's `a0`/`exe`/`comm`, and siblings (absorbed unchanged from the former `_PROCESS_CONTEXT_FIELD_NAMES`, Task 8's Splunk-over-scoring fix). |
| `ATTACKER_AUTHORED_TEXT` | Literal matches are FRAGILE regardless of the specific string - the attacker authors this field's text and can reword/obfuscate it indefinitely. A tool-shaped substring earns Artifact, not Tool. | `ScriptBlockText` (Sigma `logsource.category: ps_script`, PowerShell Script Block Logging, Event ID 4104 - absorbed unchanged from the original fix; see RESULTS.md for the full field derivation and which candidate fields, e.g. CommandLine, Payload/ContextInfo, Data, were considered and deliberately excluded). |
| `FUNCTIONAL_CONSTRAINT` | A value is DURABLE (TTP tier), unconditionally, regardless of which specific value it is - the field's value is dictated by what the technique/OS mechanism REQUIRES, not a free choice. | `GrantedAccess` (Sysmon Event ID 10, ProcessAccess - Microsoft Sysinternals' own schema: "the access requested"), `AccessMask` (Windows Security auditing Event ID 4656/4663 - Microsoft's own "sum of all Access Rights that were requested"). Deliberately excludes `IntegrityLevel`/`TokenElevationType`/`Mandatory Label` - a different mechanism (an OS-assigned privilege LEVEL, not an access-rights bitmask); see the module's own comment for the full reasoning. |
| `DATA_SOURCE_SELECTOR` | The value identifies WHICH telemetry/platform emitted the event, not the behavior itself - not an independently adversary-evadable observable. | `EventID`, `EventCode`, `event.code`, `syscall`, `auditd.data.syscall`, `eventSource`, `provider`, `dataset`, `sourcetype` (absorbed unchanged from the former `_EVENTID_SYSCALL_EXACT`/`_EVENTID_SYSCALL_LAST_SEGMENT`, the AND/OR-fix-era cloud-audit generalization). |
| `GENERIC` (default) | Field role unknown/undocumented - falls through to ordinary surface-form classification (Part 2 governs the honest floor when nothing matches). | Everything not in one of the four sets above. |

See `mechanic/field_semantics.py`'s module and inline docstrings for the
full field-by-field citations - not duplicated a second time here.

## Part 2: the honest floor for genuinely unrecognized values

When a literal matches NO known signal at all - not a protected literal,
not a data-source selector, not IOC-shaped, not a functional-constraint
field, not attacker-authored-text-shaped, not a recognized tool/catalog/
pattern match - `classify_atom` no longer silently asserts "Artifact, high
confidence, cosmetic." It still classifies Artifact (nothing here earned a
higher tier), but `AtomClassification.semantic_confidence` drops to
`"medium"` and the reason is `unrecognized_literal_no_known_signal`
instead of the old, over-claiming default.

`semantic_confidence` is a DELIBERATELY SEPARATE axis from
`priority.FragilitySignal.confidence` (which measures whether AST parsing/
combination succeeded at all, not per-atom semantic certainty about a
value mechanic did manage to classify). Conflating "we parsed this rule"
with "we're sure this specific value means what we think it means" is
exactly the overclaim this field exists to stop making. A `mechanic
explain` reader sees this stated plainly: "mechanic does not recognize the
specific meaning of `<field>=<value>` ... treat this tier as a
lower-confidence placeholder for an unrecognized value, not a verified
judgment."

## Part 4: the explanation names the whole basis, not an arbitrary subset

Found by hand-testing several multi-atom rules: the pre-fix explanation
picked *some* atom matching the rule's final tier and showed at most two
of them, silently dropping the rest - including atoms at a DIFFERENT,
more durable tier that a reader would otherwise reasonably assume were
never considered.

`priority.RuleSignals.narrative` now:

1. Names EVERY atom tied at the tier that actually SET the rule's result
   (the MIN-floor for an AND-linked rule, the MAX-ceiling for an OR-linked
   one) - capped at a generous display limit with an explicit "+N more"
   count, never silently truncated.
2. Lists the REST of the matched atoms with their own tiers, labeled
   "Other matched values, not what set the tier" - so a durable
   functional-constraint match sitting alongside a weaker literal is never
   left looking un-examined just because it wasn't the floor.
3. Adds a dedicated sentence whenever a `functional_constraint_field` or
   `attacker_authored_script_content_field` atom appears ANYWHERE in the
   rule (not only among the driving atoms) - the durability/fragility
   explanation for that field role must reach the reader even when the
   atom in question isn't what set the final tier.
4. Adds the Part 2 honest-floor sentence when a DRIVING atom is
   `semantic_confidence: "medium"` - the tier-meaning sentence above it
   must not read as a confident claim about a value mechanic has no real
   basis for.

## Part 5: validation

**Regression (must-not-move) checks, all still green**: the canonical
FIELD_MISMATCH renamed-binary rule still classifies TTP (the structural
promotion runs before any atom-level field-role logic and is untouched);
a renamed-rundll32 FIELD_MISMATCH-shaped rule still classifies TTP; a
plain rundll32.exe match with negated `ParentImage` exclusions still
classifies Tool on the `Image` atom alone (negated leaves stay excluded
from the AND/OR combination, unaffected by this fix).

**STP re-validation, both frozen fixtures, reported honestly (no tuning):**

| Fixture | Metric | Before | After |
|---|---|---:|---:|
| Sigma-only (n=70) | Kendall's tau-b | 0.2841 | **0.2841 (unchanged)** |
| Sigma-only (n=70) | Spearman's rho | 0.3056 | **0.3056 (unchanged)** |
| Sigma-only (n=70) | Mapped kappa | 0.2249 | **0.2249 (unchanged)** |
| Combined (n=72) | Kendall's tau-b (p) | 0.3449 (0.0017) | **0.3523 (0.0013)** |
| Combined (n=72) | Spearman's rho (p) | 0.3740 (0.0012) | **0.3784 (0.0010)** |
| Combined (n=72) | Mapped kappa | 0.2653 | **0.3077** |

**Zero rows moved in the Sigma-only sample** - checked directly (a
before/after tier diff across all 70 rows), not assumed. Only one row in
that sample uses `GrantedAccess` at all ("Direct Syscall of
NtOpenProcess"), and its only occurrence is inside a negated exclusion
filter, already excluded from the AND/OR combination before and after this
fix. The fix is real and independently tested (see
`tests/test_fragility.py`'s dedicated `FUNCTIONAL_CONSTRAINT` fixtures) but
has no row in this particular external-validation sample to move -
reported plainly rather than manufacturing a headline number the sample
doesn't support.

**One row moved in the combined sample, and the correlation IMPROVED**:
the Splunk rule "Detect Credential Dumping through LSASS access" (MITRE
score 4) moved mechanic's tier from Tool to TTP - a materially closer match
to MITRE's own score than before. This is the one real-world row (reached
through the quarantined text-path classifier, not the Sigma AST path) that
actually exercises an access-mask-shaped field in either sample, and it
confirms the fix's direction independently of the Sigma-only sample's
silence on the question.

Per the brief: neither result changed what was implemented. The fix is
justified by the evasion-semantics argument (a bitmask value is dictated
by the technique, not the attacker) independently of any correlation
number; the STP re-run is a check that was reported honestly whichever way
it moved, not a target tuned toward.

## Non-goals / disclosed future work

- **`CommandLine`/`ParentCommandLine`/`Payload`/`ContextInfo`/`Data`**:
  carried over unchanged from the original ScriptBlockText fix's own
  disclosed scope decisions (RESULTS.md) - genuinely mixed or ambiguous
  fields, left `GENERIC`/`BINARY_IDENTITY` rather than guessed into
  `ATTACKER_AUTHORED_TEXT`.
- **`IntegrityLevel`/`TokenElevationType`/`Mandatory Label`**: considered
  for `FUNCTIONAL_CONSTRAINT` and excluded - a genuinely different
  mechanism (an OS-assigned privilege level, not a technique-required
  access-rights bitmask). Left `GENERIC`. A future, separately-justified
  role (perhaps `PRIVILEGE_LEVEL`) could cover these if a citable source
  for their own durability semantics is found - not guessed at here.
- **Splitting `BINARY_IDENTITY`'s `refdata.all_tool_names()` catalog by
  provenance** (native-OS vs. adversary-brought) is the same STP Level 2/3
  seam `docs/stp-alignment.md` already documents as future work - this
  registry doesn't attempt it either, for the same reason (mechanic has no
  tool-provenance signal to resolve it from field/value alone).
