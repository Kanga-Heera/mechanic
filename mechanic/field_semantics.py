"""Field-semantics registry (Stage 2, Part 2d): resolves a Sigma FIELD to a
ROLE describing how a literal VALUE in that field should be tiered - one
mechanism replacing the per-field ad-hoc branches this module's history had
been accumulating one at a time.

ROOT CAUSE this exists to fix, confirmed by two hand-tested rules, in BOTH
directions:

  - `ScriptBlockText='Invoke-WebRequest'` scored Tool tier (wrongly
    durable) - fixed first as an ad-hoc, single-field special case in
    `fragility.py` (see its "A SEVENTH cause" docstring paragraph and
    RESULTS.md's "Bug fix: script-content field durability inversion").
    That fix's own mechanism (`_SCRIPT_CONTENT_FIELD_NAMES`/
    `field_carries_script_content`) is REMOVED and re-expressed here as
    the `ATTACKER_AUTHORED_TEXT` role below - same behavior, one mechanism
    instead of a parallel special case.
  - `GrantedAccess='0x1010'` scored Artifact tier (wrongly COSMETIC) - the
    LSASS access-mask case (`docs/stp-alignment.md`'s own STP Level 4
    example: `TargetImage=lsass.exe` + `GrantedAccess`). The classifier
    decided the tier from the value's SURFACE FORM alone (an ordinary hex
    string, matching no known catalog/pattern/protected-literal signal)
    with no notion that the FIELD it appears in makes this value
    functionally REQUIRED, not a stylistic choice an attacker made.

**Both failures are the SAME bug**: tier was decided from `value` alone,
when it must be decided from `(field, value)` TOGETHER - the field
determines whether a value is a functional constraint, attacker-authored
text, a durable binary identity, a data-source label, or a truly free
literal. `fragility.classify_atom` now resolves a field's role from this
registry BEFORE any surface-form (value-shape) classification runs, and
the role governs what happens next.

DESIGN PRINCIPLE, matching `protected_literals.py`'s own discipline (see
that module's docstring): this is a FIELD-level classification. Sigma's
field taxonomy - the Sysmon/Windows-Security-auditing/ATT&CK
data-component field names a rule can actually key on - is finite,
documented, and small. A VALUE wordlist is the opposite: unbounded, and
the exact trap v1's tool-name list already fell into once (see
`fragility.py`'s five-causes list, cause 1). Every field below is looked
up in a bounded, cited set; nothing here matches on the free-text CONTENT
of a value - that is what protected_literals.py and refdata.py already do
for the specific VALUES that need it, at the layer beneath this one.

Roles with no field name below - i.e. every field NOT in one of the four
sets - resolve to `GENERIC`, never guessed into a more specific role. A
field whose role is genuinely unclear MUST be `GENERIC`, so it falls
through to ordinary surface-form classification, honestly confidence-
capped where nothing recognizes it (`fragility.classify_atom`'s Part 2
floor) rather than mis-assigned a role this registry has no evidence for.
"""

from __future__ import annotations

from typing import Optional

# --- Roles ------------------------------------------------------------------

BINARY_IDENTITY = "BINARY_IDENTITY"
ATTACKER_AUTHORED_TEXT = "ATTACKER_AUTHORED_TEXT"
FUNCTIONAL_CONSTRAINT = "FUNCTIONAL_CONSTRAINT"
DATA_SOURCE_SELECTOR = "DATA_SOURCE_SELECTOR"
GENERIC = "GENERIC"

ROLES = (BINARY_IDENTITY, ATTACKER_AUTHORED_TEXT, FUNCTIONAL_CONSTRAINT, DATA_SOURCE_SELECTOR, GENERIC)

ROLE_POLICY = {
    BINARY_IDENTITY: (
        "A known value is relatively durable - renaming the running binary is "
        "the evasion. Existing tool-vocabulary/protected-literal logic applies "
        "as-is (fragility.is_tool_value's catalog+pattern check, gated to this "
        "role); this role changes no existing behavior, it only names it."
    ),
    ATTACKER_AUTHORED_TEXT: (
        "Literal matches are FRAGILE regardless of the specific string, because "
        "the attacker authors this field's text and can reword/obfuscate it "
        "indefinitely while keeping the underlying behavior. A tool-shaped "
        "substring here earns Artifact, not Tool - see "
        "fragility._tool_shaped_ignoring_field_context."
    ),
    FUNCTIONAL_CONSTRAINT: (
        "A value here is DURABLE (TTP tier), unconditionally, regardless of "
        "which specific value it is - the field's value is dictated by what "
        "the underlying technique/OS mechanism REQUIRES, not chosen freely by "
        "the attacker, so changing it forfeits the capability rather than just "
        "changing its cosmetic appearance."
    ),
    DATA_SOURCE_SELECTOR: (
        "The value identifies WHICH telemetry/platform emitted the event, not "
        "the behavior itself - not an independently adversary-evadable "
        "observable. Reported at Artifact tier when it is a rule's sole "
        "positive criterion (nothing else to report); excluded entirely from "
        "the rule-level combination otherwise (handled by fragility.classify_rule, "
        "unchanged by this registry)."
    ),
    GENERIC: (
        "Field role unknown/undocumented - falls through to ordinary "
        "surface-form (value-shape) classification: raw IOC pattern, known "
        "tool/cmdlet/exe pattern, or - if none of those match either - the "
        "honest 'unrecognized, medium confidence' floor (fragility.classify_atom's "
        "Part 2 default), never silently asserted cosmetic/high-confidence."
    ),
}


def _normalize(field: Optional[str]) -> str:
    seg = (field or "").rsplit(".", 1)[-1].lower()
    return seg.replace("_", "")


# -----------------------------------------------------------------------------
# BINARY_IDENTITY - process/image/file-identity fields. Absorbed unchanged
# from fragility.py's former `_PROCESS_CONTEXT_FIELD_NAMES` (Task 8's fix
# for Splunk over-scoring, Part 2c) - same field list, same normalization
# (case-insensitive, underscore-insensitive, last dotted segment), now
# expressed as a role instead of a bare field-name set with no name for
# what it represents. Covers Sysmon-style PascalCase (Image, CommandLine,
# NewProcessName, ParentImage), ECS (process.name, process.command_line,
# process.parent.executable), Splunk CIM snake_case (Processes.process,
# Processes.process_name, Processes.original_file_name), and Linux
# auditd's EXECVE-record convention (a0 = argv[0], exe/comm = executable
# path/short name) uniformly.
# -----------------------------------------------------------------------------
_BINARY_IDENTITY_FIELDS = {
    "image", "parentimage", "targetimage", "currentimage", "sourceimage",
    "grandparentimage", "previousimage", "newprocessname",
    "originalfilename", "processname", "parentprocessname",
    "process", "parentprocess", "executable", "parentexecutable",
    "commandline", "parentcommandline", "processcommandline",
    "name",
    "a0", "exe", "comm",
}

# -----------------------------------------------------------------------------
# ATTACKER_AUTHORED_TEXT - absorbed unchanged from fragility.py's former
# `_SCRIPT_CONTENT_FIELD_NAMES` / `field_carries_script_content` (the
# ScriptBlockText fix - RESULTS.md "Bug fix: script-content field
# durability inversion"). Provenance and the deliberately-excluded
# candidate fields (CommandLine/ParentCommandLine, ps_module's
# Payload/ContextInfo, ps_classic's Data) are recorded there in full and
# not re-derived here - see that RESULTS.md section for: the Sigma
# `logsource.category: ps_script` (PowerShell Script Block Logging, Event
# ID 4104) sourcing, and the empirical 186/186-rule corpus check that
# found this exact field name carries no collision risk with an unrelated
# meaning in real-world rules.
# -----------------------------------------------------------------------------
_ATTACKER_AUTHORED_TEXT_FIELDS = {"scriptblocktext"}

# -----------------------------------------------------------------------------
# FUNCTIONAL_CONSTRAINT - fields whose value is dictated by Windows' own
# access-control model, not a free attacker choice. Two fields, both
# citable to a specific, external, documented mechanism (same discipline
# protected_literals.py uses for its own categories):
#
#   GrantedAccess  - Sysmon Event ID 10 (ProcessAccess). Microsoft
#                     Sysinternals' own Sysmon schema documents this field
#                     as "the access requested" for the process-open
#                     operation. SigmaHQ's own canonical LSASS-access rules
#                     (e.g. the deprecated `sysmon_mimikatz_detection_lsass.yml`,
#                     car.2019-04-004) key on exactly this field with values
#                     like `0x1010`/`0x1410`, citing Microsoft's own "Process
#                     Security and Access Rights" documentation
#                     (learn.microsoft.com/windows/win32/procthread/
#                     process-security-and-access-rights) for what each bit
#                     means (0x0010 = PROCESS_VM_READ, 0x0400 =
#                     PROCESS_QUERY_INFORMATION, 0x1000 =
#                     PROCESS_QUERY_LIMITED_INFORMATION, ...). Changing the
#                     bit pattern changes what access is actually being
#                     requested - it is not possible to "reword" an access
#                     mask while keeping the same capability, unlike a
#                     filename or a script's wording.
#   AccessMask     - Windows Security auditing (Event ID 4656/4663, object
#                     access). Microsoft's own event documentation
#                     ("4663(S): An attempt was made to access an object")
#                     defines this field as "the sum of all Access Rights
#                     that were requested" - the same access-control
#                     bitmask mechanism as GrantedAccess, from a different
#                     telemetry source (Windows Security auditing rather
#                     than Sysmon).
#
# Deliberately narrow, per the same "unclear -> GENERIC, don't guess"
# discipline this module states everywhere else: `IntegrityLevel`,
# `TokenElevationType`, and `Mandatory Label` were considered and
# excluded - STP v4.0's own Level 2/3 example tables (docs/stp-alignment.md,
# Part 2) list these as "Tool-Specific Configurations", a DIFFERENT
# mechanism from an access-rights bitmask: a privilege LEVEL the OS
# assigns a process/token based on context (how it was launched, whether
# UAC was bypassed, ...), not a bitmask whose bits directly encode a
# technique's required capability. Left GENERIC rather than folded in here
# just because both are "security-relevant numeric-ish Windows fields" -
# exactly the kind of example-shaped overreach protected_literals.py's own
# docstring warns against.
# -----------------------------------------------------------------------------
_FUNCTIONAL_CONSTRAINT_FIELDS = {"grantedaccess", "accessmask"}

# -----------------------------------------------------------------------------
# DATA_SOURCE_SELECTOR - absorbed unchanged from fragility.py's former
# `_EVENTID_SYSCALL_EXACT` / `_EVENTID_SYSCALL_LAST_SEGMENT` /
# `_is_eventid_or_syscall_field` (originally the EventID/syscall structural
# test, generalized after the AND/OR combination fix surfaced the same
# failure mode for cloud-audit data-source-identification fields - see
# fragility.py's cause-3 and the `_EVENTID_SYSCALL_LAST_SEGMENT` comment
# history for the full provenance of each entry). `_EXACT` entries require
# the FULL field name (not just the last dotted segment) because their
# last segment alone would either be ambiguous or wouldn't isolate them
# from an unrelated field (e.g. `event.code`'s last segment "code" is not,
# on its own, a safe generic marker).
# -----------------------------------------------------------------------------
_DATA_SOURCE_SELECTOR_EXACT = {"eventid", "eventcode", "event.code", "syscall", "auditd.data.syscall"}
_DATA_SOURCE_SELECTOR_LAST_SEGMENT = {
    "eventid", "eventcode", "syscall",
    "eventsource",  # AWS CloudTrail's service-identifier field (ec2.amazonaws.com, ...)
    "provider",  # Elastic's event.provider (same AWS-service-identifier role as eventSource)
    "dataset",  # ECS data_stream.dataset - which integration produced the event
    "sourcetype",  # Splunk's own data-source-type identifier
}


def field_role(field: Optional[str]) -> str:
    """Resolve `field` (a Sigma leaf's field name, dotted path or bare) to
    one of the ROLES above. Pure field-name lookup - never inspects a
    value. Returns GENERIC for anything not in one of the documented sets
    above, by design (see module docstring: unclear -> GENERIC, never
    guessed)."""
    f = (field or "").lower()
    if f in _DATA_SOURCE_SELECTOR_EXACT:
        return DATA_SOURCE_SELECTOR

    norm = _normalize(field)
    if norm in _DATA_SOURCE_SELECTOR_LAST_SEGMENT:
        return DATA_SOURCE_SELECTOR
    if norm in _FUNCTIONAL_CONSTRAINT_FIELDS:
        return FUNCTIONAL_CONSTRAINT
    if norm in _ATTACKER_AUTHORED_TEXT_FIELDS:
        return ATTACKER_AUTHORED_TEXT
    if norm in _BINARY_IDENTITY_FIELDS:
        return BINARY_IDENTITY
    return GENERIC
