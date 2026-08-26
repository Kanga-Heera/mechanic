"""v1's original atom-classification constants and logic, preserved verbatim
(not re-derived from memory) for the Part 2c ablation study. This module is
NOT used by any real classification path - `fragility.py`/`text_fragility.py`
never import it except from the ablation harness in `scratchpad/`.

TWO distinct historical states live here, and conflating them was a real
measurement bug caught during review - see RESULTS.md's Part 2c re-run:

  PRE-FIX state (`is_protected_v1` / `classify_atom_v1`): the FIRST, still-
  broken attempt - EXACT field-name matching (not last-dotted-segment), so
  `event.action` never matches a bare `action` protection entry. This state
  was never the documented v1 baseline; it's ONE STEP EARLIER than it.

  DOCUMENTED-v1 state (`is_protected_v1_documented` /
  `classify_atom_v1_documented`): the state that actually PRODUCED the
  documented kappa=0.412 / 57.8% baseline - last-dotted-segment matching and
  context-gating already fixed (mid-investigation, before Stage 2 started),
  but still: Windows-only tool list, v1's narrow (example-derived) protected-
  literal categories, blanket EventID/syscall exclusion, and no negation
  awareness. THIS is the correct "list fixes OFF" comparator for isolating
  structural detection's marginal contribution over the real baseline - using
  the pre-fix state for that comparison was the bug: it reverts the lists
  further back than v1 itself ever was, making "structural ON, lists OFF"
  land below the 0.412 baseline for a reason that has nothing to do with
  structural detection.

Both states share the same tool list / tool-detection logic and the same
protected VALUE patterns (narrow: Run/RunOnce, Winlogon Userinit/Shell, the
6-pipe subset, well-known SIDs) - the dotted-path fix only ever affected
FIELD-NAME matching (`ALWAYS_PROTECTED_FIELD_NAMES`,
`CLOUD_AUDIT_ACTION_FIELD_SUFFIXES`), never value-pattern matching, which is
why only two functions need a documented-state variant.
"""

from __future__ import annotations

import re
from typing import Any

CLOUD_AUDIT_ACTION_FIELD_SUFFIXES = {
    "eventname",
    "event_name",
    "operationname",
    "operation_name",
    "methodname",
    "method_name",
    "eventtype",
    "event_type",
    "operation",
    "action",
}
CLOUD_AUDIT_CONTEXT_RE = re.compile(
    r"cloudtrail|azure\.auditlogs|gcp\.audit|kubernetes\.audit|\bokta\b|office365|o365|m365|"
    r"unifiedauditlog|amazonaws\.com|\.azure\.com",
    re.I,
)
ALWAYS_PROTECTED_FIELD_NAMES = {"ticketencryptiontype", "logontype"}
PROTECTED_VALUE_PATTERNS = [
    re.compile(r"currentversion\\+run(once)?\b", re.I),
    re.compile(r"winlogon\\+(userinit|shell)\b", re.I),
    re.compile(r"\\(svcctl|atsvc|lsarpc|samr|netlogon|spoolss|eventlog|winreg|browser|wkssvc|srvsvc)\b", re.I),
    re.compile(r"\bs-1-5-(18|19|20|32-544)\b", re.I),
]
LOLBIN_NAMES = {
    "certutil", "regsvr32", "mshta", "rundll32", "wmic", "bitsadmin", "schtasks", "wscript", "cscript",
    "msiexec", "installutil", "regasm", "regsvcs", "msbuild", "mavinject", "cmstp", "forfiles", "xwizard",
    "sc", "net", "netsh", "powershell", "cmd", "curl", "psexec", "at", "reg", "certreq", "msdt", "control",
    "odbcconf", "diskshadow", "ftp", "tftp", "hh",
}
CMDLET_RE = re.compile(
    r"\b(?:invoke|new|get|set|add|remove|start|stop|import|export|write|read|enable|disable)-[a-z][a-z0-9]+\b",
    re.I,
)
EXE_RE = re.compile(r"\b[a-z0-9_\-]+\.exe\b", re.I)

_HASH_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.I)
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

TIER_RANK = {"IOC": 0, "Artifact": 1, "Tool": 2, "TTP": 3}


def rule_is_cloud_audit_context(field_value_pairs: list[tuple[str, Any]]) -> bool:
    for field, value in field_value_pairs:
        haystack = f"{field or ''} {value if isinstance(value, str) else ''}"
        if CLOUD_AUDIT_CONTEXT_RE.search(haystack):
            return True
    return False


def is_protected_v1(field: str, value: Any, cloud_context: bool) -> bool:
    field_exact = (field or "").lower()  # BUG (preserved): exact match, not last-segment
    if field_exact in ALWAYS_PROTECTED_FIELD_NAMES:
        return True
    haystack = f"{field or ''} {value if isinstance(value, str) else ''}"
    for pat in PROTECTED_VALUE_PATTERNS:
        if pat.search(haystack):
            return True
    if cloud_context and field_exact in CLOUD_AUDIT_ACTION_FIELD_SUFFIXES:
        return True
    return False


def _last_segment(field: str) -> str:
    return (field or "").lower().rsplit(".", 1)[-1]


def is_protected_v1_documented(field: str, value: Any, cloud_context: bool) -> bool:
    """The state that actually produced the documented kappa=0.412 baseline:
    last-dotted-segment matching + context-gating (both already fixed by
    this point), v1's narrow value-pattern categories (unaffected by that
    fix - see module docstring)."""
    field_last = _last_segment(field)
    if field_last in ALWAYS_PROTECTED_FIELD_NAMES:
        return True
    haystack = f"{field or ''} {value if isinstance(value, str) else ''}"
    for pat in PROTECTED_VALUE_PATTERNS:
        if pat.search(haystack):
            return True
    if cloud_context and field_last in CLOUD_AUDIT_ACTION_FIELD_SUFFIXES:
        return True
    return False


def classify_atom_v1_documented(field: str, value: Any) -> str:
    """Same as `classify_atom_v1` (no negation parameter - v1 never looked at
    polarity) but field checks use last-dotted-segment matching, matching the
    documented-baseline state."""
    field_last = _last_segment(field)
    if field_last in ("eventid", "eventcode", "syscall") or (field or "").lower() in _EVENTID_SYSCALL_FIELDS_V1:
        return "IOC"  # blanket exclude, unconditional - the v1 bug (this part was never affected by the dotted-path fix)
    if is_raw_ioc_v1(value):
        return "IOC"
    if is_tool_v1(value):
        return "Tool"
    return "Artifact"


def is_raw_ioc_v1(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_HASH_RE.match(value)) or bool(_IPV4_RE.match(value))


def is_tool_v1(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    base = value
    for sep in ("\\", "/"):
        base = base.split(sep)[-1]
    base = base.lower()
    if "." in base:
        base = base.rsplit(".", 1)[0]
    if base in LOLBIN_NAMES:
        return True
    if CMDLET_RE.search(value):
        return True
    if EXE_RE.search(value):
        return True
    return False


_EVENTID_SYSCALL_FIELDS_V1 = {"eventid", "eventcode", "event.code", "syscall", "auditd.data.syscall"}


def classify_atom_v1(field: str, value: Any) -> str:
    """No negation parameter: v1 never looked at polarity at all."""
    cloud_context = False  # computed by caller across the whole rule, see classify_rule_v1
    field_l = (field or "").lower()
    if field_l in _EVENTID_SYSCALL_FIELDS_V1 or field_l.rsplit(".", 1)[-1] in ("eventid", "eventcode", "syscall"):
        return "IOC"  # blanket exclude, unconditional - the v1 bug
    if is_raw_ioc_v1(value):
        return "IOC"
    if is_tool_v1(value):
        return "Tool"
    return "Artifact"
