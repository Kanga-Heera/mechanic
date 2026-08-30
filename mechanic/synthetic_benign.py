"""Stage 3 Phase 3, Part 3: synthetic benign-event generation for the
automated stratified run.

Phase 1/2 hand-authored one semantically-realistic benign event per rule
(a specific, plausible legitimate PowerShell backup script; an ordinary
`Get-Process` pipeline; ...). That does not scale to an automated batch of
30-40 arbitrary SigmaHQ rules with no per-rule domain-tuning. This module
instead substitutes the rule's OWN fragile atom's field value for a fixed,
generic, field-category-appropriate benign placeholder (reusing
`mechanic.evasion`'s field-category gate, not a second one), leaving every
other field of the genuine template event untouched.

HONESTY LIMIT, stated here and repeated in docs/stage3-phase3-status.md:
this is a DELIBERATELY WEAKER benign check than Phase 1/2's hand-picked
ones. A human choosing "an ordinary Get-Process pipeline" to specifically
stress-test an overly-broad repair is a sharper adversarial probe than one
generic substitution can be. What this DOES catch: a repair that widened
its match condition enough to also fire on the most generic, textbook-
benign version of the same field - which is exactly what Phase 1's R3
case (widening to `CommandLine|contains: 'powershell'`) would have failed
even this weaker check. What it does NOT catch: a repair that is broad in
some other, less obvious way this one substitution doesn't happen to
probe.

Where no safe generic substitution exists for a field's category (a raw
IOC with no natural "obviously benign" placeholder recognized here), this
returns None and the run reports NO_NEW_FALSE_POSITIVES as not-applicable
for that rule - never a fabricated benign event."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from mechanic import evasion

# Ordinary, textbook-benign administrative commands - picked for being
# unambiguously non-malicious on their own, not tuned per rule.
_BENIGN_COMMANDLINES = ["ipconfig /all", "systeminfo", "whoami /all", "tasklist /v"]

_BENIGN_DOC_IP = "203.0.113.5"  # RFC 5737 TEST-NET-3 - reserved for documentation, never a real routable host
_BENIGN_DOC_DOMAIN = "example.com"  # RFC 2606 - reserved for documentation

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$")


def _looks_like_ipv4_or_v6(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def synthetic_benign_event(template_event: dict, field: str, value: Any) -> Optional[dict]:
    """One generic, category-appropriate benign substitution of
    `template_event[field]`, or None if no safe generic substitution is
    recognized for this value's shape (e.g. a hash, a registry path, an
    unrecognized IOC format) - callers must treat None as "no benign event
    available", never invent a placeholder of their own."""
    if not isinstance(value, str) or field not in template_event or not isinstance(template_event.get(field), str):
        return None
    category = evasion._field_category(field)
    replacement: Optional[str] = None
    if category == "commandline":
        for candidate in _BENIGN_COMMANDLINES:
            if candidate.lower() not in template_event[field].lower():
                replacement = candidate
                break
    elif category == "path_identity":
        replacement = "C:\\Windows\\System32\\notepad.exe" if "\\" in value else "notepad.exe"
    else:
        if _looks_like_ipv4_or_v6(value):
            replacement = _BENIGN_DOC_IP
        elif _DOMAIN_RE.match(value) and not _looks_like_ipv4_or_v6(value):
            replacement = _BENIGN_DOC_DOMAIN

    if replacement is None or replacement == value:
        return None
    new_event = dict(template_event)
    new_event[field] = replacement
    return new_event
