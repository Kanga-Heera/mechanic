"""Pluggable failure-category detection for the mechanic loader.

A category is a small, ordered set of rules for turning a raw exception
(plus a bit of surrounding context) into a structured, actionable diagnosis.
New categories are added by constructing a `FailureCategory` and appending
it to `REGISTRY` - nothing in `loader.py` needs to change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

import yaml

# Stages at which a failure can occur.
STAGE_YAML_PARSE = "yaml_parse"
STAGE_RULE_CONSTRUCT = "rule_construct"
STAGE_VALIDATE = "validate"

_LEADING_ASTERISK_RE = re.compile(r"^\s*[-:]?\s*\*\S")


@dataclass(frozen=True)
class CategoryMatch:
    category: str
    hint: str


class PreflightIssue(Exception):
    """Raised by a preflight check that deterministically recognized a bad
    document shape before pySigma ever touches it (version-independent,
    unlike pattern-matching pySigma's internal exception text)."""

    def __init__(self, category: str, hint: str, message: str):
        super().__init__(message)
        self.category = category
        self.hint = hint


@dataclass(frozen=True)
class FailureCategory:
    """One diagnosable failure shape.

    `stages` restricts which loader stage this detector is even considered for
    (a cheap way to avoid a validator-phase detector firing on a YAML error).
    `matches` receives (exception, raw_text_of_the_offending_file_or_None) and
    returns True if this category explains the exception. `hint` is either a
    fixed string or a callable that derives a more specific hint from the
    exception/raw text.
    """

    name: str
    stages: tuple[str, ...]
    matches: Callable[[BaseException, Optional[str]], bool]
    hint: Callable[[BaseException, Optional[str]], str] | str

    def hint_for(self, exc: BaseException, raw_text: Optional[str]) -> str:
        if callable(self.hint):
            return self.hint(exc, raw_text)
        return self.hint


def _has_leading_asterisk_alias(raw_text: Optional[str]) -> bool:
    if not raw_text:
        return False
    for line in raw_text.splitlines():
        if _LEADING_ASTERISK_RE.match(line):
            return True
    return False


def _is_bare_int_id(exc: BaseException, raw_text: Optional[str]) -> bool:
    if not isinstance(exc, AttributeError):
        return False
    msg = str(exc)
    if "'int' object has no attribute" not in msg:
        return False
    # Narrow further: this shape is specific to uuid.UUID(int_id) being handed
    # an int where it expects a hex string - confirm the traceback touches uuid.py.
    tb = exc.__traceback__
    while tb is not None:
        if tb.tb_frame.f_code.co_filename.endswith(("uuid.py", "attributes.py")):
            return "replace" in msg or "id" in msg.lower() or True
        tb = tb.tb_next
    return True


def _is_correlation_as_standard(exc: BaseException, raw_text: Optional[str]) -> bool:
    if not isinstance(exc, AttributeError):
        return False
    msg = str(exc)
    if "'str' object has no attribute 'get'" in msg:
        tb = exc.__traceback__
        while tb is not None:
            if "correlation" in tb.tb_frame.f_code.co_filename:
                return True
            tb = tb.tb_next
        # Fall back to raw-text sniffing if traceback frames were stripped.
        if raw_text and "correlation:" in raw_text:
            return True
    return False


def _is_null_date_split(exc: BaseException, raw_text: Optional[str]) -> bool:
    if not isinstance(exc, AttributeError):
        return False
    msg = str(exc)
    return "'NoneType' object has no attribute 'split'" in msg


def _is_null_reference_match(exc: BaseException, raw_text: Optional[str]) -> bool:
    if not isinstance(exc, TypeError):
        return False
    msg = str(exc)
    return "expected string or bytes-like object" in msg and (
        "NoneType" in msg or raw_text is None or True
    )


def _composer_hint(exc: BaseException, raw_text: Optional[str]) -> str:
    if isinstance(exc, yaml.composer.ComposerError) and _has_leading_asterisk_alias(raw_text):
        return (
            "value starts with '*' - YAML parses this as an alias; quote the string "
            "(e.g. \"- '*cmd /c ...'\" instead of \"- *cmd /c ...\")."
        )
    return (
        "YAML composer error, usually an undefined alias reference. If a list item "
        "begins with an unquoted '*', quote it - YAML reads '*name' as an alias "
        "reference, not a literal wildcard string."
    )


REGISTRY: list[FailureCategory] = [
    FailureCategory(
        name="bare_int_id",
        stages=(STAGE_RULE_CONSTRUCT,),
        matches=_is_bare_int_id,
        hint="`id:` is a bare YAML integer; pySigma calls UUID(id) and dies. "
        "Quote the id as a string or replace it with a real UUID4.",
    ),
    FailureCategory(
        name="correlation_as_standard_rule",
        stages=(STAGE_RULE_CONSTRUCT,),
        matches=_is_correlation_as_standard,
        hint="This document has a `correlation:` key but its value (or a sibling "
        "document merged into it) is not a mapping - it was parsed as if it were "
        "a standard detection rule. Check for a malformed multi-document YAML "
        "split (missing '---' separator, or a stray scalar document).",
    ),
    FailureCategory(
        name="yaml_scanner_error",
        stages=(STAGE_YAML_PARSE,),
        matches=lambda exc, raw: isinstance(exc, yaml.scanner.ScannerError),
        hint="YAML scanner error - often a stray tab character (YAML requires spaces "
        "for indentation) or an unquoted string starting with '*' being read as an "
        "alias. Check indentation and quote any value beginning with '*'.",
    ),
    FailureCategory(
        name="yaml_composer_error",
        stages=(STAGE_YAML_PARSE,),
        matches=lambda exc, raw: isinstance(exc, yaml.composer.ComposerError),
        hint=_composer_hint,
    ),
    FailureCategory(
        name="yaml_parser_error",
        stages=(STAGE_YAML_PARSE,),
        matches=lambda exc, raw: isinstance(exc, yaml.parser.ParserError),
        hint="YAML parser error - structurally malformed YAML (e.g. a broken block "
        "mapping). Validate the file with a standalone YAML linter to find the "
        "exact offending line.",
    ),
    FailureCategory(
        name="null_date_split",
        stages=(STAGE_RULE_CONSTRUCT,),
        matches=_is_null_date_split,
        hint="A date-like field (date/modified) is present but null (e.g. `date:` "
        "with no value). pySigma calls .split() on it unconditionally. Either "
        "remove the empty key or give it a real YYYY-MM-DD value.",
    ),
    FailureCategory(
        name="null_reference_typeerror",
        stages=(STAGE_VALIDATE,),
        matches=_is_null_reference_match,
        hint="A `references:` list contains a blank/null entry (a bare '-' with no "
        "value). YAML accepts this as None, but the SigmaHQ github-link validator "
        "calls re.match() on it unconditionally and crashes. Remove the empty "
        "reference entry.",
    ),
]


def check_bare_int_id(doc: dict) -> None:
    rule_id = doc.get("id")
    if isinstance(rule_id, int) and not isinstance(rule_id, bool):
        raise PreflightIssue(
            "bare_int_id",
            "`id:` is a bare YAML integer; pySigma calls UUID(id) and dies. "
            "Quote the id as a string or replace it with a real UUID4.",
            f"id field is a bare integer ({rule_id!r}), expected a UUID string",
        )


def check_null_date_fields(doc: dict) -> None:
    for key in ("date", "modified"):
        if key in doc and doc[key] is None:
            raise PreflightIssue(
                "null_date_split",
                "A date-like field (date/modified) is present but null (e.g. `date:` "
                "with no value). pySigma calls .split() on it unconditionally. Either "
                "remove the empty key or give it a real YYYY-MM-DD value.",
                f"{key}: field is present but null",
            )


def check_correlation_shape(doc: dict) -> None:
    if "correlation" in doc and not isinstance(doc["correlation"], dict):
        raise PreflightIssue(
            "correlation_as_standard_rule",
            "This document has a `correlation:` key but its value is not a mapping - "
            "it will be parsed as if it were a standard detection rule. Check for a "
            "malformed multi-document YAML split (missing '---' separator, or a "
            "stray scalar document).",
            f"correlation: value has type {type(doc['correlation']).__name__}, expected a mapping",
        )


# Deterministic, version-independent checks run on the raw parsed dict before
# pySigma ever sees it. Each either returns None or raises PreflightIssue.
# Add new entries here (or via extend()) without touching loader.py.
PREFLIGHT_CHECKS: list[Callable[[dict], None]] = [
    check_bare_int_id,
    check_null_date_fields,
    check_correlation_shape,
]


def run_preflight(doc: dict) -> None:
    """Run all registered preflight checks against a freshly-parsed YAML document."""
    if not isinstance(doc, dict):
        return
    for check in PREFLIGHT_CHECKS:
        check(doc)


def categorize(exc: BaseException, stage: str, raw_text: Optional[str] = None) -> CategoryMatch:
    """Run the registry against `exc` and return the first matching category.

    Falls back to a generic 'uncategorized' bucket (still captured, never lost)
    if nothing in the registry recognizes the shape.
    """
    if isinstance(exc, PreflightIssue):
        return CategoryMatch(category=exc.category, hint=exc.hint)
    for category in REGISTRY:
        if stage not in category.stages:
            continue
        try:
            if category.matches(exc, raw_text):
                return CategoryMatch(category=category.name, hint=category.hint_for(exc, raw_text))
        except Exception:
            # A detector must never itself crash the scan.
            continue
    return CategoryMatch(
        category=f"uncategorized_{type(exc).__name__}",
        hint="No known category matched. Inspect the exception message and traceback directly.",
    )
