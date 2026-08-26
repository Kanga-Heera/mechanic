"""Fault-isolated Sigma rule loader (Component 1).

pySigma's own `SigmaCollection.load_ruleset()` has zero defensive coding in
the "parse untrusted YAML into a rule object" path: any single malformed file
in a batch kills the whole load, and even its `collect_errors=True` mode only
catches `SigmaError` subclasses - not the AttributeError/TypeError crashes
that real-world third-party rules trigger (bare-int `id:`, correlation-shaped
documents, null date fields). A second, independent crash class happens
*after* successful parsing, during validation (e.g. a null `references:`
entry blowing up a validator's `re.match()` call) - so isolation has to wrap
both the load step and each individual validator call, not just the load.

This module does both, one file/document/validator-call at a time, and turns
every failure into a structured `FailureRecord` instead of a traceback.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaRuleLocation
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator

from mechanic import categories
from mechanic.discovery import discover_files

Rule = Union[SigmaRule, SigmaCorrelationRule]


@dataclass
class FailureRecord:
    file: str
    stage: str  # yaml_parse | rule_construct | validate
    category: str
    exception_type: str
    message: str
    line: Optional[int] = None
    fix_hint: str = ""
    validator: Optional[str] = None  # populated for stage == "validate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "stage": self.stage,
            "category": self.category,
            "exception_type": self.exception_type,
            "message": self.message,
            "line": self.line,
            "fix_hint": self.fix_hint,
            "validator": self.validator,
        }


@dataclass
class LoadedRule:
    file: str
    rule: Rule
    rule_type: str  # "standard" | "correlation"
    issues: list[FailureRecord] = field(default_factory=list)

    @property
    def title(self) -> str:
        return getattr(self.rule, "title", None) or "<untitled>"

    @property
    def rule_id(self) -> Optional[str]:
        rid = getattr(self.rule, "id", None)
        return str(rid) if rid is not None else None


@dataclass
class ScanResult:
    root: str
    rules: list[LoadedRule] = field(default_factory=list)
    failures: list[FailureRecord] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def files_ok(self) -> int:
        loaded_files = {lr.file for lr in self.rules}
        return len(loaded_files)

    @property
    def files_failed(self) -> int:
        failed_files = {f.file for f in self.failures if f.stage in ("yaml_parse", "rule_construct")}
        return len(failed_files)

    def failures_by_category(self) -> dict[str, list[FailureRecord]]:
        grouped: dict[str, list[FailureRecord]] = {}
        for f in self.failures:
            grouped.setdefault(f.category, []).append(f)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_ok": self.files_ok,
            "files_failed": self.files_failed,
            "rules_loaded": len(self.rules),
            "failures_total": len(self.failures),
            "failures_by_category": {
                cat: len(items) for cat, items in self.failures_by_category().items()
            },
            "rules": [
                {"file": lr.file, "type": lr.rule_type, "id": lr.rule_id, "title": lr.title}
                for lr in self.rules
            ],
            "failures": [f.to_dict() for f in self.failures],
        }


def _yaml_error_line(exc: yaml.YAMLError) -> Optional[int]:
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return mark.line + 1
    return None


def _is_correlation_doc(doc: dict) -> bool:
    return isinstance(doc, dict) and "correlation" in doc


def _construct_rule(doc: dict, source: SigmaRuleLocation) -> Rule:
    """Preflight-check then construct a single rule/correlation-rule document.

    Raises on any problem; callers are expected to wrap this in try/except and
    hand the exception to `categories.categorize()`.
    """
    categories.run_preflight(doc)
    if _is_correlation_doc(doc):
        return SigmaCorrelationRule.from_dict(doc, collect_errors=False, source=source)
    return SigmaRule.from_dict(doc, collect_errors=False, source=source)


def parse_text(
    raw_text: str, source_path: Path, file_str: Optional[str] = None
) -> tuple[list[LoadedRule], list[FailureRecord]]:
    """Load every document out of already-in-memory YAML text, isolated from
    other files/documents exactly like `load_file`.

    Factored out of `load_file` so Part 1 (semantic diff) can parse rule text
    reconstructed from a specific git blob (a historical version of a file
    that may not exist on disk at all) through the exact same isolation and
    categorization path as a normal on-disk scan - no separate/duplicate
    parsing logic. `source_path` is used only for `SigmaRuleLocation` (error
    messages / provenance); `file_str` overrides what failure records report
    as the file (defaults to `str(source_path)`), useful for labeling a
    historical blob as e.g. "rules/x.yml@abc1234".
    """
    rules: list[LoadedRule] = []
    failures: list[FailureRecord] = []
    file_str = file_str if file_str is not None else str(source_path)

    try:
        docs = list(yaml.safe_load_all(raw_text))
    except yaml.YAMLError as e:
        match = categories.categorize(e, categories.STAGE_YAML_PARSE, raw_text)
        failures.append(
            FailureRecord(
                file=file_str,
                stage="yaml_parse",
                category=match.category,
                exception_type=type(e).__name__,
                message=str(e),
                line=_yaml_error_line(e),
                fix_hint=match.hint,
            )
        )
        return rules, failures

    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            failures.append(
                FailureRecord(
                    file=file_str,
                    stage="rule_construct",
                    category="non_mapping_document",
                    exception_type="TypeError",
                    message=f"Document is a {type(doc).__name__}, expected a mapping",
                    fix_hint="This YAML document at the top level is not a mapping "
                    "(key: value block) - Sigma rules must be. Check for a stray "
                    "scalar or list document.",
                )
            )
            continue
        try:
            source = SigmaRuleLocation(source_path)
            rule = _construct_rule(doc, source)
        except Exception as e:  # noqa: BLE001 - deliberately broad, this is the isolation boundary
            match = categories.categorize(e, categories.STAGE_RULE_CONSTRUCT, raw_text)
            failures.append(
                FailureRecord(
                    file=file_str,
                    stage="rule_construct",
                    category=match.category,
                    exception_type=type(e).__name__,
                    message=str(e),
                    fix_hint=match.hint,
                )
            )
            continue

        rule_type = "correlation" if isinstance(rule, SigmaCorrelationRule) else "standard"
        rules.append(LoadedRule(file=file_str, rule=rule, rule_type=rule_type))

    return rules, failures


def load_file(path: Path) -> tuple[list[LoadedRule], list[FailureRecord]]:
    """Load every document in a single file, isolated from every other file.

    A YAML parse error kills the *file* (nothing recoverable further down the
    stream once the parser derails), but a construction error on one document
    of a multi-document file does not prevent the other documents in the same
    file from loading.
    """
    file_str = str(path)
    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return [], [
            FailureRecord(
                file=file_str,
                stage="yaml_parse",
                category="unreadable_file",
                exception_type=type(e).__name__,
                message=str(e),
                fix_hint="File could not be opened/read from disk.",
            )
        ]
    return parse_text(raw_text, path, file_str)


def load_ruleset(root: Path, fmt: str = "sigma") -> ScanResult:
    """Load every rule file under `root`, isolating failures per file/document."""
    root = Path(root)
    result = ScanResult(root=str(root))
    files = discover_files(root, fmt)
    result.files_scanned = len(files)
    for path in files:
        rules, failures = load_file(path)
        result.rules.extend(rules)
        result.failures.extend(failures)
    return result


def default_validators() -> dict[str, type]:
    """The full set of registered pySigma validators (core + any installed plugin
    packages, e.g. pySigma-validators-sigmahq), keyed by identifier."""
    plugins = InstalledSigmaPlugins.autodiscover()
    return dict(plugins.validators)


def validate_rules(
    loaded_rules: list[LoadedRule],
    validator_classes: Optional[dict[str, type]] = None,
) -> list[FailureRecord]:
    """Run every validator against every standard rule, isolating each
    (rule, validator) pair so one crashing validator can't take down the
    whole validation pass - and attaches per-rule issues onto the LoadedRule
    for downstream consumers.

    Correlation rules are skipped: pySigma's validator framework targets
    SigmaRule, not SigmaCorrelationRule.
    """
    validator_classes = validator_classes or default_validators()
    validator = SigmaValidator(validator_classes.values())
    name_by_classname = {cls.__name__: name for name, cls in validator_classes.items()}

    failures: list[FailureRecord] = []
    for loaded in loaded_rules:
        if loaded.rule_type != "standard":
            continue
        for v in validator.validators:
            v_name = name_by_classname.get(type(v).__name__, type(v).__name__)
            try:
                v.validate(loaded.rule)
            except Exception as e:  # noqa: BLE001 - isolation boundary
                match = categories.categorize(e, categories.STAGE_VALIDATE)
                record = FailureRecord(
                    file=loaded.file,
                    stage="validate",
                    category=match.category,
                    exception_type=type(e).__name__,
                    message=str(e),
                    fix_hint=match.hint,
                    validator=v_name,
                )
                failures.append(record)
                loaded.issues.append(record)

    try:
        validator.finalize()
    except Exception:  # noqa: BLE001 - finalize() runs cross-rule checks; isolate too
        pass

    return failures
