"""Per-file fragility classification for Elastic (TOML/EQL/KQL) and Splunk
(YAML/SPL) rules - QUARANTINED, not part of the CORE. This is exactly the
`_elastic_fragility`/`_splunk_fragility` logic that used to live in
`mechanic/priority.py`, moved here unchanged (see git history on this file)
as part of scoping the CORE to Sigma-only - see docs/multiformat-
experimental.md for why and docs/core-vs-experiment.md for the enforcement.

Every `FragilitySignal` this module produces carries `and_or_corrected=False`
and a non-None `caveat` explaining that it was NOT computed with the AND/OR
combination correction external validation (against MITRE's STP) showed to
be necessary for Sigma's real AST - `mechanic.priority.RuleSignals.narrative`
already renders that caveat into plain prose unconditionally whenever it's
present, so nothing in this module has to duplicate that rendering.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

from mechanic.experimental.multiformat import splunk_macros, text_fragility
from mechanic.priority import FragilitySignal

_AND_OR_CAVEAT = (
    "This tier comes from the text-only path (no AST): it is capped at 'medium' "
    "confidence and computed WITHOUT the AND/OR combination correction (AND->MIN, "
    "OR->MAX) that external validation against STP showed to be necessary -- the "
    "correction requires walking a real parse tree, which does not exist for this "
    "rule language here. Treat this tier as less trustworthy than a Sigma/AST tier."
)


def classify_elastic_file(path: Path) -> FragilitySignal:
    try:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
    except Exception as e:
        return FragilitySignal(None, "low", False, True, f"failed to parse TOML: {e}", [], {}, [], None)
    rule = doc.get("rule", {})
    rtype = rule.get("type", "")
    if rtype == "threat_match":
        return FragilitySignal(
            "IOC", "medium", False, False, None, [], {}, [],
            "Tier assigned from rule type ('threat_match' = indicator matching), not from content "
            "classification -- no atoms were extracted or scored. " + _AND_OR_CAVEAT,
        )
    query = rule.get("query")
    if not query:
        return FragilitySignal(None, "low", False, True, "no 'query' field present in rule", [], {}, [], None)
    try:
        atoms, ok = text_fragility.extract_elastic_atoms(query)
        if not ok:
            return FragilitySignal(None, "low", False, True, "regex-based atom extraction found nothing in query text", [], {}, [], None)
        result = text_fragility.classify_text_rule(atoms, ok)
    except Exception as e:
        return FragilitySignal(None, "low", False, True, f"text classification failed: {e}", [], {}, [], None)
    atom_dicts = [{"field": a.field, "value": a.value, "negated": a.negated} for a in atoms]
    if result.unscoreable or result.tier is None:
        return FragilitySignal(None, "low", False, True, "text classifier returned no tier", result.structural_findings, {}, atom_dicts, None)
    return FragilitySignal(
        result.tier, result.confidence, False, False, None,
        result.structural_findings, {}, atom_dicts, _AND_OR_CAVEAT,
    )


def classify_splunk_file(path: Path) -> FragilitySignal:
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception as e:
        return FragilitySignal(None, "low", False, True, f"failed to parse YAML: {e}", [], {}, [], None)
    search = doc.get("search", "") if isinstance(doc, dict) else ""
    if not search:
        return FragilitySignal(None, "low", False, True, "no 'search' field present in rule", [], {}, [], None)
    try:
        resolved, *_ = splunk_macros.resolve_macros(search)
        atoms, ok = text_fragility.extract_splunk_atoms(resolved)
        if not ok:
            return FragilitySignal(None, "low", False, True, "regex-based atom extraction found nothing in resolved search text", [], {}, [], None)
        result = text_fragility.classify_text_rule(atoms, ok, raw_text=resolved, pre_resolution_text=search)
    except Exception as e:
        return FragilitySignal(None, "low", False, True, f"text classification failed: {e}", [], {}, [], None)
    atom_dicts = [{"field": a.field, "value": a.value, "negated": a.negated} for a in atoms]
    if result.unscoreable or result.tier is None:
        return FragilitySignal(None, "low", False, True, "text classifier returned no tier", result.structural_findings, {}, atom_dicts, None)
    return FragilitySignal(
        result.tier, result.confidence, False, False, None,
        result.structural_findings, {}, atom_dicts, _AND_OR_CAVEAT,
    )


FRAGILITY_FN = {"elastic_toml": classify_elastic_file, "splunk_yaml": classify_splunk_file}
