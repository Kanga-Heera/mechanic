"""RSigma CLI wrapper with the silent-zero guard (Stage 3, Part 1).

Context (see docs/stage3-harness-evaluation.md for the full investigation):
RSigma was adopted PARTIALLY (Recommendation B) as the Stage 3 verification
harness, wrapped via its CLI (`engine eval`) rather than reimplemented. The
investigation's headline risk was RSigma's *silent-zero* failure mode: a
rule whose fields don't exist under the paths RSigma parsed an event into
reports "0 matches" with no error, indistinguishable from a genuine
no-fire. That was proven live on one rule. Building this module (Part 2 of
this phase) surfaced two more instances of the same underlying problem
that the investigation had not caught, both fixed here rather than glossed
over:

1. A single-JSON-event file with an incorrectly-escaped backslash
   (`\\M` is not a valid JSON escape) is *silently dropped* by
   `-e @file` - `events_observed` in the `--observe-fields` report reads 0,
   but the plain summary line still says "Processed 1 events, 0 matches" as
   if the event had been evaluated. Caught by cross-checking
   `events_observed` against the expected event count, not just checking
   `missing` fields.

2. The field-mapping problem is NOT limited to Security/TaskScheduler-style
   "builtin" rules, and RSigma's own builtin `-p sysmon` pipeline does NOT
   fix it for process_creation rules against raw EVTX either - live testing
   (this phase, not the original investigation) found `-p sysmon` still
   reports every Sysmon EventData field as missing (and adds a spurious
   "EventID" requirement of its own that also goes unmet). The original
   investigation's Task 2 table claim that Sysmon-shaped rules "work with
   zero extra setup" was WRONG and is corrected here: raw EVTX needs a
   field-mapping pipeline unconditionally, regardless of rule category.
   Nor is the flattening scheme uniform: WMI-Activity events store their
   payload under `Event.UserData.<ProviderSpecificName>.*`, not
   `Event.EventData.*` at all, so a fixed System-vs-EventData guess (the
   naive design considered and rejected here) is also wrong on its own
   terms - it would have silently mis-generated a pipeline that still
   produces missing fields for a whole channel family.

The fix used throughout this module is *discovery, not guessing*: run one
dry pass with no pipeline, `--observe-fields`, and build the field mapping
from whatever real nested paths RSigma actually reports for that specific
event, matched by exact last-path-segment against the rule's own field
names. This handled all three shapes above (System/EventData/UserData)
without knowing about any of them in advance - see `_discover_pipeline`.

Guarantee this module makes: every value coming out of `evaluate()` is
either `status="trusted"` (both field presence AND expected-event-count are
independently confirmed) or `status="unverifiable"` (loud, with the
specific reason) - a plain boolean fire/no-fire is never handed back
without one of those two labels attached. Callers (mechanic/gate.py, the
`mechanic verify` CLI command) must never treat "unverifiable" as either a
pass or a fail.

Stage 3 Phase 2, Part 3 added multi-record EVTX per-record accounting
(previously: any file with more than 1 record came back as a single
UNVERIFIABLE aggregate - see docs/stage3-phase1-status.md). Building the
real multi-record test fixture (a genuine, locally-exported multi-record
.evtx - see tests/test_verify.py's module docstring for how it was made
and why) surfaced a THIRD instance of the exact same silent-zero family:

3. Last-path-segment discovery (finding #2's fix) matched a rule field
   name against a discovered path's raw final dot-segment - which works for
   a Sysmon-style NAMED <Data Name='Image'>...</Data> element (RSigma
   reports it at .../EventData/Image), but not for a classic/legacy,
   non-manifested Windows Event Log's UNNAMED <Data>...</Data> element (no
   Name attribute to key by at all): RSigma reports that one's content at
   .../EventData/Data/#text, whose last segment is the literal string
   "#text", not "Data" - so a rule field named "Data" came back unresolved
   even though the value was right there. Fixed in `_match_key` by
   stripping a trailing ".#text" pseudo-segment before comparing - the
   mapping itself still stores the full original path, only the *matching*
   key is adjusted.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional, Union

import yaml

from mechanic import ast_repr, loader

PINNED_VERSION = "0.21.0"
RSIGMA_BIN_ENV = "MECHANIC_RSIGMA_BIN"

# Windows EVTX <System> block fields worth trying first when a discovered
# field name has more than one candidate path (see _discover_pipeline). This
# is a tie-breaker, not a guess used on its own - every field still has to
# actually be found in the dry pass's observed paths before it's trusted.
_SYSTEM_LIKE_HINTS = ("Event.System.",)
_EVENTDATA_LIKE_HINTS = ("Event.EventData.",)

EventDict = dict[str, Any]


class VerifyError(Exception):
    """Raised for setup/usage problems (bad binary, unreadable rule, no rule
    documents, correlation rule, etc.) - never raised for a rule simply not
    firing, which is a normal, valid outcome."""


# ---------------------------------------------------------------------------
# rsigma binary resolution and version pin enforcement
# ---------------------------------------------------------------------------


def find_rsigma_binary(explicit: Optional[Union[str, Path]] = None) -> Path:
    """Locate the rsigma binary and refuse to proceed unless it reports the
    exact pinned version. Order: explicit path arg, $MECHANIC_RSIGMA_BIN,
    PATH. Raises VerifyError rather than falling back silently - an
    unpinned RSigma binary evaluating a rule is exactly the kind of
    untrustworthy-zero situation this module exists to prevent."""
    import os

    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get(RSIGMA_BIN_ENV)
    if env:
        candidates.append(Path(env))
    which = shutil.which("rsigma") or shutil.which("rsigma.exe")
    if which:
        candidates.append(Path(which))

    for c in candidates:
        if c.exists():
            _check_version(c)
            return c

    raise VerifyError(
        f"rsigma binary not found. Set ${RSIGMA_BIN_ENV} to its path, put it on PATH, or pass "
        f"rsigma_bin= explicitly. This harness is validated against v{PINNED_VERSION} only - "
        "see docs/stage3-harness-evaluation.md."
    )


def _check_version(path: Path) -> None:
    try:
        out = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=10)
    except Exception as e:  # noqa: BLE001 - any failure to even launch it is a hard stop
        raise VerifyError(f"failed to run '{path} --version': {e}") from e
    text = f"{out.stdout}\n{out.stderr}"
    if PINNED_VERSION not in text:
        raise VerifyError(
            f"'{path} --version' reported {text.strip()!r}, expected the pinned v{PINNED_VERSION}. "
            "This harness's silent-zero guard was validated against that exact build only "
            "(docs/stage3-harness-evaluation.md) - refusing to evaluate against a different, "
            "unvalidated RSigma version rather than silently trust it."
        )


# ---------------------------------------------------------------------------
# Rule introspection (reuses loader.py / ast_repr.py - no changes to either)
# ---------------------------------------------------------------------------


@dataclass
class RuleInfo:
    rule_id: Optional[str]
    title: Optional[str]
    fields: list[str]  # every field name the rule's detection tree references
    logsource: dict[str, Optional[str]]
    attack_tags: list[str]


def load_rule_info(rule_path: Path) -> RuleInfo:
    """Load one Sigma rule and extract exactly the facts the guard and the
    gate need, via mechanic's existing fault-isolated loader and AST - no
    duplicate YAML/condition parsing lives in this module."""
    rules, failures = loader.load_file(rule_path)
    if failures:
        f = failures[0]
        raise VerifyError(f"{rule_path}: failed to load ({f.category}: {f.message})")
    if not rules:
        raise VerifyError(f"{rule_path}: no rule documents found")
    if len(rules) > 1:
        raise VerifyError(f"{rule_path}: {len(rules)} rule documents found; verify expects exactly one")
    lr = rules[0]
    if lr.rule_type != "standard":
        raise VerifyError(f"{rule_path}: correlation rules are not supported by the verification harness")

    tree = ast_repr.build_ast(lr.rule)
    fields = sorted({leaf["field"] for leaf in ast_repr.iter_leaves_of_rule(tree) if leaf.get("field")})
    return RuleInfo(rule_id=lr.rule_id, title=lr.title, fields=fields, logsource=tree["logsource"], attack_tags=tree["attack_tags"])


# ---------------------------------------------------------------------------
# subprocess plumbing
# ---------------------------------------------------------------------------


def _run(rsigma_bin: Path, args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([str(rsigma_bin), *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise VerifyError(f"rsigma timed out after {timeout}s: {args}") from e


def _parse_matched_lines(stdout: str) -> list[dict]:
    """`--output-format json` emits one compact JSON object per line per
    firing event (NDJSON), interleaved with plain-text banner lines
    ("Loaded N rules...", "Processed N events, M matches."). Only lines that
    parse as JSON objects are matches; everything else is banner noise."""
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


_SUMMARY_RE = re.compile(r"Processed (\d+) (?:EVTX records|events), (\d+) matches\.")


def _parse_summary(text: str) -> Optional[tuple[int, int]]:
    m = _SUMMARY_RE.search(text)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _observe_fields(rsigma_bin: Path, rule_path: Path, event_path: Path, pipeline_path: Optional[Path], report_path: Path) -> dict:
    args = ["engine", "eval", "-r", str(rule_path)]
    if pipeline_path is not None:
        args += ["-p", str(pipeline_path)]
    args += ["-e", f"@{event_path}", "--observe-fields", "--observe-fields-report", str(report_path)]
    _run(rsigma_bin, args)
    if not report_path.exists():
        raise VerifyError(f"rsigma did not produce a field-observability report for {event_path}")
    return json.loads(report_path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Pipeline discovery - the fix for the "-p sysmon doesn't work on raw EVTX,
# and System-vs-EventData is a wrong guess anyway" finding (see module
# docstring). Only used for EVTX input; flat JSON is assumed pre-flattened
# and is checked (never silently trusted) but not auto-remediated.
# ---------------------------------------------------------------------------


@dataclass
class PipelineDiscovery:
    mapping: dict[str, str]  # field -> discovered path, only for fields resolved unambiguously
    unresolved: list[str]  # rule fields with zero candidate paths in the raw event
    ambiguous: dict[str, list[str]]  # rule fields with >1 candidate path, and what they were

    def to_pipeline_dict(self, name: str) -> dict:
        return {
            "name": name,
            "priority": 100,
            "transformations": [{"id": "mechanic_discovered_flatten", "type": "field_name_mapping", "mapping": self.mapping}],
        }


def _match_key(path: str) -> str:
    """The field-name-shaped part of an observed path, for last-segment
    matching. RSigma renders an XML element's own text content as
    '<path>.#text' whenever that element ALSO has attributes (seen on
    <EventID Qualifiers='0'>9911</EventID> -> 'Event.System.EventID.#text')
    - and, discovered while building Part 3's multi-record fixture, this
    also happens for a plain, attribute-less <Data>value</Data> element
    when it carries no Name attribute (the classic/legacy, non-manifested
    Windows Event Log shape - no Sysmon-style 'Name=' present at all, so
    there's nothing to key each Data element by, only its text content):
    'Event.EventData.Data.#text'. Stripping a trailing '.#text' before
    taking the last segment is what lets a rule field named 'Data' resolve
    against that path at all - without this, '#text' (not 'Data') would be
    the last segment and the field would come back unresolved even though
    the value is right there."""
    if path.endswith(".#text"):
        path = path[: -len(".#text")]
    return path.rsplit(".", 1)[-1]


def _discover_pipeline(rsigma_bin: Path, rule_path: Path, event_path: Path, rule_fields: list[str], tmp_dir: Path) -> PipelineDiscovery:
    """Dry pass with no pipeline: whatever real nested paths RSigma reports
    as 'unknown' for this event are the raw, un-mapped truth for this event
    source. Match each rule field name against candidates whose path's last
    dot-segment (see _match_key) equals it exactly. This is discovery, not
    a guess about which of System/EventData/UserData a given channel uses."""
    report = _observe_fields(rsigma_bin, rule_path, event_path, None, tmp_dir / "discover_fields.json")
    # `missing` entries in this dry (no-pipeline) pass are just the rule's own field names
    # echoed back unmapped - not real observed paths. Only `unknown` entries are genuine
    # paths seen in the parsed event, so only those are candidates.
    observed_paths = [u["field"] for u in report.get("unknown", [])]
    candidates_by_last_segment: dict[str, list[str]] = {}
    for path in observed_paths:
        last = _match_key(path)
        candidates_by_last_segment.setdefault(last, []).append(path)

    mapping: dict[str, str] = {}
    unresolved: list[str] = []
    ambiguous: dict[str, list[str]] = {}
    for f in rule_fields:
        candidates = sorted(set(candidates_by_last_segment.get(f, [])))
        if not candidates:
            unresolved.append(f)
        elif len(candidates) == 1:
            mapping[f] = candidates[0]
        else:
            # Tie-break: prefer EventData, then System, else first alphabetically -
            # but record the ambiguity regardless so it's visible, not silently guessed.
            preferred = next((c for c in candidates if any(c.startswith(h) for h in _EVENTDATA_LIKE_HINTS)), None)
            preferred = preferred or next((c for c in candidates if any(c.startswith(h) for h in _SYSTEM_LIKE_HINTS)), None)
            preferred = preferred or candidates[0]
            mapping[f] = preferred
            ambiguous[f] = candidates
    return PipelineDiscovery(mapping=mapping, unresolved=unresolved, ambiguous=ambiguous)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class EventOutcome:
    index: int
    fired: bool
    status: str  # "trusted" | "unverifiable"
    reasons: list[str] = field(default_factory=list)
    matched_fields: list[dict] = field(default_factory=list)
    label: Optional[str] = None
    # Stage 3 Phase 3: populated (only) when this outcome is unverifiable
    # specifically because the rule references field(s) genuinely absent
    # from the parsed event schema - i.e. the same condition the `reasons`
    # prose already describes, exposed here as structured data instead of a
    # string a caller would otherwise have to regex back out. This is what
    # lets mechanic.repair_outcome detect a TELEMETRY_REPAIR case
    # deterministically (a rule referencing a field the log source can't
    # provide) without re-parsing reasons text.
    missing_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "label": self.label,
            "fired": self.fired,
            "status": self.status,
            "reasons": self.reasons,
            "matched_fields": self.matched_fields,
            "missing_fields": self.missing_fields,
        }


@dataclass
class VerifyReport:
    rule_file: str
    rule_id: Optional[str]
    rule_title: Optional[str]
    event_source: str
    pipeline_description: Optional[str]
    discovery: Optional[PipelineDiscovery]
    rsigma_version: str
    outcomes: list[EventOutcome]

    @property
    def any_unverifiable(self) -> bool:
        return any(o.status == "unverifiable" for o in self.outcomes)

    @property
    def trusted_fired_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "trusted" and o.fired)

    @property
    def trusted_no_fire_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "trusted" and not o.fired)

    @property
    def unverifiable_count(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "unverifiable")

    def fired(self, index: int) -> Optional[bool]:
        """True/False if that event's result is trusted, None (never a
        silent False) if it's unverifiable."""
        for o in self.outcomes:
            if o.index == index:
                return o.fired if o.status == "trusted" else None
        raise IndexError(index)

    def to_dict(self) -> dict:
        return {
            "rule_file": self.rule_file,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "event_source": self.event_source,
            "pipeline_description": self.pipeline_description,
            "discovery": None
            if self.discovery is None
            else {"mapping": self.discovery.mapping, "unresolved": self.discovery.unresolved, "ambiguous": self.discovery.ambiguous},
            "rsigma_version": self.rsigma_version,
            "any_unverifiable": self.any_unverifiable,
            "trusted_fired_count": self.trusted_fired_count,
            "trusted_no_fire_count": self.trusted_no_fire_count,
            "unverifiable_count": self.unverifiable_count,
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


# ---------------------------------------------------------------------------
# Event I/O helpers
# ---------------------------------------------------------------------------


def _read_event_file(path: Path) -> list[EventDict]:
    """Strict, fail-loud JSON/NDJSON reading. This is what closes off the
    'malformed JSON silently dropped by rsigma' failure mode (module
    docstring, finding #1) for anything that goes through evaluate()'s file
    path: a syntax problem raises here, in Python, before rsigma ever sees
    the file - it can never surface downstream as a quiet zero-match."""
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, list) else [obj]
    except json.JSONDecodeError:
        pass
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise VerifyError(f"{path}: invalid JSON on line {e.lineno if hasattr(e, 'lineno') else '?'}: {e}") from e
    return events


_IDX_KEY = "_mechanic_idx"


def _write_ndjson(events: list[EventDict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for i, e in enumerate(events):
            tagged = dict(e)
            tagged[_IDX_KEY] = i
            f.write(json.dumps(tagged) + "\n")


@contextmanager
def _tmp_dir(explicit: Optional[Path]) -> Iterator[Path]:
    if explicit is not None:
        explicit.mkdir(parents=True, exist_ok=True)
        yield explicit
    else:
        with tempfile.TemporaryDirectory(prefix="mechanic_verify_") as td:
            yield Path(td)


# ---------------------------------------------------------------------------
# JSON / NDJSON evaluation path
# ---------------------------------------------------------------------------


def _evaluate_json_events(
    rsigma_bin: Path,
    rule_path: Path,
    events: list[EventDict],
    pipeline_path: Optional[Path],
    labels: Optional[list[str]],
    tmp_dir: Path,
) -> tuple[list[EventOutcome], Optional[dict]]:
    ndjson_path = tmp_dir / "events.ndjson"
    _write_ndjson(events, ndjson_path)

    report_path = tmp_dir / "fields_report.json"
    args = ["engine", "eval", "-r", str(rule_path)]
    if pipeline_path is not None:
        args += ["-p", str(pipeline_path)]
    args += [
        "-e", f"@{ndjson_path}",
        "--include-event", "--match-detail", "full", "--output-format", "json",
        "--observe-fields", "--observe-fields-report", str(report_path),
    ]
    proc = _run(rsigma_bin, args)
    matched = _parse_matched_lines(proc.stdout)
    field_report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {"summary": {"events_observed": 0}, "missing": []}

    missing_names = sorted({m["field"] for m in field_report.get("missing", [])})
    expected_n = len(events)
    observed_n = field_report.get("summary", {}).get("events_observed", 0)
    schema_bad = bool(missing_names)
    count_mismatch = observed_n != expected_n

    fired_by_idx: dict[int, list[dict]] = {}
    for m in matched:
        idx = m.get("event", {}).get(_IDX_KEY)
        if idx is not None:
            fired_by_idx.setdefault(idx, []).append(m)

    parse_failed: set[int] = set()
    if count_mismatch:
        parse_failed = _probe_individual_parse(rsigma_bin, rule_path, pipeline_path, events, tmp_dir)

    outcomes = []
    for i, e in enumerate(events):
        reasons = []
        if schema_bad:
            status = "unverifiable"
            reasons.append(f"rule references field(s) absent from the parsed event schema under this pipeline: {missing_names}")
        elif i in parse_failed:
            status = "unverifiable"
            reasons.append("this event was not ingested by rsigma at all (events_observed count came up short) - "
                           "likely malformed JSON (e.g. a raw backslash that isn't a valid JSON escape)")
        else:
            status = "trusted"
        fired = i in fired_by_idx
        mf = [x for m in fired_by_idx.get(i, []) for x in m.get("matched_fields", [])]
        outcomes.append(
            EventOutcome(
                index=i,
                fired=fired,
                status=status,
                reasons=reasons,
                matched_fields=mf,
                label=(labels[i] if labels else None),
                missing_fields=list(missing_names) if schema_bad else [],
            )
        )
    return outcomes, field_report


def _probe_individual_parse(rsigma_bin: Path, rule_path: Path, pipeline_path: Optional[Path], events: list[EventDict], tmp_dir: Path) -> set[int]:
    """Only called when the batch's events_observed count doesn't match the
    input count - isolates exactly which event(s) rsigma silently dropped by
    re-running each one alone. Bounded cost: this fallback only triggers on
    a detected mismatch, never on the common/clean path."""
    bad: set[int] = set()
    for i, e in enumerate(events):
        p = tmp_dir / f"probe_{i}.json"
        p.write_text(json.dumps(e), encoding="utf-8")
        report_p = tmp_dir / f"probe_{i}_fields.json"
        args = ["engine", "eval", "-r", str(rule_path)]
        if pipeline_path is not None:
            args += ["-p", str(pipeline_path)]
        args += ["-e", f"@{p}", "--observe-fields", "--observe-fields-report", str(report_p)]
        _run(rsigma_bin, args)
        if report_p.exists():
            rep = json.loads(report_p.read_text(encoding="utf-8"))
            if rep.get("summary", {}).get("events_observed", 0) == 0:
                bad.add(i)
        else:
            bad.add(i)
    return bad


# ---------------------------------------------------------------------------
# EVTX evaluation path
# ---------------------------------------------------------------------------


_RECORD_ID_FIELD = "EventRecordID"
# Every Windows EVTX record carries its own unique EventRecordID
# (Microsoft-documented, monotonically increasing per channel) - used here
# purely as a correlation key, never as rule-matching content.
_CATCHALL_RULE_ID = "8f2b8b2e-9c1a-4b7b-8f0a-mechanic00001"
_CATCHALL_RULE_YAML = f"""title: mechanic internal record enumeration (not a detection rule)
id: {_CATCHALL_RULE_ID}
status: test
logsource: {{category: process_creation, product: windows}}
detection:
    selection:
        {_RECORD_ID_FIELD}: '*'
    condition: selection
"""


def _extract_by_dotted_path(obj: Any, dotted_path: str) -> Any:
    """Walk a nested dict (as embedded via --include-event) by a
    '.'-joined path exactly as reported by --observe-fields (including a
    literal '#text'/'#attributes.X' pseudo-segment where present - these
    are ordinary dict keys in the embedded JSON, not special syntax)."""
    cur = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _enumerate_evtx_records(
    rsigma_bin: Path, evtx_path: Path, pipeline_path: Optional[Path], record_id_path: str, tmp_dir: Path
) -> tuple[list[Any], dict]:
    """Run a trivial always-true rule (EventRecordID wildcard match) through
    the SAME discovered pipeline to enumerate every record's own id, in
    file order - this is how the total record set (fired or not) is known
    at all, since RSigma's normal match output only ever reports records
    that fired. Returns (record_ids, field_report) - the field_report's
    own events_observed is cross-checked by the caller against this list's
    length, the same "don't trust a bare count" discipline as the JSON
    path's _probe_individual_parse."""
    rule_path = tmp_dir / "mechanic_catchall_rule.yml"
    rule_path.write_text(_CATCHALL_RULE_YAML, encoding="utf-8")
    report_path = tmp_dir / "catchall_fields_report.json"
    args = ["engine", "eval", "-r", str(rule_path)]
    if pipeline_path is not None:
        args += ["-p", str(pipeline_path)]
    args += [
        "-e", f"@{evtx_path}",
        "--include-event", "--match-detail", "off", "--output-format", "json",
        "--observe-fields", "--observe-fields-report", str(report_path),
    ]
    proc = _run(rsigma_bin, args)
    matched = _parse_matched_lines(proc.stdout)
    ids = [_extract_by_dotted_path(m.get("event", {}), record_id_path) for m in matched]
    field_report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {"summary": {"events_observed": 0}}
    return ids, field_report


def _evaluate_evtx(
    rsigma_bin: Path,
    rule_path: Path,
    rule_fields: list[str],
    evtx_path: Path,
    pipeline_path: Optional[Path],
    auto_pipeline: bool,
    tmp_dir: Path,
) -> tuple[list[EventOutcome], Optional[dict], Optional[PipelineDiscovery]]:
    discovery: Optional[PipelineDiscovery] = None
    generated_pipeline_path = pipeline_path
    if pipeline_path is None and auto_pipeline:
        # Always also resolve EventRecordID, even though no rule asked for
        # it - Part 3's multi-record path needs it to correlate matches
        # back to individual records (see _enumerate_evtx_records).
        fields_for_discovery = list(dict.fromkeys([*rule_fields, _RECORD_ID_FIELD]))
        discovery = _discover_pipeline(rsigma_bin, rule_path, evtx_path, fields_for_discovery, tmp_dir)
        if discovery.mapping:
            generated_pipeline_path = tmp_dir / "auto_pipeline.yml"
            generated_pipeline_path.write_text(
                yaml.safe_dump(discovery.to_pipeline_dict("mechanic auto-discovered EVTX flatten"), sort_keys=False),
                encoding="utf-8",
            )

    report_path = tmp_dir / "fields_report.json"
    args = ["engine", "eval", "-r", str(rule_path)]
    if generated_pipeline_path is not None:
        args += ["-p", str(generated_pipeline_path)]
    args += [
        "-e", f"@{evtx_path}",
        "--include-event", "--match-detail", "full", "--output-format", "json",
        "--observe-fields", "--observe-fields-report", str(report_path),
    ]
    proc = _run(rsigma_bin, args)
    matched = _parse_matched_lines(proc.stdout)
    field_report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {"summary": {"events_observed": 0}, "missing": []}
    missing_names = sorted({m["field"] for m in field_report.get("missing", [])})

    summary = _parse_summary(proc.stdout + proc.stderr)
    total = summary[0] if summary else field_report.get("summary", {}).get("events_observed", 0)
    match_count = summary[1] if summary else len(matched)

    if total != 1 and total >= 2:
        return _evaluate_evtx_multi_record(
            rsigma_bin, evtx_path, generated_pipeline_path, discovery, total, matched, missing_names, field_report, tmp_dir
        )
    if total != 1:
        reasons = [f"EVTX file contains {total} record(s); expected at least 1."]
        outcomes = [EventOutcome(index=0, fired=match_count > 0, status="unverifiable", reasons=reasons)]
    elif missing_names:
        reasons = [f"rule references field(s) missing from the parsed EVTX structure even after discovery: {missing_names}"]
        outcomes = [EventOutcome(index=0, fired=match_count > 0, status="unverifiable", reasons=reasons, missing_fields=list(missing_names))]
    else:
        mf = [x for m in matched for x in m.get("matched_fields", [])]
        outcomes = [EventOutcome(index=0, fired=match_count > 0, status="trusted", reasons=[], matched_fields=mf)]
    return outcomes, field_report, discovery


def _evaluate_evtx_multi_record(
    rsigma_bin: Path,
    evtx_path: Path,
    pipeline_path: Optional[Path],
    discovery: Optional[PipelineDiscovery],
    total: int,
    matched: list[dict],
    missing_names: list[str],
    field_report: dict,
    tmp_dir: Path,
) -> tuple[list[EventOutcome], Optional[dict], Optional[PipelineDiscovery]]:
    """Stage 3 Phase 2, Part 3: per-record fire/no-fire accounting for a
    multi-record EVTX file (Phase 1's stated gap). Correlates each match
    back to the specific record it came from via EventRecordID, enumerated
    independently through a trivial always-true rule (_enumerate_evtx_records)
    since RSigma's normal output only lists records that fired. Every
    verification step here can fail closed to a single aggregate
    UNVERIFIABLE outcome (never a silently-clean per-record count) if
    EventRecordID can't be resolved, or the enumeration pass's own numbers
    don't add up."""
    record_id_path = discovery.mapping.get(_RECORD_ID_FIELD) if discovery else None
    if record_id_path is None:
        reasons = [
            f"EVTX file contains {total} records but this file's own {_RECORD_ID_FIELD} field could not be "
            "unambiguously resolved during pipeline discovery, so per-record fire/no-fire correlation isn't "
            "possible - only the aggregate match count is available, which is not enough to trust a "
            "per-event verdict."
        ]
        return [EventOutcome(index=0, fired=len(matched) > 0, status="unverifiable", reasons=reasons)], field_report, discovery

    all_ids, catchall_report = _enumerate_evtx_records(rsigma_bin, evtx_path, pipeline_path, record_id_path, tmp_dir)
    catchall_observed = catchall_report.get("summary", {}).get("events_observed", 0)
    unique_ids = {rid for rid in all_ids if rid is not None}
    enumeration_ok = catchall_observed == total and len(all_ids) == total and len(unique_ids) == total
    if not enumeration_ok:
        reasons = [
            f"could not reliably enumerate all {total} record(s) via the {_RECORD_ID_FIELD} catch-all pass "
            f"(catch-all matched {len(all_ids)}/{total} records, catch-all's own events_observed="
            f"{catchall_observed}, {len(unique_ids)} distinct id(s) among them) - per-record accounting is "
            "not trustworthy here; treating the whole file as one unverifiable unit rather than guessing."
        ]
        return [EventOutcome(index=0, fired=len(matched) > 0, status="unverifiable", reasons=reasons)], field_report, discovery

    fired_ids = set()
    for m in matched:
        rid = _extract_by_dotted_path(m.get("event", {}), record_id_path)
        if rid is not None:
            fired_ids.add(rid)

    # A whole-file schema problem (a rule field missing everywhere) applies
    # uniformly to every record - marking every outcome unverifiable
    # together is exactly the same "don't silently average it away"
    # behaviour the single-record path already has, just applied per-record
    # here so gate._all_trusted_fired's own any-unverifiable-poisons-the-
    # batch logic sees it correctly.
    schema_reason = (
        [f"rule references field(s) missing from the parsed EVTX structure even after discovery: {missing_names}"]
        if missing_names
        else []
    )
    outcomes = [
        EventOutcome(
            index=i,
            fired=(rid in fired_ids),
            status="unverifiable" if missing_names else "trusted",
            reasons=list(schema_reason),
            label=f"{_RECORD_ID_FIELD}={rid}",
            missing_fields=list(missing_names) if missing_names else [],
        )
        for i, rid in enumerate(all_ids)
    ]
    return outcomes, field_report, discovery


# ---------------------------------------------------------------------------
# Stage 3 Phase 3: EVTX -> flat dict bridge
# ---------------------------------------------------------------------------


def flat_event_from_evtx(
    rule_path: Union[str, Path], evtx_path: Union[str, Path], *, rsigma_bin: Optional[Union[str, Path]] = None, tmp_dir: Optional[Path] = None
) -> dict[str, Any]:
    """Project the ONE firing record of a genuine EVTX fixture (e.g.
    SigmaHQ's own `regression_data` corpus, each with an `info.yml`
    declaring its own hand-verified `match_count`) down to a flat dict
    keyed by the RULE's own field names, using the exact same
    discover-don't-guess pipeline this module already trusts
    (`_discover_pipeline`) rather than a second, independently-invented
    flattening scheme.

    This is the bridge that lets `mechanic.evasion`'s dict-shaped
    `template_event` (built for Phase 2's hand-authored events) also work
    for a rule this project has no hand-authored event for - the Phase 3
    stratified sample draws its true-positive template from a real,
    independently-sourced fixture this way instead of a synthetic or
    invented one.

    Raises VerifyError (never silently guesses) if:
      - any of the rule's own fields fail to resolve during discovery,
      - the rule does not fire on the file at all (no positive record to
        project), or
      - the rule fires on more than one record (ambiguous which is the
        declared true positive - expected exactly 1, per the fixture's own
        info.yml)."""
    rule_path = Path(rule_path)
    evtx_path = Path(evtx_path)
    resolved_bin = find_rsigma_binary(rsigma_bin)
    rule_info = load_rule_info(rule_path)

    with _tmp_dir(tmp_dir) as td:
        discovery = _discover_pipeline(resolved_bin, rule_path, evtx_path, rule_info.fields, td)
        if discovery.unresolved:
            raise VerifyError(
                f"{rule_path}: field(s) {discovery.unresolved} did not resolve against {evtx_path} during "
                "discovery - cannot build a template event for this rule/fixture pair."
            )
        pipeline_path = td / "flat_event_pipeline.yml"
        pipeline_path.write_text(
            yaml.safe_dump(discovery.to_pipeline_dict("mechanic flat-event projection"), sort_keys=False),
            encoding="utf-8",
        )
        args = [
            "engine", "eval", "-r", str(rule_path), "-p", str(pipeline_path),
            "-e", f"@{evtx_path}", "--include-event", "--match-detail", "off", "--output-format", "json",
        ]
        proc = _run(resolved_bin, args)
        matched = _parse_matched_lines(proc.stdout)

    if not matched:
        raise VerifyError(f"{rule_path} does not fire on any record in {evtx_path} - no known-positive record to project.")
    if len(matched) > 1:
        raise VerifyError(
            f"{rule_path} fires on {len(matched)} record(s) in {evtx_path} - ambiguous which is the declared "
            "true positive; expected exactly 1 (per this fixture's own info.yml match_count)."
        )
    full_event = matched[0].get("event", {})
    return {field_name: _extract_by_dotted_path(full_event, path) for field_name, path in discovery.mapping.items()}


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------


def evaluate(
    rule_path: Union[str, Path],
    events: Union[str, Path, list[EventDict]],
    *,
    pipeline: Optional[Union[str, Path]] = None,
    auto_pipeline: bool = True,
    rsigma_bin: Optional[Union[str, Path]] = None,
    labels: Optional[list[str]] = None,
    tmp_dir: Optional[Path] = None,
) -> VerifyReport:
    """Evaluate one Sigma rule against a set of events via RSigma's
    `engine eval`, returning per-event outcomes each explicitly tagged
    trusted or unverifiable. Never returns a bare boolean.

    `events` may be:
      - a Path/str ending in .evtx: evaluated per-record. A single-record
        file returns one outcome, same as before. A multi-record file
        (Stage 3 Phase 2, Part 3) returns one outcome per record, each
        independently fired/not-fired via EventRecordID correlation against
        a trivial always-true enumeration pass (see _evaluate_evtx_multi_record)
        - trusted only when that record's own field-presence check passes
        AND the enumeration pass's own record count/uniqueness checks out;
        any doubt collapses to a single aggregate UNVERIFIABLE outcome for
        the whole file rather than a guessed per-record split.
      - a Path/str to a .json (single object or JSON array) or .ndjson file.
      - a list[dict] of events directly (the common case for hand-built
        gate inputs) - written to a temp NDJSON file internally.

    `pipeline`, if given, is used as-is (caller's own pySigma-compatible
    YAML). If omitted and `auto_pipeline` is True (default) and the event
    source is EVTX, a pipeline is auto-discovered per _discover_pipeline -
    never guessed from rule category. JSON/NDJSON input is assumed
    pre-flattened; no auto-remediation is attempted for it, only detection.
    """
    rule_path = Path(rule_path)
    resolved_bin = find_rsigma_binary(rsigma_bin)
    rule_info = load_rule_info(rule_path)
    pipeline_path = Path(pipeline) if pipeline else None

    with _tmp_dir(tmp_dir) as td:
        if isinstance(events, (str, Path)) and str(events).lower().endswith(".evtx"):
            outcomes, _field_report, discovery = _evaluate_evtx(
                resolved_bin, rule_path, rule_info.fields, Path(events), pipeline_path, auto_pipeline, td
            )
            event_source = str(events)
            pipeline_description = str(pipeline_path) if pipeline_path else ("auto-discovered" if discovery and discovery.mapping else None)
        else:
            if isinstance(events, (str, Path)):
                events_list = _read_event_file(Path(events))
                event_source = str(events)
            else:
                events_list = list(events)
                event_source = f"<{len(events_list)} in-memory event(s)>"
            outcomes, _field_report = _evaluate_json_events(resolved_bin, rule_path, events_list, pipeline_path, labels, td)
            discovery = None
            pipeline_description = str(pipeline_path) if pipeline_path else None

    return VerifyReport(
        rule_file=str(rule_path),
        rule_id=rule_info.rule_id,
        rule_title=rule_info.title,
        event_source=event_source,
        pipeline_description=pipeline_description,
        discovery=discovery,
        rsigma_version=PINNED_VERSION,
        outcomes=outcomes,
    )
