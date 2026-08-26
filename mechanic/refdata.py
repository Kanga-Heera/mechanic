"""Reference data for the fragility classifier (Stage 2, Part 2): tool names
derived from LOLBAS/GTFOBins/ATT&CK software objects, loaded from the static
JSON snapshots in `mechanic/data/` (see `data/SOURCES.md` for exact source
URLs, fetch date, and counts).

v1's classifier used a hand-curated, Windows-only tool list; that was
identified as one of the five systematic causes of its poor hand-label
agreement. This module exists specifically so the tool-name vocabulary is
*derived from an external source*, not typed by hand - see RESULTS.md.

Deliberately offline: these are static files fetched once and committed, not
fetched over the network at import time - mechanic must stay deterministic
and reproducible without network access.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"


def _load_json(name: str):
    with open(_DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def _strip_ext(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


@lru_cache(maxsize=1)
def lolbas_names() -> frozenset[str]:
    """Windows living-off-the-land binary names, lowercase, both with and
    without their `.exe`/`.dll` extension (rules match either form - e.g.
    `Image|endswith: '\\certutil.exe'` vs. a bare `process.name: certutil`)."""
    raw = _load_json("toolnames_lolbas.json")
    names = set()
    for n in raw:
        low = n.lower()
        names.add(low)
        names.add(_strip_ext(low))
    return frozenset(names)


@lru_cache(maxsize=1)
def gtfobins_names() -> frozenset[str]:
    """Linux/Unix binary names, lowercase. GTFOBins entries have no file
    extension to begin with (`sudo`, `python3`, `mount`, ...)."""
    return frozenset(n.lower() for n in _load_json("toolnames_gtfobins.json"))


@lru_cache(maxsize=1)
def loobins_names() -> frozenset[str]:
    """macOS living-off-the-land binaries (LOOBins project - GTFOBins covers
    Linux/Unix generally but is thin on macOS-specific system binaries like
    `launchctl`/`osascript`/`plutil`)."""
    return frozenset(n.lower() for n in _load_json("toolnames_loobins.json"))


@lru_cache(maxsize=1)
def attack_software_names() -> frozenset[str]:
    """Named attacker tool/malware vocabulary (Mimikatz, Rubeus, PsExec,
    Cobalt Strike, ...) from ATT&CK `malware`/`tool` STIX objects - distinct
    from LOLBAS/GTFOBins, which are built-in OS binaries, not attacker
    tooling. Includes each object's `name` and all `x_mitre_aliases`."""
    raw = _load_json("attack_software.json")
    names = set()
    for entry in raw:
        names.add(entry["name"].lower())
        for alias in entry.get("aliases", []):
            names.add(alias.lower())
    return frozenset(names)


@lru_cache(maxsize=1)
def all_tool_names() -> frozenset[str]:
    """The combined Tool-tier vocabulary: OS-provided dual-use binaries
    (LOLBAS + GTFOBins + LOOBins) plus named attacker tools (ATT&CK
    software). A rule keying on any of these is defeated by switching to a
    different tool with the same capability - the definition of Tool tier."""
    return lolbas_names() | gtfobins_names() | loobins_names() | attack_software_names()


def is_known_tool_name(candidate: str) -> bool:
    """True if `candidate` (a bare token - a process/image basename, an
    argv[0], a Signature-field word) matches a known LOLBAS/GTFOBins/ATT&CK
    tool name, case-insensitively, with or without a file extension.

    Callers are responsible for extracting the bare name from a full path
    first (e.g. `\\Windows\\System32\\certutil.exe` -> `certutil.exe`) - this
    function does not do path splitting, since what counts as a path
    separator is field/platform-dependent and that judgment belongs with the
    caller (the AST leaf's field/value context).
    """
    low = candidate.lower().strip()
    if not low:
        return False
    return low in all_tool_names() or _strip_ext(low) in all_tool_names()
