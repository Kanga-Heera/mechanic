"""Splunk SPL macro resolution - ported unchanged from the Phase 0
investigation's `splunk_atoms.py` (already validated there: 2 genuinely
unresolved macros out of 2,144 Splunk detections). Kept as its own module
since it's Splunk-specific plumbing, not part of the tier-classification
logic itself."""

from __future__ import annotations

import functools
import glob
import re

MACRO_DIR = "D:/sigma-research/thirdparty/splunk-security-content/macros"

BACKTICK_RE = re.compile(r"`([a-zA-Z0-9_]+)(\([^)]*\))?`")

# Built-in Splunk CIM app macros: ship with Splunk's Common Information Model
# app, not with this repo, so they never resolve via macros/. Confirmed benign
# by inspection: drop_dm_object_name is a pure field-renaming pipe utility
# (strips a datamodel object prefix off field names), no filtering literal.
KNOWN_BENIGN_EXTERNAL_MACROS = {"drop_dm_object_name"}


@functools.lru_cache(maxsize=1)
def load_macros() -> dict[str, str]:
    import yaml

    macros: dict[str, str] = {}
    for f in glob.glob(f"{MACRO_DIR}/**/*.yml", recursive=True):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "name" in data and "definition" in data:
                macros[data["name"]] = data["definition"]
        except Exception:
            pass
    return macros


def resolve_macros(search_text: str, depth: int = 3) -> tuple[str, int, int, int, int, list[str]]:
    """Returns (resolved_text, n_refs, n_resolved, n_benign_external, n_unresolved, unresolved_names)."""
    macros = load_macros()
    n_refs = n_resolved = n_benign_external = n_unresolved = 0
    unresolved_names: list[str] = []
    text = search_text

    for _ in range(depth):
        matches = list(BACKTICK_RE.finditer(text))
        if not matches:
            break
        changed = False
        for m in matches:
            name = m.group(1)
            n_refs += 1
            if name in macros:
                n_resolved += 1
                text = text.replace(m.group(0), " " + macros[name] + " ", 1)
                changed = True
            elif name.endswith("_filter"):
                # Splunk ES convention: per-rule filter macro, ships empty
                # (resolves to no-op "search *" at deploy time).
                text = text.replace(m.group(0), " ", 1)
                changed = True
            elif name in KNOWN_BENIGN_EXTERNAL_MACROS:
                n_benign_external += 1
                text = text.replace(m.group(0), " ", 1)
                changed = True
            else:
                n_unresolved += 1
                unresolved_names.append(name)
                text = text.replace(m.group(0), " ", 1)
        if not changed:
            break
    return text, n_refs, n_resolved, n_benign_external, n_unresolved, unresolved_names
