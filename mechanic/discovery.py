"""Format-agnostic rule-file discovery.

Sigma loading and AST work only make sense for YAML Sigma rules, but staleness
(Component 2) is defined purely in terms of "files matching a pattern", so it
works unmodified on Elastic's TOML rules or Splunk's YAML-with-a-different-schema.
New formats are added by extending `FORMATS` - nothing else needs to change.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional


@dataclass(frozen=True)
class RuleFormat:
    name: str
    globs: tuple[str, ...]
    exclude_dirs: tuple[str, ...] = ()


FORMATS: dict[str, RuleFormat] = {
    "sigma": RuleFormat(
        name="sigma",
        globs=("**/*.yml", "**/*.yaml"),
        exclude_dirs=(".git", "tests", "test"),
    ),
    "elastic_toml": RuleFormat(
        name="elastic_toml", globs=("**/*.toml",), exclude_dirs=(".git", "_deprecated")
    ),
    "splunk_yaml": RuleFormat(
        name="splunk_yaml", globs=("**/*.yml",), exclude_dirs=(".git", "deprecated")
    ),
    "yaml_generic": RuleFormat(
        name="yaml_generic", globs=("**/*.yml", "**/*.yaml"), exclude_dirs=(".git",)
    ),
}


def _is_excluded(path: Path, root: Path, exclude_dirs: tuple[str, ...]) -> bool:
    rel_parts = path.relative_to(root).parts
    return any(part in exclude_dirs for part in rel_parts)


def _dir_identity(path: Path) -> Optional[tuple]:
    """A directory's OS-level identity (device, inode), used to detect a
    symlink/junction cycle regardless of whether the platform's own
    `os.path.islink` recognizes the link type - it does not, for Windows
    directory junctions, which is exactly the gap this closes. Returns
    None (never a cycle key) if the directory can't be stat'd at all -
    that failure is surfaced separately by the caller, not swallowed here.
    """
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def _walk_files_no_cycles(root: Path, exclude_dirs: tuple[str, ...]) -> Iterator[Path]:
    """Yield every file under `root`, immune to symlink/junction cycles.

    `os.walk(followlinks=False)` alone is not sufficient: it correctly
    refuses to descend into a POSIX-symlinked directory (`os.path.islink`
    identifies it), but a Windows directory junction is not reported as a
    symlink by `os.path.islink` at all, so a junction loop would still be
    walked into. This instead tracks each visited directory's resolved
    (device, inode) identity and refuses to re-enter one already seen -
    catching both cases uniformly, on any platform, independent of how the
    link was made. A directory this process lacks permission to stat or
    list is skipped, not raised - consistent with this module's "one bad
    thing never aborts the whole scan" contract.
    """
    seen: set[tuple] = set()
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        ident = _dir_identity(current)
        if ident is not None:
            if ident in seen:
                continue
            seen.add(ident)
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                is_dir = entry.is_dir(follow_symlinks=True)
                is_file = entry.is_file(follow_symlinks=True)
            except OSError:
                continue
            if is_dir:
                if entry.name in exclude_dirs:
                    continue
                stack.append(Path(entry.path))
            elif is_file:
                yield Path(entry.path)


def _tail_patterns(globs: tuple[str, ...]) -> list[str]:
    """`"**/*.yml"` -> `"*.yml"` (this module's globs are always exactly
    `"**/<filename pattern>"` - recurse from root, match the filename)."""
    tails = []
    for g in globs:
        assert g.startswith("**/"), f"unsupported glob shape: {g!r} (expected '**/...')"
        tails.append(g[len("**/") :])
    return tails


def discover_files(root: Path, fmt: str | RuleFormat = "sigma") -> list[Path]:
    """Discover rule files under `root` for the given format.

    `fmt` can be a registry key (see FORMATS) or a RuleFormat instance for a
    one-off pattern the caller doesn't want to register globally. Traversal
    is cycle-safe (see `_walk_files_no_cycles`) - a symlink or junction loop
    anywhere under `root` terminates instead of hanging or crashing.
    """
    root = Path(root)
    rule_format = FORMATS[fmt] if isinstance(fmt, str) else fmt
    tails = _tail_patterns(rule_format.globs)
    seen: set[Path] = set()
    files: list[Path] = []
    for path in _walk_files_no_cycles(root, rule_format.exclude_dirs):
        if path in seen:
            continue
        if not any(fnmatch.fnmatch(path.name, tail) for tail in tails):
            continue
        seen.add(path)
        files.append(path)
    return sorted(files)
