"""Format-agnostic rule-file discovery.

Sigma loading and AST work only make sense for YAML Sigma rules, but staleness
(Component 2) is defined purely in terms of "files matching a pattern", so it
works unmodified on Elastic's TOML rules or Splunk's YAML-with-a-different-schema.
New formats are added by extending `FORMATS` - nothing else needs to change.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


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


def discover_files(root: Path, fmt: str | RuleFormat = "sigma") -> list[Path]:
    """Discover rule files under `root` for the given format.

    `fmt` can be a registry key (see FORMATS) or a RuleFormat instance for a
    one-off pattern the caller doesn't want to register globally.
    """
    root = Path(root)
    rule_format = FORMATS[fmt] if isinstance(fmt, str) else fmt
    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in rule_format.globs:
        for path in root.glob(pattern):
            if not path.is_file() or path in seen:
                continue
            if _is_excluded(path, root, rule_format.exclude_dirs):
                continue
            seen.add(path)
            files.append(path)
    return sorted(files)
