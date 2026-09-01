"""CLI (Component 4): mechanic scan|staleness|ast|report|triage|explain, --json, --top N."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import rich_click as click
from rich.console import Console
from rich.table import Table

from mechanic import ast_repr, churn, loader, priority
from mechanic.discovery import FORMATS

console = Console()
err_console = Console(stderr=True)

_FMT_CHOICE = click.Choice(sorted(FORMATS))

# --- rich-click presentation config (help/usage screens only - no effect on
# actual argument parsing, which is stock click underneath) ---------------
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = False
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_ERRORS_SUGGESTION = "magenta italic"
click.rich_click.ERRORS_SUGGESTION = "Try 'mechanic COMMAND --help' for help on a specific command."
click.rich_click.MAX_WIDTH = 100
click.rich_click.COMMAND_GROUPS = {
    "mechanic": [
        {
            "name": "Inspect",
            "commands": ["scan", "ast"],
        },
        {
            "name": "Staleness (Part 1)",
            "commands": ["staleness", "report"],
        },
        {
            "name": "Triage (Part 2/3 - fragility + review priority)",
            "commands": ["triage", "explain", "priority-legend"],
        },
        {
            "name": "GUI (view-only, no repair)",
            "commands": ["gui"],
        },
    ]
}
click.rich_click.OPTION_GROUPS = {
    "mechanic staleness": [
        {"name": "Scope", "options": ["--fmt", "--subdir"]},
        {"name": "Thresholds", "options": ["--mechanical-threshold", "--top"]},
        {"name": "Output", "options": ["--json", "--help"]},
    ],
    "mechanic report": [
        {"name": "Scope", "options": ["--fmt", "--subdir"]},
        {"name": "Thresholds", "options": ["--mechanical-threshold", "--top"]},
        {"name": "Output", "options": ["--json", "--help"]},
    ],
    "mechanic triage": [
        {"name": "Scope", "options": ["--fmt", "--subdir"]},
        {"name": "Thresholds & ordering", "options": ["--mechanical-threshold", "--top", "--ordering"]},
        {"name": "Cache", "options": ["--refresh"]},
        {"name": "Output", "options": ["--json", "--help"]},
    ],
    "mechanic explain": [
        {"name": "Scope", "options": ["--fmt", "--subdir"]},
        {"name": "Thresholds", "options": ["--mechanical-threshold"]},
        {"name": "Cache", "options": ["--refresh"]},
        {"name": "Output", "options": ["--json", "--help"]},
    ],
}


def _print_json(data: dict[str, Any]) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def _scan(path: Path, fmt: str) -> tuple[loader.ScanResult, list[loader.FailureRecord]]:
    result = loader.load_ruleset(path, fmt)
    validate_failures = loader.validate_rules(result.rules)
    return result, validate_failures


def _render_scan_report(result: loader.ScanResult, validate_failures: list[loader.FailureRecord]) -> None:
    summary = Table(title=f"mechanic scan — {result.root}")
    summary.add_column("metric")
    summary.add_column("value", justify="right")
    summary.add_row("files scanned", str(result.files_scanned))
    summary.add_row("files loaded (>=1 rule)", str(result.files_ok))
    summary.add_row("files failed to load", str(result.files_failed))
    summary.add_row("rules loaded", str(len(result.rules)))
    summary.add_row("load failures", str(len(result.failures)))
    summary.add_row("validator crashes", str(len(validate_failures)))
    console.print(summary)

    all_failures = result.failures + validate_failures
    if not all_failures:
        console.print("[green]No load or validator failures.[/green]")
        return

    by_category: dict[str, list[loader.FailureRecord]] = {}
    for f in all_failures:
        by_category.setdefault(f.category, []).append(f)

    cat_table = Table(title="Failures by category")
    cat_table.add_column("category")
    cat_table.add_column("stage")
    cat_table.add_column("count", justify="right")
    for cat, items in sorted(by_category.items(), key=lambda kv: -len(kv[1])):
        cat_table.add_row(cat, items[0].stage, str(len(items)))
    console.print(cat_table)

    detail = Table(title="Failure detail")
    detail.add_column("file", overflow="fold")
    detail.add_column("category")
    detail.add_column("message", overflow="fold")
    detail.add_column("fix hint", overflow="fold")
    for f in all_failures:
        detail.add_row(f.file, f.category, f.message, f.fix_hint)
    console.print(detail)


def _render_staleness_report(report: churn.StalenessReport, top_n: int) -> None:
    summary = report.summary()
    t = Table(title=f"mechanic staleness — {report.root}")
    t.add_column("metric")
    t.add_column("value", justify="right")
    t.add_row("rule count", str(report.rule_count))
    t.add_row("mechanical threshold", f"{report.mechanical_threshold:.0%}")
    t.add_row(
        f"raw commit-touches, last {report.raw_commit_window_days}d (unfiltered, illustrative)",
        str(report.raw_commit_total),
    )
    t.add_row("excluded mechanical commits", str(len(report.excluded_commits)))
    t.add_row("mean organic commits/rule", f"{summary['mean_organic_commits_per_rule']:.2f}")
    t.add_row("median organic commits/rule", f"{summary['median_organic_commits_per_rule']:.1f}")
    t.add_row("% ever revised", f"{summary['pct_ever_revised']:.1f}%")
    t.add_row("% touched within 6mo", f"{summary['pct_touched_within_6mo']:.1f}%")
    t.add_row("% stale (>2yr)", f"{summary['pct_stale_over_2yr']:.1f}%")
    console.print(t)

    if report.excluded_commits:
        ex = Table(title="Excluded mechanical commits")
        ex.add_column("hash")
        ex.add_column("subject", overflow="fold")
        ex.add_column("rule files touched", justify="right")
        for c in report.excluded_commits:
            ex.add_row(c.hash[:10], c.subject, str(c.rule_files_touched))
        console.print(ex)

    sens = Table(title="Threshold sensitivity")
    sens.add_column("threshold")
    sens.add_column("excluded commits", justify="right")
    for s in sorted(report.sensitivity, key=lambda s: s.threshold):
        sens.add_row(f"{s.threshold:.0%}", str(len(s.excluded_commits)))
    console.print(sens)

    stalest = Table(title=f"Top {top_n} stalest rules")
    stalest.add_column("file", overflow="fold")
    stalest.add_column("days since organic touch", justify="right")
    stalest.add_column("organic commits", justify="right")
    stalest.add_column("ever revised")
    for r in report.top_stalest(top_n):
        stalest.add_row(r.file, str(r.days_since), str(r.organic_commit_count), str(r.ever_revised))
    console.print(stalest)


_PRIORITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange3",
    "MEDIUM": "yellow",
    "LOW": "dim",
}


def _render_priority_cell(p: priority.Priority) -> str:
    if p.uncertain or p.label is None:
        return "[dim]UNCERTAIN[/dim]"
    style = _PRIORITY_STYLE.get(p.label, "")
    band_label = {
        "stale_over_2yr": ">2yr",
        "aging_6mo_to_2yr": "6mo-2yr",
        "fresh_under_6mo": "<6mo",
    }.get(p.staleness_band, p.staleness_band or "-")
    text = f"[{style}]{p.label}[/{style}] ({p.tier}×{band_label})" if style else f"{p.label} ({p.tier}×{band_label})"
    if p.lower_confidence:
        text += "*"
    return text


def _render_rule_signal_row(r: priority.RuleSignals) -> tuple[str, str, str, str, str, str, str, str]:
    tier = r.fragility.tier or "-"
    conf = r.fragility.confidence + ("*" if r.fragility.caveat else "")
    staleness = "NEVER REVISED" if r.never_revised else f"{r.days_since_behavioral_change}d since behavioral change"
    hyps = ", ".join(r.triage_hypotheses) if r.triage_hypotheses else "-"
    return (
        r.file,
        _render_priority_cell(r.priority),
        tier,
        conf,
        r.short_reason,
        staleness,
        str(r.age_days) if r.age_days is not None else "-",
        hyps,
    )


def _render_triage_report(report: priority.TriageReport, top_n: int, ordering: str = "tier_first") -> None:
    console.print(f"[bold]mechanic triage — {report.root}[/bold]")
    console.print(f"[bold cyan]{report.one_line_summary()}[/bold cyan]")
    console.print(report.disclosure, style="yellow")

    summary = Table(title="Summary")
    summary.add_column("metric")
    summary.add_column("value", justify="right")
    summary.add_row("rules discovered", str(report.rule_count))
    summary.add_row("scoreable", str(len(report.scoreable)))
    summary.add_row("unscoreable (own section below)", str(len(report.unscoreable)))
    for h, count in sorted(report.bucket_counts().items(), key=lambda kv: -kv[1]):
        summary.add_row(f"triage hypothesis: {h}", str(count))
    console.print(summary)

    ordering_labels = {
        "tier_first": "fragility tier first, then staleness",
        "staleness_first": "staleness first, then fragility tier",
        "priority_first": "priority label first (CRITICAL..LOW)",
    }
    t = Table(title=f"Top {top_n}, sorted for review, worst first ({ordering_labels[ordering]} — not a combined score)")
    t.add_column("file", overflow="fold")
    t.add_column("priority (tier×staleness)")
    t.add_column("tier")
    t.add_column("tier conf.")
    t.add_column("why (driving observable)", overflow="fold")
    t.add_column("behavioral staleness")
    t.add_column("age (days)", justify="right")
    t.add_column("triage hypotheses (unverified)", overflow="fold")
    rows = report.sorted_scoreable(ordering=ordering)[:top_n]
    for r in rows:
        t.add_row(*_render_rule_signal_row(r))
    console.print(t)
    console.print(
        "Priority is a lookup over two separate axes (fragility tier × staleness band) shown in "
        "parentheses next to every label - never a blended score. See `mechanic priority-legend` "
        "for the full matrix.",
        style="dim",
    )
    if any(r.fragility.caveat for r in rows):
        console.print(
            "[yellow]* tier confidence (and any priority marked with a trailing *) comes from the "
            "TEXT-ONLY path (Elastic/Splunk, no AST) — computed WITHOUT the AND/OR combination "
            "correction that external validation against MITRE STP showed necessary. Treat these as "
            "less trustworthy than an unmarked (Sigma/AST) tier; see `mechanic explain <file>` for "
            "the full caveat on any individual row.[/yellow]"
        )

    if report.unscoreable:
        u = Table(title=f"Unscoreable ({len(report.unscoreable)}) — no tier assigned, never defaulted")
        u.add_column("file", overflow="fold")
        u.add_column("reason", overflow="fold")
        for r in report.unscoreable[:top_n]:
            u.add_row(r.file, r.fragility.unscoreable_reason or "-")
        if len(report.unscoreable) > top_n:
            u.add_row("...", f"({len(report.unscoreable) - top_n} more; use --json for the full list)")
        console.print(u)


def _render_explain(sig: priority.RuleSignals) -> None:
    console.print(f"[bold]mechanic explain — {sig.file}[/bold]\n")
    console.print(sig.narrative, style="bold")
    console.print()
    console.print(
        "Full signal detail follows below, for anyone who wants to verify the "
        "sentences above against the underlying data.",
        style="dim",
    )

    stale_t = Table(title="Behavioral staleness (Part 1)")
    stale_t.add_column("field")
    stale_t.add_column("value")
    stale_t.add_row("never revised", str(sig.never_revised))
    stale_t.add_row("behavioral commit count", str(sig.behavioral_commit_count))
    stale_t.add_row(
        "days since last behavioral change",
        str(sig.days_since_behavioral_change) if sig.days_since_behavioral_change is not None else "N/A (never revised)",
    )
    stale_t.add_row(
        "age (days since earliest known creation commit)",
        str(sig.age_days) if sig.age_days is not None else "unknown",
    )
    stale_t.add_row(
        "commit-classification confidence (behavioral vs. cosmetic split)",
        str(sig.staleness_classification_confidence or "n/a"),
    )
    console.print(stale_t)

    f = sig.fragility
    if f.unscoreable:
        console.print(f"[red]Fragility: UNSCOREABLE[/red] — {f.unscoreable_reason}")
        console.print("No tier was assigned. This rule is excluded from ranking, not defaulted to a tier.")
        return

    frag_t = Table(title="Fragility tier (Part 2)")
    frag_t.add_column("field")
    frag_t.add_column("value")
    frag_t.add_row("tier", f.tier or "-")
    frag_t.add_row("confidence", f.confidence)
    frag_t.add_row("AND/OR-corrected (AST walk)", str(f.and_or_corrected))
    if f.caveat:
        frag_t.add_row("caveat", f.caveat)
    frag_t.add_row("structural findings", ", ".join(f.structural_findings) if f.structural_findings else "none")
    console.print(frag_t)

    if f.structural_detail:
        sd = Table(title="Structural detector detail")
        sd.add_column("detector")
        sd.add_column("explanation", overflow="fold")
        for name, detail in f.structural_detail.items():
            sd.add_row(name, detail)
        console.print(sd)

    if f.atoms:
        a = Table(title="Contributing atoms (field/value pairs the tier was derived from)")
        a.add_column("field")
        a.add_column("value", overflow="fold")
        for atom in f.atoms:
            a.add_row(str(atom.get("field")), str(atom.get("value")))
        console.print(a)
        console.print(
            "Note: per-node AST path breadcrumbs are not tracked by the classifier "
            "(see mechanic/fragility.py); field/value pairs and structural-detector "
            "detail above are the full reasoning trail currently available.",
            style="dim",
        )

    if sig.triage_hypotheses:
        console.print(f"Triage hypotheses (Stage 3, UNTESTED — not conclusions): {', '.join(sig.triage_hypotheses)}")
    else:
        console.print("Triage hypotheses: none of the documented heuristic combinations matched.")

    console.print()
    p = sig.priority
    prio_t = Table(title="Priority (matrix lookup - see `mechanic priority-legend`)")
    prio_t.add_column("field")
    prio_t.add_column("value")
    prio_t.add_row("label", _render_priority_cell(p))
    prio_t.add_row("fragility tier (axis 1)", p.tier or "-")
    prio_t.add_row("staleness band (axis 2)", p.staleness_band or "-")
    if p.uncertain:
        prio_t.add_row("uncertain", f"[yellow]{p.uncertainty_reason}[/yellow]")
    console.print(prio_t)


@click.group(
    epilog="Start with [cyan]mechanic scan PATH[/cyan] on any rule repository, then "
    "[cyan]mechanic triage PATH[/cyan] once it loads cleanly - each command's own "
    "[cyan]--help[/cyan] has worked examples. Every command accepts [cyan]--json[/cyan] for "
    "machine-readable output. Full methodology, validated results, and known limitations: "
    "see [u]RESULTS.md[/u] and [u]README.md[/u] in the project repository. This CLI is the "
    "CORE product only - it needs no network, no API key, and no RSigma binary; the "
    "experimental repair-verification harness lives in the separate "
    "[cyan]mechanic-repair[/cyan] command (see [u]docs/core-vs-experiment.md[/u]).",
)
@click.version_option(prog_name="mechanic", package_name="mechanic")
def main() -> None:
    """[bold]mechanic[/bold] - detection-rule maintenance triage.

    Fault-isolated Sigma/Elastic/Splunk rule loading, git-driven behavioral
    staleness, a structural fragility classifier validated against MITRE's
    Summiting the Pyramid methodology, and an explainable review-priority
    triage on top - built to surface which detection rules need a human
    look, not to hand down verdicts. Every command below has its own
    [cyan]--help[/cyan] with worked examples - see [cyan]mechanic COMMAND --help[/cyan].

    This is the CORE product: it never imports the Stage 3 repair pipeline
    (no RSigma, no network, no LLM API key required for any command here).
    The repair-verification harness is a separate, quarantined experiment -
    see [u]docs/core-vs-experiment.md[/u] and the [cyan]mechanic-repair[/cyan] command.
    """


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--fmt",
    default="sigma",
    show_default=True,
    type=_FMT_CHOICE,
    help="Rule format to parse (see mechanic/discovery.py for the full registry).",
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of tables.")
def scan(path: Path, fmt: str, as_json: bool) -> None:
    """Load every rule under PATH and report exactly what failed and why.

    Fault-isolated: one malformed file (bad YAML, a null field a validator
    doesn't expect, a deprecated condition syntax) is caught and reported
    per-file - it never aborts the whole scan. This is the first thing to
    run against a new or unfamiliar rule repository, before staleness or
    triage, since both of those silently skip whatever scan would have
    flagged as a load failure.

    \b
    Examples:
      mechanic scan ./sigma/rules
      mechanic scan --fmt elastic_toml ./elastic-detection-rules/rules
      mechanic scan --json ./sigma/rules > scan.json
    """
    result, validate_failures = _scan(path, fmt)
    if as_json:
        d = result.to_dict()
        d["validate_failures"] = [f.to_dict() for f in validate_failures]
        _print_json(d)
    else:
        _render_scan_report(result, validate_failures)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--fmt", default="sigma", show_default=True, type=_FMT_CHOICE, help="Rule format to discover.")
@click.option(
    "--mechanical-threshold",
    default=churn.DEFAULT_THRESHOLD,
    show_default=True,
    type=float,
    help="Fraction of current rule count a commit must touch to be excluded as mechanical (bulk import/reformat).",
)
@click.option("--top", "top_n", default=20, show_default=True, type=int, help="How many of the stalest rules to show.")
@click.option(
    "--subdir",
    default=None,
    help="Restrict rule discovery/counting to this path within the repo (git root stays at PATH).",
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of tables.")
def staleness(
    path: Path, fmt: str, mechanical_threshold: float, top_n: int, subdir: Optional[str], as_json: bool
) -> None:
    """Behavioral churn: which rules has nobody organically touched?

    Filters out mass mechanical commits (bulk imports, schema migrations,
    reformats) before computing anything - those otherwise dominate raw
    commit counts and make every rule look "actively maintained." Reports
    per-rule organic commit counts, days since last touch, and a threshold-
    sensitivity table so the mechanical cutoff isn't taken on faith.

    \b
    Examples:
      mechanic staleness ./sigma --subdir rules
      mechanic staleness --mechanical-threshold 0.05 --top 50 ./sigma --subdir rules
      mechanic staleness --fmt splunk_yaml --subdir detections ./splunk-security-content
    """
    try:
        report = churn.compute_staleness(path, fmt, mechanical_threshold, subdir=subdir)
    except churn.ChurnError as e:
        err_console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    if as_json:
        _print_json(report.to_dict(top_n=top_n))
    else:
        _render_staleness_report(report, top_n)


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Always dumps JSON; flag kept for CLI symmetry with other commands.")
def ast(file: Path, as_json: bool) -> None:
    """Dump one Sigma rule's parsed, syntax-independent AST.

    Selections/filters as named nodes, AND/OR/NOT as structure, an explicit
    negated flag on every leaf. Mainly a debugging tool for inspecting how
    a specific rule gets parsed before trusting `triage`'s classification
    of it - Sigma only (see `mechanic explain` for Elastic/Splunk).

    \b
    Examples:
      mechanic ast ./sigma/rules/windows/some_rule.yml
      mechanic ast ./sigma/rules/windows/some_rule.yml | jq .conditions
    """
    rules, failures = loader.load_file(file)
    if failures:
        for f in failures:
            err_console.print(f"[red]{f.category}[/red]: {f.message} - {f.fix_hint}")
        raise SystemExit(1)
    if not rules:
        err_console.print("[yellow]No rule documents found in file.[/yellow]")
        raise SystemExit(1)
    trees = [ast_repr.build_ast(r.rule) for r in rules]
    _print_json(trees[0] if len(trees) == 1 else trees)


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--fmt", default="sigma", show_default=True, type=_FMT_CHOICE, help="Rule format to discover.")
@click.option(
    "--mechanical-threshold",
    default=churn.DEFAULT_THRESHOLD,
    show_default=True,
    type=float,
    help="Fraction of current rule count a commit must touch to be excluded as mechanical (bulk import/reformat).",
)
@click.option("--top", "top_n", default=20, show_default=True, type=int, help="How many of the stalest rules to show.")
@click.option("--subdir", default=None, help="Restrict staleness to this path within the repo.")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of tables.")
def report(
    path: Path,
    fmt: str,
    mechanical_threshold: float,
    top_n: int,
    subdir: Optional[str],
    as_json: bool,
) -> None:
    """Run `scan` and `staleness` together in one pass.

    Convenience wrapper - identical output to running both commands
    separately, useful when you want the full load-health + staleness
    picture for a repository in one shot (e.g. piping to a single JSON
    file for a CI artifact).

    \b
    Examples:
      mechanic report ./sigma --subdir rules
      mechanic report --json ./sigma --subdir rules > report.json
    """
    result, validate_failures = _scan(path, fmt)
    try:
        staleness_report = churn.compute_staleness(path, fmt, mechanical_threshold, subdir=subdir)
        staleness_error = None
    except churn.ChurnError as e:
        staleness_report = None
        staleness_error = str(e)

    if as_json:
        d: dict[str, Any] = {"scan": result.to_dict()}
        d["scan"]["validate_failures"] = [f.to_dict() for f in validate_failures]
        d["staleness"] = staleness_report.to_dict(top_n=top_n) if staleness_report else None
        d["staleness_error"] = staleness_error
        _print_json(d)
    else:
        _render_scan_report(result, validate_failures)
        if staleness_report:
            _render_staleness_report(staleness_report, top_n)
        else:
            err_console.print(f"[red]staleness skipped: {staleness_error}[/red]")


@main.command()
@click.argument("path", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--fmt", default="sigma", show_default=True, type=_FMT_CHOICE, help="Rule format to discover.")
@click.option(
    "--mechanical-threshold",
    default=churn.DEFAULT_THRESHOLD,
    show_default=True,
    type=float,
    help="Fraction of current rule count a commit must touch to be excluded as mechanical (bulk import/reformat).",
)
@click.option("--top", "top_n", default=20, show_default=True, type=int, help="How many rules to show in the sorted table.")
@click.option(
    "--subdir",
    default=None,
    help="Restrict rule discovery/counting to this path within the repo (git root stays at PATH).",
)
@click.option(
    "--refresh", is_flag=True, help="Force re-mining git history, ignoring any cached mine_commits result."
)
@click.option(
    "--ordering",
    type=click.Choice(["tier_first", "staleness_first", "priority_first"]),
    default="tier_first",
    show_default=True,
    help="Which unweighted sort/lookup strategy to scan by (no combined score exists - see RESULTS.md).",
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of tables.")
def triage(
    path: Path,
    fmt: str,
    mechanical_threshold: float,
    top_n: int,
    subdir: Optional[str],
    refresh: bool,
    ordering: str,
    as_json: bool,
) -> None:
    """Staleness and fragility, side by side, sorted for review.

    [bold yellow]NOT a combined score[/bold yellow] - a pre-registered correlation
    experiment found no association between the two axes reliable enough to
    fuse into one number (see RESULTS.md, "Part 3"). Every rule keeps both
    signals and its full reasoning; the sort order is a scanning convenience,
    not a verdict. Unscoreable rules get their own section - never a
    guessed tier. Git history is mined once and cached to disk under
    PATH/.mechanic_cache/, keyed to the repo's current commit - safe to
    re-run repeatedly without re-paying the mining cost.

    \b
    Examples:
      mechanic triage ./sigma --subdir rules
      mechanic triage --ordering staleness_first --top 50 ./sigma --subdir rules
      mechanic triage --refresh ./sigma --subdir rules   # repo moved forward, force re-mine
      mechanic triage --json ./sigma --subdir rules | jq '.rules[0]'
    """
    try:
        report = priority.compute_triage(path, fmt, mechanical_threshold, subdir=subdir, refresh=refresh)
    except churn.ChurnError as e:
        err_console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    if as_json:
        _print_json(report.to_dict(top_n=top_n, ordering=ordering))
    else:
        _render_triage_report(report, top_n, ordering=ordering)


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--fmt", default="sigma", show_default=True, type=_FMT_CHOICE, help="Rule format FILE belongs to.")
@click.option(
    "--mechanical-threshold",
    default=churn.DEFAULT_THRESHOLD,
    show_default=True,
    type=float,
    help="Fraction of current rule count a commit must touch to be excluded as mechanical (bulk import/reformat).",
)
@click.option(
    "--subdir", default=None, help="Restrict rule discovery/counting within the auto-detected git root."
)
@click.option(
    "--refresh", is_flag=True, help="Force re-mining git history, ignoring any cached mine_commits result."
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of prose + tables.")
def explain(
    file: Path, fmt: str, mechanical_threshold: float, subdir: Optional[str], refresh: bool, as_json: bool
) -> None:
    """Plain-English justification for why one rule sits where it does.

    Auto-detects the git root above FILE and re-runs the same computation
    `mechanic triage` uses, so the two commands are always consistent, then
    prints a short prose explanation first (staleness, tier, what drove it,
    any triage hypothesis - and, for Elastic/Splunk, an explicit caveat that
    the tier wasn't computed with the AND/OR correction Sigma's AST path
    gets), followed by the full field-level detail for anyone who wants to
    verify it. "Review this," never a verdict.

    \b
    Examples:
      mechanic explain ./sigma/rules/windows/some_rule.yml
      mechanic explain --fmt splunk_yaml ./splunk-security-content/detections/some_rule.yml
      mechanic explain --json ./sigma/rules/windows/some_rule.yml | jq .fragility
    """
    file = file.resolve()
    root = file.parent
    while not (root / ".git").exists():
        if root.parent == root:
            err_console.print(f"[red]no .git directory found above {file}[/red]")
            raise SystemExit(1)
        root = root.parent
    try:
        report = priority.compute_triage(root, fmt, mechanical_threshold, subdir=subdir, refresh=refresh)
    except churn.ChurnError as e:
        err_console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    rel = str(file.relative_to(root)).replace("\\", "/")
    match = next((r for r in report.scoreable + report.unscoreable if r.file == rel), None)
    if match is None:
        err_console.print(f"[red]{rel} was not found among discovered rules under {root} (fmt={fmt}).[/red]")
        raise SystemExit(1)
    if as_json:
        _print_json(match.to_dict())
    else:
        _render_explain(match)


@main.command("priority-legend")
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of a table.")
def priority_legend(as_json: bool) -> None:
    """Print the priority matrix itself - the full, fixed lookup table
    every rule's priority label comes from, plus the rationale for why
    it's shaped the way it is. Needs no repository - this is a static
    schema, not a computation over any rule.

    \b
    Examples:
      mechanic priority-legend
      mechanic priority-legend --json
    """
    schema = priority.priority_matrix_schema()
    if as_json:
        _print_json(schema)
        return
    console.print("[bold]mechanic priority-legend[/bold]\n")
    console.print(schema["rationale"])
    console.print()
    t = Table(title="Priority matrix (fragility tier × staleness band)")
    t.add_column("tier (worst -> best)")
    for band in schema["staleness_bands_stale_to_fresh"]:
        t.add_column(band)
    for tier in schema["tiers_worst_to_best"]:
        row = [tier]
        for band in schema["staleness_bands_stale_to_fresh"]:
            label = next(c["label"] for c in schema["cells"] if c["tier"] == tier and c["staleness_band"] == band)
            style = _PRIORITY_STYLE.get(label, "")
            row.append(f"[{style}]{label}[/{style}]" if style else label)
        t.add_row(*row)
    console.print(t)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Interface to bind the local server to.")
@click.option("--port", default=8642, show_default=True, type=int, help="Port to serve on.")
@click.option("--no-browser", is_flag=True, help="Don't automatically open a browser tab.")
def gui(host: str, port: int, no_browser: bool) -> None:
    """Launch the local web GUI - a VIEW over this same core engine.

    Runs fully offline: no network access, no API key, no RSigma. It is a
    thin FastAPI server that calls straight into `mechanic.priority`/
    `mechanic.churn` (the exact same functions `triage`/`explain` use) and
    serves their JSON to a static frontend - it never recomputes or
    reshapes an analysis result, and it never exposes the Stage 3 repair
    experiment (see docs/core-vs-experiment.md). Needs the optional `gui`
    extra: [cyan]pip install "mechanic\[gui]"[/cyan].

    \b
    Examples:
      mechanic gui
      mechanic gui --port 9000 --no-browser
    """
    try:
        from mechanic.gui.server import run_server
    except ImportError:
        err_console.print(
            "[red]The GUI needs extra dependencies that aren't installed.[/red]\n"
            'Install them with: [cyan]pip install "mechanic\\[gui]"[/cyan]'
        )
        raise SystemExit(1)
    run_server(host=host, port=port, open_browser=not no_browser)


if __name__ == "__main__":
    main()
