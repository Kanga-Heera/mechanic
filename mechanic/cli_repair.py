"""EXPERIMENT CLI - Stage 3 repair-verification harness (`mechanic-repair verify`).

Quarantined from `mechanic/cli.py` (the CORE CLI) per
`docs/core-vs-experiment.md`: the reactor core (`scan`/`staleness`/`triage`/
`explain`) must import and run with zero dependency on the repair pipeline -
no RSigma binary, no network, no LLM API key. This module is the ONLY place
`mechanic.verify` is imported from a CLI entrypoint; importing `mechanic.cli`
alone never pulls this module in.

Installed as its own console script, `mechanic-repair`, so running the core
tool never touches this file at all:

    mechanic-repair verify RULE --against events.evtx
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import rich_click as click
from rich.console import Console
from rich.table import Table

from mechanic import verify as verifymod

console = Console()
err_console = Console(stderr=True)

click.rich_click.USE_RICH_MARKUP = True
click.rich_click.USE_MARKDOWN = False
click.rich_click.MAX_WIDTH = 100
click.rich_click.OPTION_GROUPS = {
    "mechanic-repair verify": [
        {"name": "Harness", "options": ["--against", "--pipeline", "--no-auto-pipeline", "--rsigma-bin"]},
        {"name": "Output", "options": ["--json", "--help"]},
    ],
}


def _print_json(data: dict[str, Any]) -> None:
    click.echo(json.dumps(data, indent=2, default=str))


def _render_verify_report(report: "verifymod.VerifyReport") -> None:
    console.print(f"[bold]mechanic-repair verify — {report.rule_file}[/bold]")
    console.print(f"rule: {report.rule_title or '-'} ({report.rule_id or 'no id'})")
    console.print(f"events: {report.event_source}")
    console.print(f"rsigma v{report.rsigma_version}, pipeline: {report.pipeline_description or 'none'}")
    if report.discovery is not None:
        d = report.discovery
        console.print(f"auto-discovered field mapping: {d.mapping}", style="dim")
        if d.unresolved:
            console.print(f"[yellow]could not resolve path for field(s): {d.unresolved}[/yellow]")
        if d.ambiguous:
            console.print(f"[yellow]ambiguous candidates (tie-broken, shown for transparency): {d.ambiguous}[/yellow]")
    console.print()

    if report.any_unverifiable:
        console.print(
            f"[bold red]UNVERIFIABLE[/bold red] — {report.unverifiable_count} of {len(report.outcomes)} event(s) "
            "could not be trusted. A gate decision built on these would be worse than no decision.",
        )
    else:
        console.print(
            f"[bold green]TRUSTED[/bold green] — {report.trusted_fired_count} fired, "
            f"{report.trusted_no_fire_count} did not, all verified.",
        )
    console.print()

    t = Table(title="Per-event results")
    t.add_column("#", justify="right")
    t.add_column("label")
    t.add_column("fired")
    t.add_column("status")
    t.add_column("reasons / evidence", overflow="fold")
    for o in report.outcomes:
        fired_str = "[bold]FIRED[/bold]" if o.fired else "no fire"
        status_str = "[green]trusted[/green]" if o.status == "trusted" else "[bold red]UNVERIFIABLE[/bold red]"
        evidence = "; ".join(o.reasons) if o.reasons else (
            ", ".join(f"{m.get('field')}={m.get('value')!r}" for m in o.matched_fields) or "-"
        )
        t.add_row(str(o.index), o.label or "-", fired_str, status_str, evidence)
    console.print(t)


@click.group()
@click.version_option(prog_name="mechanic-repair", package_name="mechanic")
def main() -> None:
    """[bold]mechanic-repair[/bold] - Stage 3 EXPERIMENT: repair-verification harness.

    This is NOT the core product - see [u]docs/core-vs-experiment.md[/u].
    It requires a pinned RSigma binary on PATH (or $MECHANIC_RSIGMA_BIN) and,
    for repair *generation* (invoked via scripts/, not this CLI), a live
    GROQ_API_KEY. The core `mechanic` CLI (scan/staleness/triage/explain)
    never imports this module and has no such requirement.
    """


@main.command()
@click.argument("rule", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--against",
    "logset",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Event file to check RULE against: a .evtx file, or a JSON/NDJSON file of events.",
)
@click.option(
    "--pipeline",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="pySigma-compatible field-mapping pipeline YAML to use as-is, instead of auto-discovery.",
)
@click.option(
    "--no-auto-pipeline",
    is_flag=True,
    help="Disable auto-discovering a field-mapping pipeline for EVTX input; evaluate RSigma's raw field paths as-is.",
)
@click.option(
    "--rsigma-bin",
    default=None,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help=f"Path to the pinned rsigma binary (v{verifymod.PINNED_VERSION}). Defaults to $MECHANIC_RSIGMA_BIN, then PATH.",
)
@click.option("--json", "as_json", is_flag=True, help="Print machine-readable JSON instead of tables.")
def verify(
    rule: Path,
    logset: Path,
    pipeline: Optional[Path],
    no_auto_pipeline: bool,
    rsigma_bin: Optional[Path],
    as_json: bool,
) -> None:
    """Check whether RULE fires on each event in a log set - with a guard.

    Wraps RSigma's `engine eval` (pinned v0.21.0 - see
    docs/stage3-harness-evaluation.md). RSigma silently reports "0 matches"
    when a rule's fields don't exist under the paths it parsed an event
    into - this command never trusts that at face value. Every event comes
    back tagged [bold]trusted[/bold] (field presence AND event count both
    independently confirmed) or [bold red]UNVERIFIABLE[/bold red] (loud,
    with the reason) - never a silent pass.

    For EVTX input, a field-mapping pipeline is auto-discovered by default:
    a dry pass finds the real nested paths RSigma parsed the event into,
    then maps each of RULE's own fields to whichever path ends in that
    field name. Disable with --no-auto-pipeline, or supply your own with
    --pipeline. JSON/NDJSON input is assumed already flat; mismatches are
    still detected, just not auto-repaired.

    \b
    Examples:
      mechanic-repair verify rule.yml --against positive.evtx
      mechanic-repair verify rule.yml --against events.ndjson --json
      mechanic-repair verify rule.yml --against positive.evtx --pipeline my_pipeline.yml
    """
    try:
        report = verifymod.evaluate(
            rule, logset, pipeline=pipeline, auto_pipeline=not no_auto_pipeline, rsigma_bin=rsigma_bin
        )
    except verifymod.VerifyError as e:
        err_console.print(f"[red]{e}[/red]")
        raise SystemExit(1)
    if as_json:
        _print_json(report.to_dict())
    else:
        _render_verify_report(report)
    if report.any_unverifiable:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
