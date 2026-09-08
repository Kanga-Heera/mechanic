# mechanic GUI

A local, offline web interface for browsing `mechanic`'s triage results
without using the CLI. It shows exactly what `mechanic triage` computes —
nothing here is a separate analysis.

## Starting it

```
pip install -e ".[gui]"
mechanic gui
```

This opens `http://127.0.0.1:8642/` in your browser. The server runs
entirely on your machine: no outbound network calls, no external
stylesheets/scripts/fonts, no account or login.

## Loading a repository

1. Enter the path to a local Sigma rule repository (must be a git
   checkout — staleness is computed from git history).
2. Optionally narrow to a subdirectory (e.g. `rules`) if the repo has
   non-rule content at its root.
3. Click **Load**. A progress bar tracks mining → staleness → behavioral
   diff → fragility classification; large repositories (thousands of
   rules) can take a few minutes on first load. Subsequent loads of the
   same repo are much faster (git history is cached on disk).
4. You can click **Stop** at any point to cancel a load in progress.

Recently loaded repositories are remembered in your browser (not sent
anywhere) so you can reload them with one click.

## Reading the results

- **Overview**: rule counts, a priority breakdown, and small charts for
  fragility tier and staleness distribution.
- **Triage table**: every rule, sorted by review priority by default.
  Filter by typing a path fragment, or by clicking the Priority/Tier chips.
  Click a column header to re-sort.
- **Priority legend**: click the sidebar button to see the full tier ×
  staleness matrix that produces each priority label, with the plain-English
  rationale for the ordering.
- **Rule detail**: click any row to open a panel with three tabs —
  *Overview* (the plain-English explanation, priority, and key facts),
  *Source* (the rule file's raw YAML), and *History* (the commits that
  touched this file, newest first).

A priority label is never invented for a rule mechanic can't confidently
assess — those rules appear under **Unscoreable rules** at the bottom of
the table with the specific reason (failed to parse, no query text, etc.).

## Scope

The GUI only analyses Sigma rules — this mirrors the CLI's own scope (see
`docs/core-vs-experiment.md` for why fragility/tiering/priority are
Sigma-only). Pointing it at a non-Sigma repository is rejected with a clear
message before any analysis starts.

## Loading a saved report instead

If you already have a `mechanic triage --json` output file, you can load
it directly via `POST /api/load-from-report` (see `mechanic/gui/server.py`)
instead of recomputing — useful for viewing a report generated on a
different machine.
