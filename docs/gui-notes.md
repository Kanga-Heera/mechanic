# The GUI: what it is, how it stays a view, and what it doesn't do

`mechanic gui` is a local web GUI over the CORE engine - `scan`/`staleness`/
`triage`/`explain`'s functionality, with the priority matrix
(`docs/core-hardening-status.md`'s companion feature), presented for a SOC
analyst to browse without reading the CLI's own docs. This document covers
what it is, how "it's just a view, never a recomputation" is actually
enforced (not just claimed), and the honest scope of what it doesn't do.

## Architecture

```
mechanic gui
  -> mechanic/cli.py's `gui` command (lazy-imports mechanic.gui.server)
  -> mechanic/gui/server.py: a FastAPI app
       - POST /api/load            starts a background thread running
                                    priority.compute_triage() (the SAME
                                    function `mechanic triage` calls)
       - GET  /api/jobs/{id}       poll for progress (real, not simulated -
                                    see "Progress reporting" below)
       - GET  /api/jobs/{id}/result   the finished TriageReport's
                                       .to_dict() - identical to what
                                       `mechanic triage --json` prints
       - GET  /api/jobs/{id}/rule  one rule's .to_dict(), looked up in the
                                    already-computed report (no recompute)
       - GET  /api/jobs/{id}/rule-source   the rule file's raw content,
                                    verbatim, confined to the loaded
                                    repository root (no analysis - a file
                                    read, same trust model as the CLI)
       - GET  /api/jobs/{id}/rule-history  every mined commit that touched
                                    this file (under any past rename),
                                    filtered from the SAME all_facts the
                                    report was built from - not re-mined,
                                    not a new analysis, just a per-file
                                    projection of already-mined facts
       - GET  /api/priority-legend    priority.priority_matrix_schema()
  -> mechanic/gui/static/{index.html,style.css,app.js}
       a single-page vanilla-JS frontend (no build step, no framework, no
       CDN dependency) that fetches the JSON above and renders it -
       filtering/sorting the already-fetched rows client-side, never
       calling back into the engine for a different "view" of the same
       data.
```

**Proof this is a passthrough, not a reimplementation**:
`tests/test_gui.py::test_load_and_poll_and_result_matches_core_directly`
asserts the GUI's HTTP response for a loaded repo is **byte-identical**
(as parsed JSON) to calling `priority.compute_triage(...).to_dict()`
directly in the same test. If a future GUI change ever reshapes or
recomputes anything, that test fails.

## Progress reporting is real, not simulated

`compute_triage()` gained an optional `progress_cb(stage, done, total)`
parameter (Part 1 of this feature, additive only - every existing call
site passes nothing and behaves exactly as before). The GUI's background
job thread passes a callback that updates an in-memory `Job` record; the
frontend polls `/api/jobs/{id}` every 600ms and shows real numbers off
that:

- `mining`: a running commit count off `churn._mine_commits`'s actual
  PyDriller traversal (every ~250 commits) - or an instant `cache_hit` if
  `mine_commits_cached` finds a valid disk cache (see
  `docs/core-hardening-status.md` Part 4 for why that cache exists).
- `staleness` / `semantic_diff`: coarse stage markers around the two
  whole-corpus passes.
- `classifying`: `i / total_rules` off the actual per-rule fragility loop
  - the slowest part at corpus scale (QUICKSTART.md's "honest timing
    note": several minutes on SigmaHQ's full 3,144-rule `rules/`), so this
    is the stage where a real percentage matters most.

No stage is a fake timer or a spinner standing in for unknown progress
except the two coarse single-step markers (`staleness`/`semantic_diff`),
which are genuinely fast relative to mining/classifying and are shown as
indeterminate rather than a fabricated percentage.

## Error handling: the core's own loud failures, surfaced, not swallowed

A job thread catches `churn.ChurnError` (no `.git`, a shallow clone) and
stores the exact message; `/api/jobs/{id}/result` returns HTTP 422 with
that same string as `detail`, and the frontend renders it as a plain error
banner. A path that doesn't exist is rejected at `POST /api/load` (HTTP
400) before a job is even created. Zero rules discovered is not an error -
the frontend shows a clear "no rules found" message instead of an empty
table. `tests/test_gui.py` has a case for each of these three.

## Offline, by construction

The served page loads no external stylesheet, font, or script - `style.css`
uses only system font stacks (`-apple-system`/`Segoe UI`/... for UI text,
`ui-monospace`/`SFMono-Regular`/... for rule content), and `app.js` uses
only `fetch()` against this same origin. `tests/test_gui.py::
test_static_frontend_has_no_external_network_references` greps all three
static files for `http://`/`https://`/CDN-hostname substrings and fails if
any appear. The server itself imports no HTTP client library (`requests`,
`urllib.request`) - it has no code path that could make an outbound call.

## Repair stays quarantined and unexposed

`mechanic/gui/server.py` imports only `mechanic.churn` and
`mechanic.priority` - core modules. `tests/test_gui.py::
test_gui_source_imports_nothing_from_experiment` source-scans every file
under `mechanic/gui/` for the same experiment-module leaf names
`tests/test_core_isolation.py` checks against core; `test_gui_has_no_
repair_endpoints` checks the actual FastAPI route table for the same. The
existing `tests/test_core_isolation.py` (Part 0 of the hardening pass) is
re-run as its own subprocess from inside `test_gui.py` too, so adding the
GUI can never silently break that boundary without a test noticing in the
same file that added the GUI.

## Design

Dark, calm, restrained - `mechanic/gui/static/style.css`'s header comment
states the palette (`--bg-base` near-black, `--bg-panel`/`--bg-panel-
raised` layered dark blue, `--accent`/`--accent-bright` for interactive
emphasis). Priority is never color-only: every badge carries a small
colour dot, the label text, and the `tier×band` axis pair - a
colour-blind viewer reading only the text still gets the same information
a sighted-for-hue viewer gets from the colour.

**The status (priority) colour ramp was run through the `dataviz` skill's
`validate_palette.js`** against this exact dark surface, not eyeballed -
categorical/CVD-separation mode, since CRITICAL/HIGH/MEDIUM/LOW are four
distinct states, not a magnitude ramp. It adopts the skill's own reference
status palette (good/warning/serious/critical); CVD separation passes
outright (worst adjacent pair ΔE 11.3, clearing the 8 floor), while the
strict "normal-vision, no-label" floor (>=15 ΔE) lands at 13.6 on the
tightest pair - a wide sweep of alternate red/orange/yellow/green
combinations (recorded in `style.css`'s own comment on the ramp) found
nothing that cleared 15 outright; three adjacent warm hues in a stoplight
scheme sit close to the perceptual limit at matched lightness/chroma.
Accepted at 13.6/15 specifically because every instance of these colours
in this UI is a labelled badge (colour dot + text + tier×band), never a
bare colour swatch relying on hue alone - the condition the strict floor
exists to guard against. The tier-distribution and staleness-distribution
charts deliberately use a single accent-blue hue instead (a magnitude
encoding, per the skill's "sequential = one hue" rule) precisely so they
don't compete with the status ramp's meaning.

**Layout**: a persistent sidebar (repository form, recent repos via
`localStorage` - never sent to the server, load-and-forget convenience
only) plus a wide content area (stat tiles, three small charts, the
triage table) - closer to a console than a stacked web form. The rule
detail panel is tabbed (Overview / Source / History) rather than one long
scroll of tables, so the primary read (the explain narrative + priority)
isn't buried under raw field dumps; Source and History are one click away
for anyone who wants to verify against the rule's actual content and git
past.

## What this GUI deliberately does not do

- No repair generation, no verification harness, no `mechanic-repair`
  anything - see `docs/core-vs-experiment.md`.
- No editing of rules, no writing to the loaded repository - read-only,
  same as the CLI.
- No authentication, no multi-user support, no persistence across a
  server restart (jobs live in an in-memory dict) - this is a local,
  single-operator tool, the same posture `mechanic triage` already has.
- No new analysis, no new number - see "Architecture" above.
