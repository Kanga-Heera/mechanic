# mechanic — command reference

`mechanic` is a detection-rule maintenance triage tool for **Sigma** rule
repositories. Given a rule repository, it tells you which rules are
structurally fragile (easy for an attacker to evade with a trivial
rename/reorder/substitution) and which are behaviorally stale (nobody has
organically revised them), so you know what to look at first.

It runs entirely offline — no network access, no API key, no external
service — against a local git checkout. See `README.md` for the full
pitch and validation methodology, and `docs/gui.md` if you'd rather browse
results in a browser instead of the terminal.

## Install

```
pip install -e .            # core CLI only
pip install -e ".[gui]"     # + the local web GUI (`mechanic gui`)
pip install -e ".[dev]"     # + test tooling
```

## Commands at a glance

| Command | What it does | Scope |
|---|---|---|
| `scan` | Loads every rule under a path, reports load/parse failures per-file | Sigma-only |
| `staleness` | Which rules nobody has organically revised, by git history | Any format |
| `ast` | Dumps one rule's parsed structure (debugging aid) | Sigma-only |
| `report` | `scan` + `staleness` together, one JSON blob | Sigma-only |
| `triage` | Staleness and fragility side by side, sorted for review | Sigma-only |
| `explain` | Plain-English justification for one rule's triage result | Sigma-only |
| `priority-legend` | Prints the fixed tier × staleness lookup table | n/a (no repo needed) |
| `gui` | Launches the local web GUI over the same engine | Sigma-only |

Every command accepts `--json` for machine-readable output, and `--help`
for its own full option list and examples.

Fragility, tiering, and priority (`scan`/`triage`/`explain`/`report`) only
work on Sigma rules — this is deliberate, not a gap; see
`docs/core-vs-experiment.md` for why. `staleness` is the one exception: it
stays format-agnostic (`--fmt sigma|elastic_toml|splunk_yaml|yaml_generic`)
because git history is real regardless of what language a rule is written
in.

## `mechanic scan PATH`

Loads every rule file under `PATH` and reports exactly what failed and
why. Fault-isolated: one malformed file never aborts the whole scan. Run
this first against an unfamiliar repository — `staleness`/`triage` will
silently skip whatever `scan` would have flagged as a load failure.

```
mechanic scan ./sigma/rules
mechanic scan --json ./sigma/rules > scan.json
```

## `mechanic staleness PATH`

Which rules has nobody organically touched? Filters out mass mechanical
commits (bulk imports, schema migrations, reformats) before counting
anything, so a repo-wide reformat doesn't make every rule look "actively
maintained." Reports per-rule organic commit counts, days since last
touch, and a threshold-sensitivity table.

```
mechanic staleness ./sigma --subdir rules
mechanic staleness --mechanical-threshold 0.05 --top 50 ./sigma --subdir rules
mechanic staleness --fmt splunk_yaml --subdir detections ./splunk-security-content
```

Key options: `--fmt` (format to discover; default `sigma`), `--mechanical-
threshold` (fraction of the current rule count a commit must touch to
count as mechanical), `--subdir`, `--top`.

## `mechanic ast FILE`

Dumps one Sigma rule's parsed, syntax-independent AST — selections/filters
as named nodes, AND/OR/NOT as structure, an explicit negated flag on every
leaf. Mainly useful for checking how a specific rule gets parsed before
trusting `triage`'s classification of it.

```
mechanic ast ./sigma/rules/windows/some_rule.yml
mechanic ast ./sigma/rules/windows/some_rule.yml | jq .conditions
```

## `mechanic report PATH`

Runs `scan` and `staleness` together in one pass — identical output to
running both separately, convenient for a single CI artifact.

```
mechanic report ./sigma --subdir rules
mechanic report --json ./sigma --subdir rules > report.json
```

## `mechanic triage PATH`

The main event: staleness and fragility side by side, sorted for review.
**Not a combined score** — a pre-registered correlation experiment found
no reliable association between the two axes to fuse into one number (see
`RESULTS.md`). Every rule keeps both signals and its full reasoning; the
sort order is a scanning convenience, not a verdict. Rules that can't be
confidently scored get their own section with a specific reason — never a
guessed tier.

Git history is mined once and cached to disk under `PATH/.mechanic_cache/`,
keyed to the repo's current commit — safe to re-run repeatedly without
re-paying the mining cost.

```
mechanic triage ./sigma --subdir rules
mechanic triage --ordering staleness_first --top 50 ./sigma --subdir rules
mechanic triage --refresh ./sigma --subdir rules   # repo moved forward, force re-mine
mechanic triage --json ./sigma --subdir rules | jq '.rules[0]'
```

Key options: `--ordering` (`tier_first` / `staleness_first` / `priority_first`),
`--mechanical-threshold`, `--subdir`, `--top`, `--refresh` (force re-mine),
`--mining-timeout`.

## `mechanic explain FILE`

Plain-English justification for why one rule sits where it does.
Auto-detects the git root above `FILE` and re-runs the same computation
`triage` uses, so the two commands are always consistent. Prints a short
prose explanation first (staleness, tier, what drove it), then the full
field-level detail for anyone who wants to verify it against the
underlying data.

```
mechanic explain ./sigma/rules/windows/some_rule.yml
mechanic explain --json ./sigma/rules/windows/some_rule.yml | jq .fragility
```

## `mechanic priority-legend`

Prints the fixed tier × staleness lookup table every rule's priority label
comes from, plus the rationale for its shape. Needs no repository — it's a
static schema, not a computation.

```
mechanic priority-legend
mechanic priority-legend --json
```

## `mechanic gui`

Launches the local web GUI (`http://127.0.0.1:8642/` by default) — a view
over this same engine, nothing recomputed. Needs the optional `gui` extra.
See `docs/gui.md` for a full walkthrough.

```
mechanic gui
mechanic gui --port 9000 --no-browser
```

## JSON output

Every command's `--json` output is stable, documented data meant to be
piped to `jq` or consumed by another tool — see `README.md`'s "JSON
schema" section for the full shape of `triage`'s output specifically
(the richest of the set).

## Further reading

- `README.md` — what the tool is, validation methodology, full component
  breakdown.
- `QUICKSTART.md` — a real, verbatim walkthrough against a pinned SigmaHQ
  checkout.
- `docs/gui.md` — the web GUI.
- `docs/core-vs-experiment.md` — why fragility/tiering/priority are
  Sigma-only, and what's quarantined outside the core.
