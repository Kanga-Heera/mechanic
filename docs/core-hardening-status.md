# Core hardening pass status: is the reactor core flawless?

This document is the go/no-go writeup for the "harden the CORE" pass,
mirroring `docs/stage3-phase{1,2,3}-status.md`'s format. It covers six
parts, each committed separately: (0) separating core from experiment,
(1) adversarial-input robustness, (2) output trustworthiness/readability,
(3) a real end-to-end proof, (4) regression-locking the validated numbers,
(5) this document plus the README status paragraph. Full evidence for
every claim below is in the commit history and the test files named.

## Part 0 — is the core actually independent of the experiment?

**Yes, and it wasn't quite true before this pass.** `mechanic/cli.py` (the
core CLI) had exactly one dependency on the Stage 3 repair pipeline: a
module-level `from mechanic import verify as verifymod`, imported for the
`verify` subcommand. Every other core module (`loader`, `churn`,
`discovery`, `categories`, `semantic_diff`, `ast_repr`, `fragility`,
`text_fragility`, `structural_detectors`, `protected_literals`, `refdata`,
`splunk_macros`, `priority`, `legacy_v1`) already had zero cross-dependency,
confirmed by grep, not assumed. That one dependency is now gone: `verify`
moved to its own file (`mechanic/cli_repair.py`) and its own console script
(`mechanic-repair`), so `import mechanic.cli` - and every core command -
never touches the experiment tree at all. `requests` (experiment-only)
moved out of the core's `dependencies` into an optional `repair` extra.

Enforcement, not just claim: `tests/test_core_isolation.py` spawns a fresh
subprocess, imports `mechanic.cli`, and asserts no experiment module
appears in `sys.modules`; a second check runs `scan`/`staleness`/`triage`/
`explain` end-to-end against a real fixture repo with `GROQ_API_KEY` and
`MECHANIC_RSIGMA_BIN` both unset, asserting clean completion.

## Part 1 — does the core survive adversarial input?

**Yes - two real gaps found and fixed, everything else proven correct and
now locked.** Built an adversarial fixture set
(`tests/test_loader_adversarial.py`) covering every case named in the
brief: empty file, comments-only file, bare `---` marker, non-YAML/binary
junk, truncated YAML, a non-mapping top-level document, every field null,
no detection block, a 10MB junk file, a UTF-8 BOM, CRLF line endings, an
empty directory, a symlink/junction loop, a file vanishing mid-scan, and a
10,000-rule directory (opt-in, since it takes several minutes - a smaller
30/200-rule case runs by default as a linearity sanity check).

Two real bugs surfaced, not hypothesized:

1. A file that parses as valid YAML but yields zero documents (empty,
   comments-only, a bare `---`) previously vanished from every count -
   not `files_ok`, not `files_failed`, not `failures`. Fixed: now flagged
   `empty_or_no_documents`, so `files_scanned == files_ok + files_failed`
   holds again, always.
2. `mechanic/discovery.py`'s file walker (pathlib `Path.glob`) had no
   real symlink-loop protection, reproduced concretely with an actual
   Windows directory-junction loop (32 duplicate nested hits before the
   fix). Replaced with a custom walker tracking each visited directory's
   (device, inode) identity - platform- and link-type-independent, proven
   against the same repro: 1 file found in 2ms afterward, not a loop.

Everything else in the adversarial set was already handled correctly by
the existing fault-isolation design (per-file/per-document try/except,
`OSError` caught around file reads) - this pass didn't need to change that
logic, only prove it and lock it with a regression test.

## Part 2 — is the output trustworthy and readable?

**Yes, after fixing one real bug the new tests caught.**
`churn.mine_commits_cached`'s cache hit/miss progress messages were being
printed to **stdout** with plain `print()` - every `mechanic triage
--json`/`explain --json` call that needed to mine or re-mine git history
was emitting a diagnostic line before the JSON, corrupting it for any
consumer piping to `jq` or `json.loads`. This is exactly the kind of bug a
schema-locking test is for: found by `tests/test_cli.py`, not anticipated
going in. Fixed by moving those messages to stderr - confirmed to be the
only stdout-polluting `print()` in any core module.

Added, per the brief: a one-line summary ("N rules, X fragile, Y stale, Z
need attention") on `triage`, in both human and `--json` output; a "why
(driving observable)" column on the ranked table so the specific reason a
rule is flagged doesn't require a separate `explain` call per row; a
visible legend under the table explaining the text-path confidence
asterisk (the caveat itself already existed in both outputs, just without
an explanation of what it meant); and `triage`/`explain` `--json` schema
documentation in README.md (previously only `scan`/`staleness`/`ast`/
`report` were documented there). Staleness and fragility remain two
separate, un-combined axes throughout - no blended score was added
anywhere, locked by `tests/test_cli.py::
test_triage_never_combines_staleness_and_fragility_into_one_score`.

## Part 3 — does it actually work, end to end, on a real repo?

**Yes.** `QUICKSTART.md` documents `scan` -> `staleness` -> `triage` ->
`explain` against a real, pinned SigmaHQ checkout
(`da9bb07d642a2826e89702445d32c795209ec108`, `rules/`, 3,144 files),
every command and its real output reproduced verbatim, run from a clean
`pip install`. One honest finding disclosed rather than hidden: a
full-corpus `staleness`/`triage`/`explain` run on SigmaHQ takes several
minutes wall-clock even with git-history mining served from a warm cache
- the semantic-diff and per-rule fragility passes do real, non-trivial
work per rule, and 3,144 rules is a lot of rules. This is pre-existing
behavior this pass did not introduce or need to fix; it's disclosed in
`QUICKSTART.md`'s "honest timing note" precisely because a quickstart
that quietly took several minutes without saying so would itself be a
readability/trust failure of the kind Part 2 exists to prevent. `scan`
(no git involved) stays fast regardless of corpus size.

## Part 4 — are the validated numbers locked against silent drift?

**Yes, for everything that is genuinely time-invariant; deliberately not
for the one thing that isn't.** The STP rank correlation (Kendall's tau-b
0.361, Spearman's rho 0.392, mapped quadratic-weighted kappa 0.316, n=72)
is locked against a new frozen, self-contained fixture
(`tests/fixtures/stp_validation_frozen.json`) so the test needs no
external repo clone ever again, while still re-running mechanic's real,
current classifier against every row - a future classifier change that
shifts any of these 72 real rules' tiers will show up here. The three
mechanical-commit figures (SigmaHQ 2,931 files, Elastic 1,064, Splunk
2,068 - immutable historical facts, not time-relative) are locked via a
small, safe addition to `churn._mine_commits` (`single=<hash>`, PyDriller's
own single-commit mode) against the pinned commit hashes.

The staleness reproduction *percentages* (51.1%/2.7%/5.6%) are
deliberately NOT bit-locked: RESULTS.md itself documents them as
wall-clock-relative against live, still-moving external repos, so an
exact-equality test there would be asserting stability the project's own
methodology never claimed. The mechanism that produces them (mechanical-
commit exclusion + organic-commit math) is already locked deterministically
in `tests/test_churn.py`'s synthetic-repo tests, referenced rather than
duplicated.

## Recommendation

**Go.** All six parts are committed separately, the full test suite is
green (198 passed, 37 skipped - the skip set is entirely the experiment's
own RSigma/API-key-gated tests, unchanged by this pass), and every
finding above - the two real bugs, the one real UX gap, the one real
timing characteristic - was disclosed rather than smoothed over, per this
project's standing reporting discipline. The core is ready to be described,
without qualification, as production-hardened; the experiment stays
exactly as honestly-measured and exactly as quarantined as it was before
this pass, unchanged in behavior, moved only in module location.
