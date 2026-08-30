#!/usr/bin/env python
"""Stage 3 Phase 3, Part 3: seeded, committed stratified sample over
SigmaHQ's own regression_data corpus.

Reproducibility discipline (this project has been burned by an
unreproducible sample before - see kappa-provenance.md Section 10,
problem 5, on the missing original phase0 sampling script): THIS SCRIPT is
the source of truth for the Phase 3 sample, not a pickle. Re-running it
with the same --seed against the same SigmaHQ checkout regenerates an
identical selection (modulo the corpus itself changing over time - SigmaHQ
is a live, growing repository). Its output is also committed directly
(data/phase3_sample_manifest.json) as an inspectable snapshot of exactly
what the one committed Phase 3 acceptance-rate run in RESULTS.md used.

A candidate rule is included only if, in order:
  1. it has a genuine EVTX regression fixture under SigmaHQ's own
     regression_data/ tree - an independently-authored known-positive
     event, never anything mechanic generated;
  2. it is a standard (non-correlation) rule mechanic.fragility can assign
     a tier to (UNSCOREABLE / insufficient-information rules are skipped -
     there's nothing to stratify them by);
  3. mechanic.verify.full_flat_event_from_evtx can actually build a
     template event from it: the fixture fires on exactly one record, and
     RSigma's own dry-pass discovery resolves it. A rule that fails this
     is skipped, not forced in with a degraded/guessed event - the same
     "discovery, not guessing" discipline verify.py already applies
     everywhere else.

WIDE (not narrow) projection, and why: the stored `template_event` uses
`verify.full_flat_event_from_evtx` - every field RSigma observes in the
record, not just the ones the ORIGINAL rule happens to reference. The
first Phase 3 run used the narrower `flat_event_from_evtx` and this
concretely mis-fired: a repair correctly proposing `ParentImage`/`Image`
for a rule whose original fragile atom was `CommandLine` alone got routed
to TELEMETRY_REPAIR, not because those fields are absent from the
telemetry, but because the narrow projection had never even tried to
resolve them. See docs/stage3-phase3-status.md for the full account.

Requires MECHANIC_RSIGMA_BIN (step 3 calls the harness) and a local SigmaHQ
checkout (--sigma-repo, default D:/sigma-research/sigma - the same one
tests/test_verify.py's SIGMA_REPO points at).

Usage:
    python scripts/sample_phase3_rules.py
    python scripts/sample_phase3_rules.py --per-tier 8 --seed 42
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # repo root - run without an editable install

from mechanic import ast_repr, fragility, loader, verify  # noqa: E402

SEED = 42
TARGET_PER_TIER = 10
TIERS = ["IOC", "Artifact", "Tool", "TTP"]


def _sigma_repo_default() -> Path:
    return Path("D:/sigma-research/sigma")


def _rule_path_for_regression_dir(sigma_repo: Path, regression_dir: Path) -> Path:
    """regression_data/<top>/<subpath>/<rule_basename>/ mirrors
    <top>/<subpath>/<rule_basename>.yml exactly - confirmed directly
    against multiple examples in the corpus (see
    docs/stage3-phase3-status.md for the check), not assumed."""
    rel = regression_dir.relative_to(sigma_repo / "regression_data")
    return (sigma_repo / rel).with_suffix(".yml")


def _discover_candidates(sigma_repo: Path) -> list[dict]:
    candidates = []
    regression_root = sigma_repo / "regression_data"
    for info_path in sorted(regression_root.rglob("info.yml")):
        d = info_path.parent
        evtxs = sorted(d.glob("*.evtx"))
        if not evtxs:
            continue
        rule_path = _rule_path_for_regression_dir(sigma_repo, d)
        if not rule_path.exists():
            continue
        candidates.append({"rule_path": rule_path, "evtx_path": evtxs[0]})
    return candidates


def _classify(rule_path: Path) -> Optional[str]:
    try:
        rules, failures = loader.load_file(rule_path)
    except Exception:
        return None
    if failures or not rules or rules[0].rule_type != "standard":
        return None
    tree = ast_repr.build_ast(rules[0].rule)
    return fragility.classify_rule(tree).tier


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sigma-repo", type=Path, default=_sigma_repo_default())
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--per-tier", type=int, default=TARGET_PER_TIER)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "phase3_sample_manifest.json")
    parser.add_argument("--rsigma-bin", type=Path, default=None)
    args = parser.parse_args()

    print(f"Scanning {args.sigma_repo / 'regression_data'} for EVTX-backed regression fixtures...")
    candidates = _discover_candidates(args.sigma_repo)
    print(f"{len(candidates)} candidate rule/fixture pair(s) with a resolvable rule file found.")

    by_tier: dict[str, list[dict]] = {t: [] for t in TIERS}
    unscoreable = 0
    for c in candidates:
        tier = _classify(c["rule_path"])
        if tier in by_tier:
            c["tier"] = tier
            by_tier[tier].append(c)
        else:
            unscoreable += 1
    print(f"{unscoreable} candidate(s) unscoreable/insufficient-information - excluded.")
    for t in TIERS:
        print(f"  tier {t}: {len(by_tier[t])} scoreable candidate(s) before harness validation")

    rng = random.Random(args.seed)
    selected: list[dict] = []
    skipped: list[dict] = []
    for tier in TIERS:
        pool = list(by_tier[tier])
        rng.shuffle(pool)
        kept = 0
        for c in pool:
            if kept >= args.per_tier:
                break
            try:
                template_event = verify.full_flat_event_from_evtx(c["rule_path"], c["evtx_path"], rsigma_bin=args.rsigma_bin)
            except verify.VerifyError as e:
                skipped.append({"rule_path": str(c["rule_path"]), "tier": tier, "reason": str(e)})
                continue
            info = verify.load_rule_info(c["rule_path"])
            selected.append(
                {
                    "rule_path": str(c["rule_path"].relative_to(args.sigma_repo)),
                    "evtx_path": str(c["evtx_path"].relative_to(args.sigma_repo)),
                    "tier": tier,
                    "rule_id": info.rule_id,
                    "title": info.title,
                    "template_event": template_event,
                }
            )
            kept += 1
        print(f"tier {tier}: selected {kept}/{args.per_tier} (attempted {len(pool)} candidate(s) in seeded order)")

    manifest = {
        "seed": args.seed,
        "per_tier_target": args.per_tier,
        "sigma_repo": str(args.sigma_repo),
        "total_selected": len(selected),
        "skipped_during_harness_validation": skipped,
        "rules": selected,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    print(f"\nWrote {len(selected)} rule(s) to {args.out}")


if __name__ == "__main__":
    main()
