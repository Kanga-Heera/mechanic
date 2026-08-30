#!/usr/bin/env python
"""Stage 3 Phase 3, Part 3: the honest acceptance-rate run.

For each rule in the committed stratified sample
(data/phase3_sample_manifest.json), calls the LLM repair generator exactly
once, classifies the outcome via mechanic.repair_outcome (gate-enforced,
never LLM-asserted), and writes a full results JSON: every rule's outcome,
gate evidence, generation failures, and the model/endpoint actually used -
plus a summary matching exactly what RESULTS.md is required to report:
overall acceptance rate, breakdown by outcome, breakdown by fragility
tier, every rejection's failed condition(s), how often
gate.fully_exercised was False, and the generation-failure count.

NOTHING HERE IS TUNED TO MOVE THE NUMBER. A low acceptance rate is the
finding this whole stage exists to produce, not something to adjust the
classifier, the gate, or the sample to avoid - per the Phase 3 task spec's
Part 3, verbatim.

Requires GROQ_API_KEY (or whatever provider is configured via
mechanic.llm_client) and MECHANIC_RSIGMA_BIN. Makes one real network call
per rule in the sample - run the Part 0 smoke test first to confirm the
key/endpoint/parsing work before spending free-tier rate-limit budget
here.

Usage:
    python scripts/run_phase3_acceptance.py
    python scripts/run_phase3_acceptance.py --limit 3          # debugging
    python scripts/run_phase3_acceptance.py --sleep 5          # gentler on free-tier rate limits
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mechanic import evasion, llm_client, repair_generator, repair_outcome  # noqa: E402
from mechanic.synthetic_benign import synthetic_benign_event  # noqa: E402

_WORKER_SCRIPT = Path(__file__).resolve().parent / "_generate_repair_worker.py"


def _generate_repair_with_hard_timeout(rule_path: Path, *, model, base_url, timeout: float) -> repair_generator.GeneratedRepair:
    """Runs generate_repair() in its own subprocess with an OS-enforced
    wall-clock timeout - see _generate_repair_worker.py's module docstring
    for why: Python's own socket-level timeout was found NOT to reliably
    fire on this project's development machine (a stale/CLOSE_WAIT
    connection left the in-process call blocked for 10+ minutes past its
    stated timeout). `subprocess.run(timeout=...)` kills the child
    regardless of what syscall it's stuck in - a guarantee no in-process
    timeout parameter gave us here. Raises subprocess.TimeoutExpired or
    RuntimeError (never silently returns a fabricated repair) on failure -
    callers must treat either as this rule's generation having failed."""
    proc = subprocess.run(
        [sys.executable, str(_WORKER_SCRIPT), str(rule_path), model or "-", base_url or "-"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"generation worker exited {proc.returncode}: stderr={proc.stderr[-2000:]!r}")
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    if not payload.get("ok"):
        raise RuntimeError(f"{payload.get('error_type', 'Error')}: {payload.get('error')}")
    g = payload["generated"]
    return repair_generator.GeneratedRepair(
        proposed_rule_yaml=g["proposed_rule_yaml"],
        raw_model_text=g["raw_model_text"],
        model=g["model"],
        endpoint=g["endpoint"],
        no_repair_signal=g["no_repair_signal"],
        parse_note=g["parse_note"],
        raw_reasoning=g.get("raw_reasoning"),
    )


def run_one(sigma_repo: Path, entry: dict, *, model=None, base_url=None, rsigma_bin=None, llm_timeout: float = 90.0) -> dict:
    rule_path = sigma_repo / entry["rule_path"]
    template_event = entry["template_event"]
    tier = entry["tier"]

    # A single generic benign event derived from the rule's OWN fragile
    # atom (mechanic.synthetic_benign) - recomputed here rather than
    # stored in the manifest, so it always reflects the current
    # classifier. None, honestly, if no safe generic substitution exists
    # for this atom's field category (see that module's docstring) -
    # NO_NEW_FALSE_POSITIVES then reports not-applicable for this rule,
    # never a fabricated benign event.
    fragile, _ = evasion.fragile_atoms_for_rule(rule_path)
    benign_events: list[dict] = []
    if fragile:
        atom = fragile[0]
        if atom.field and isinstance(atom.value, str):
            b = synthetic_benign_event(template_event, atom.field, atom.value)
            if b is not None:
                benign_events = [b]

    try:
        generated = _generate_repair_with_hard_timeout(rule_path, model=model, base_url=base_url, timeout=llm_timeout)
    except subprocess.TimeoutExpired:
        return {
            "rule_path": entry["rule_path"],
            "rule_id": entry["rule_id"],
            "title": entry["title"],
            "tier": tier,
            "outcome": "RUN_ERROR",
            "reason": f"generation worker did not return within {llm_timeout}s - killed (stale connection or genuinely slow response)",
            "generated": None,
            "gate_report": None,
            "failed_conditions": [],
            "benign_event_available": bool(benign_events),
        }
    except RuntimeError as e:
        return {
            "rule_path": entry["rule_path"],
            "rule_id": entry["rule_id"],
            "title": entry["title"],
            "tier": tier,
            "outcome": "RUN_ERROR",
            "reason": str(e),
            "generated": None,
            "gate_report": None,
            "failed_conditions": [],
            "benign_event_available": bool(benign_events),
        }

    verdict = repair_outcome.classify_repair(rule_path, generated, template_event, benign_events, rsigma_bin=rsigma_bin)
    result = verdict.to_dict()
    result["rule_path"] = entry["rule_path"]
    result["rule_id"] = entry["rule_id"]
    result["title"] = entry["title"]
    result["benign_event_available"] = bool(benign_events)
    return result


def summarize(results: list[dict]) -> dict:
    outcome_counts: Counter = Counter(r["outcome"] for r in results)
    by_tier: dict[str, Counter] = {}
    for r in results:
        by_tier.setdefault(r["tier"], Counter())[r["outcome"]] += 1
    total = len(results)
    logic_repairs = outcome_counts.get("LOGIC_REPAIR", 0)
    fully_exercised_false = sum(1 for r in results if r.get("gate_report") and r["gate_report"].get("fully_exercised") is False)
    failed_condition_counts: Counter = Counter(cond for r in results for cond in r.get("failed_conditions", []))
    return {
        "total": total,
        "acceptance_rate": (logic_repairs / total) if total else None,
        "outcome_counts": dict(outcome_counts),
        "by_tier": {t: dict(c) for t, c in by_tier.items()},
        "fully_exercised_false_count": fully_exercised_false,
        "rejections_by_failed_condition": dict(failed_condition_counts),
    }


def _write_progress(out_path: Path, manifest_path: Path, model: str, base_url: str, results: list[dict]) -> None:
    """Written after EVERY rule, not just at the end - so a kill/interrupt
    at any point (this project's background runs were killed mid-batch
    more than once - see docs/stage3-phase3-status.md) loses at most the
    one rule in flight, never the rules already completed."""
    summary = summarize(results)
    out = {"manifest": str(manifest_path), "model": model, "base_url": base_url, "summary": summary, "results": results}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "phase3_sample_manifest.json")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent / "data" / "phase3_run_results.json")
    parser.add_argument("--model", default=None)
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--rsigma-bin", type=Path, default=None)
    parser.add_argument("--limit", type=int, default=None, help="only run the first N rules (debugging)")
    parser.add_argument("--sleep", type=float, default=2.0, help="seconds between LLM calls (free-tier rate-limit courtesy)")
    parser.add_argument("--llm-timeout", type=float, default=90.0, help="hard wall-clock seconds before killing a stuck generation subprocess")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="skip rules already present (by rule_path) in an existing --out file, and append to it instead of overwriting",
    )
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    sigma_repo = Path(manifest["sigma_repo"])
    rules = manifest["rules"]
    if args.limit:
        rules = rules[: args.limit]

    model = args.model or llm_client.DEFAULT_MODEL
    base_url = args.base_url or llm_client.DEFAULT_BASE_URL

    results: list[dict] = []
    already_done: set[str] = set()
    if args.resume and args.out.exists():
        prior = json.loads(args.out.read_text(encoding="utf-8"))
        results = prior.get("results", [])
        already_done = {r["rule_path"] for r in results}
        print(f"Resuming: {len(already_done)} rule(s) already completed in {args.out}, skipping them.")

    todo = [e for e in rules if e["rule_path"] not in already_done]
    print(f"Model: {model}   Endpoint: {base_url}   Rules: {len(rules)} total, {len(todo)} to run\n")

    for i, entry in enumerate(todo):
        print(f"[{i + 1}/{len(todo)}] {entry['tier']:9s} {entry['rule_path']} ...", end=" ", flush=True)
        result = run_one(sigma_repo, entry, model=args.model, base_url=args.base_url, rsigma_bin=args.rsigma_bin, llm_timeout=args.llm_timeout)
        print(result["outcome"])
        results.append(result)
        _write_progress(args.out, args.manifest, model, base_url, results)  # incremental - survives a kill
        if i < len(todo) - 1:
            time.sleep(args.sleep)

    summary = summarize(results)
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2, default=str))
    print(f"\nWrote full results to {args.out}")


if __name__ == "__main__":
    main()
