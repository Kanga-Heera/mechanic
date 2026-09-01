"""Local web GUI (`mechanic gui`) - a VIEW over the CORE engine only.

This package imports ONLY core modules (mechanic.priority, mechanic.churn,
mechanic.loader, ...) - never anything from the Stage 3 repair experiment
tree (verify/gate/evasion/llm_client/repair_generator/repair_outcome/
synthetic_benign). It computes nothing itself: every number the frontend
displays comes straight out of `priority.TriageReport.to_dict()`, the same
JSON `mechanic triage --json` produces. See docs/core-vs-experiment.md and
docs/gui-notes.md.

`mechanic/cli.py` only imports this package lazily, inside the `gui`
command's body - so fastapi/uvicorn (declared under the optional `gui`
extra, not core's base dependencies) are never required just to run
scan/staleness/triage/explain.
"""
