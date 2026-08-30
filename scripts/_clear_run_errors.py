#!/usr/bin/env python
"""Helper for retry_until_complete.ps1: strip RUN_ERROR entries out of a
Phase 3 results file so run_phase3_acceptance.py's --resume will retry
those rules instead of treating a timeout as a permanent outcome."""
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    d = json.load(f)
before = len(d["results"])
d["results"] = [r for r in d["results"] if r["outcome"] != "RUN_ERROR"]
after = len(d["results"])
print(f"  cleared {before - after} RUN_ERROR entries, {after} real outcome(s) remain")
with open(path, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2, default=str)
