#!/usr/bin/env python
"""Stage 3 Phase 3: subprocess worker for ONE generate_repair() call.

Run in its own short-lived process, invoked by run_phase3_acceptance.py via
`subprocess.run(..., timeout=N)`. This exists because Python's own
socket-level read timeout was found, empirically, NOT to reliably fire on
this project's development machine: a stale/half-closed TCP connection to
Groq's API (observed via `netstat` sitting in CLOSE_WAIT) left the parent
process blocked well past its stated `timeout=` tuple, in some cases for
10+ minutes - see docs/stage3-phase3-status.md for the full investigation.
`subprocess.run`'s OS-level timeout kills the whole child process
regardless of which syscall it's blocked in, which is a hard guarantee no
in-process timeout parameter can offer on every platform - it trades a
slightly heavier per-call cost (one interpreter startup) for actually
bounding worst-case wall-clock time. This is the fix that made the Phase 3
batch run reliably completable on this machine.

Prints exactly one JSON object to stdout: `{"ok": true, "generated": {...}}`
on success, or `{"ok": false, "error_type": ..., "error": ...}` if
generation raised - the caller must never crash on a subprocess call, only
translate a bad outcome into RUN_ERROR for that one rule and keep going.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mechanic import llm_client, repair_generator  # noqa: E402


def main() -> None:
    rule_path = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    base_url = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "-" else None
    try:
        generated = repair_generator.generate_repair(rule_path, model=model, base_url=base_url)
        print(json.dumps({"ok": True, "generated": generated.to_dict()}))
    except Exception as e:  # noqa: BLE001 - this process must always emit parseable JSON, never a bare traceback
        print(json.dumps({"ok": False, "error_type": type(e).__name__, "error": str(e)}))


if __name__ == "__main__":
    main()
