"""Elastic/Splunk triage - QUARANTINED, not part of the CORE product. See
docs/multiformat-experimental.md for what this is and why it's here instead
of `mechanic triage`, and docs/core-vs-experiment.md for how the boundary is
enforced.

This is a thin composition, not a reimplementation: `compute_multiformat_
triage` calls straight into `mechanic.priority.build_triage_report` (the
same staleness + semantic-diff + per-rule-assembly engine `mechanic triage`
itself runs) with this package's own `classify_elastic_file`/
`classify_splunk_file` in place of the core's Sigma-only `_sigma_fragility`.
Nothing about staleness or behavioral-diff computation is duplicated or
reimplemented here - those stay exactly as validated in the core, for any
format (see RESULTS.md Part 1). Only the fragility/tiering axis - the one
that needs a real parse tree to earn the core's validation bar - is
different, and that difference is exactly what's quarantined.

There is deliberately no CLI/console-script entry point for this module.
Call `compute_multiformat_triage` directly from Python (see the example
below), or drive it from a test/script under this same experimental tree.
A polished CLI surface is exactly the kind of "looks like a supported
product" affordance the quarantine exists to avoid presenting - see
`docs/multiformat-experimental.md` for the honest path back to a real CLI
command (a real KQL/EQL/SPL parser, at which point this stops being
text-path-approximated and can rejoin the core).

Example:
    >>> from pathlib import Path
    >>> from mechanic.experimental.multiformat.triage import compute_multiformat_triage
    >>> report = compute_multiformat_triage(Path("thirdparty/elastic-detection-rules"), "elastic_toml", subdir="rules")
    >>> report.to_dict()["summary"]
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Callable, Optional

from mechanic import churn
from mechanic.experimental.multiformat.multiformat_fragility import FRAGILITY_FN
from mechanic.priority import TriageReport, build_triage_report


class UnsupportedMultiformatError(ValueError):
    """Raised for any `fmt` this module doesn't have a fragility builder
    for - `"sigma"` included (that's `mechanic.priority.compute_triage`'s
    job, not this module's; routing a Sigma repo through here would silently
    skip the STP-validated AST path for no reason)."""

    def __init__(self, fmt: str):
        self.fmt = fmt
        super().__init__(
            f"fmt={fmt!r} is not a quarantined multiformat fragility builder "
            f"(known: {sorted(FRAGILITY_FN)}) - use mechanic.priority.compute_triage for 'sigma'."
        )


def compute_multiformat_triage(
    path: Path,
    fmt: str,
    mechanical_threshold: float = churn.DEFAULT_THRESHOLD,
    subdir: Optional[str] = None,
    as_of: Optional[date] = None,
    all_facts: Optional[list] = None,
    refresh: bool = False,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    mining_timeout: Optional[float] = None,
) -> TriageReport:
    """Elastic/Splunk equivalent of `mechanic.priority.compute_triage` -
    same staleness/semantic-diff engine, this package's own regex-
    approximated fragility classification. Every `FragilitySignal` produced
    here carries a non-None `caveat` and `and_or_corrected=False` (see
    `multiformat_fragility.py`) - `RuleSignals.narrative`/`.to_dict()`
    (core, unmodified) already render that distinction, so nothing here
    needs its own caveat-rendering logic.

    `fmt` must be `"elastic_toml"` or `"splunk_yaml"` - `UnsupportedMultiformatError`
    otherwise, including for `"sigma"` (see that error's docstring for why).
    """
    if fmt not in FRAGILITY_FN:
        raise UnsupportedMultiformatError(fmt)
    return build_triage_report(
        path,
        FRAGILITY_FN[fmt],
        fmt=fmt,
        mechanical_threshold=mechanical_threshold,
        subdir=subdir,
        as_of=as_of,
        all_facts=all_facts,
        refresh=refresh,
        progress_cb=progress_cb,
        mining_timeout=mining_timeout,
    )
