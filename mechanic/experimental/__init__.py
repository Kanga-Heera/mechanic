"""EXPERIMENT tree - never imported by the CORE (mechanic.cli and everything
it imports). See docs/core-vs-experiment.md for the boundary this enforces
and why, and tests/test_core_isolation.py for the test that fails if a core
module ever imports from here.

Two quarantined experiments currently live under this package:

  - mechanic.experimental.repair -- NOT here; Stage 3's repair-verification
    pipeline predates this package and stays quarantined the way it always
    has (mechanic/verify.py, gate.py, evasion.py, ... + mechanic/cli_repair.py
    as its own console script). Not moved here so as not to rewrite its git
    history for no functional reason.
  - mechanic.experimental.multiformat -- Elastic (EQL/KQL/ES|QL) and Splunk
    (SPL) text-path fragility classification: regex-approximated atom
    extraction over free text, since there is no real parser for either
    query language anywhere in this codebase (see
    docs/multiformat-experimental.md). Quarantined because it does not meet
    the CORE's external-validation bar - Sigma's real AST is what the
    STP-validated structural detectors and AND/OR combination logic
    actually run against.
"""
