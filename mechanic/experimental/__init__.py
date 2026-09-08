"""EXPERIMENT tree - never imported by the CORE (mechanic.cli and everything
it imports). See docs/core-vs-experiment.md for the boundary this enforces
and why, and tests/test_core_isolation.py for the test that fails if a core
module ever imports from here.

One quarantined experiment currently lives under this package:

  - mechanic.experimental.multiformat -- Elastic (EQL/KQL/ES|QL) and Splunk
    (SPL) text-path fragility classification: regex-approximated atom
    extraction over free text, since there is no real parser for either
    query language anywhere in this codebase (see
    docs/multiformat-experimental.md). Quarantined because it does not meet
    the CORE's external-validation bar - Sigma's real AST is what the
    STP-validated structural detectors and AND/OR combination logic
    actually run against.
"""
