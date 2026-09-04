"""Elastic/Splunk multiformat fragility analysis - QUARANTINED, not part of
the CORE product. See docs/multiformat-experimental.md for what this is,
why it's here instead of in mechanic/, and the concrete path back to core
status (a real KQL parser via kibana-ql).

Modules:
  text_fragility.py       - regex-based atom extraction + tier classification
                             for Elastic EQL/KQL/ES|QL and Splunk SPL.
  splunk_macros.py        - Splunk CIM/macro resolution, needed before SPL
                             text can be tokenized at all.
  multiformat_fragility.py - the per-file FragilitySignal builders
                             (classify_elastic_file/classify_splunk_file)
                             that used to live in mechanic/priority.py.
  triage.py                - compute_multiformat_triage(): the same
                             staleness + semantic-diff + fragility assembly
                             `mechanic triage` runs, reused via
                             priority.build_triage_report (core, sigma-only
                             by default) with this package's own fragility
                             functions instead.

Nothing in mechanic/ (the CORE) imports anything from this package - see
tests/test_core_isolation.py. This package freely imports FROM mechanic/
(fragility.TIER_RANK/classify_atom, protected_literals, structural_detectors,
priority.FragilitySignal/build_triage_report, churn, semantic_diff, ...) -
that direction is fine and expected; only core-importing-experiment is
forbidden.
"""
