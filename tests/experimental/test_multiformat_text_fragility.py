"""Elastic/Splunk text-path atom extraction + classification - quarantined,
not part of the CORE (see docs/multiformat-experimental.md and
docs/core-vs-experiment.md). Kept and run in isolation so the experimental
code doesn't bit-rot, never exercised by mechanic.cli."""

from mechanic.experimental.multiformat import text_fragility as tf


def _atoms(*triples):
    return [tf.TextAtom(field, value, negated) for field, value, negated in triples]


def test_rarity_independent_signal_promotes_ttp():
    """`Detect Rare Executables`-shaped: a count threshold with NO tool-tier
    atom anywhere - rarity IS the substantive signal here."""
    atoms = _atoms(("Processes.dest", "host1", False))
    raw = "| tstats count from datamodel=Endpoint.Processes by Processes.process_name | where count < 10"
    result = tf.classify_text_rule(atoms, True, raw_text=raw)
    assert result.tier == "TTP"
    assert "RARITY" in result.structural_findings


def test_rarity_wrapping_tool_selector_stays_tool():
    """`Excessive Usage Of Cacls App`-shaped: the count threshold wraps an
    otherwise ordinary Tool-tier selector (icacls.exe) - must stay Tool, not
    get promoted to TTP by the rarity wrapper alone."""
    atoms = _atoms(("Processes.process_name", "icacls.exe", False))
    raw = "| tstats count from datamodel=Endpoint.Processes where Processes.process_name=icacls.exe | where count >=10"
    result = tf.classify_text_rule(atoms, True, raw_text=raw)
    assert result.tier == "Tool"
    assert "RARITY" not in result.structural_findings


def test_eventid_sole_criterion_kept_substantive():
    atoms = _atoms(("auditd.data.syscall", "init_module", False))
    result = tf.classify_text_rule(atoms, True)
    assert result.tier != "IOC"


def test_eventid_excluded_alongside_other_logic():
    atoms = _atoms(("event.code", "4688", False), ("process.command_line", "mimikatz.exe", False))
    result = tf.classify_text_rule(atoms, True)
    # event.code contributes nothing (excluded as selector); mimikatz.exe drives the tier
    assert result.tier == "Tool"


def test_short_tool_name_suppressed_in_text_path():
    atoms = _atoms(("Processes.process", "run this at noon", False))
    result = tf.classify_text_rule(atoms, True)
    assert result.tier != "Tool"


def test_pre_resolution_macro_name_supplies_cloud_context():
    """The CIM finding: `event.action`-equivalent field has no visible
    platform marker in the RESOLVED text (CIM abstracts it away), but the
    macro reference NAME (`okta_..._filter`) still carries it, pre-resolution."""
    atoms = _atoms(("All_Changes.action", "created", False), ("All_Changes.command", "system.api_token.create", False))
    pre_resolution = "| tstats count FROM datamodel=Change WHERE All_Changes.action=created | `okta_new_api_token_created_filter`"
    result_without = tf.classify_text_rule(atoms, True)
    result_with = tf.classify_text_rule(atoms, True, pre_resolution_text=pre_resolution)
    assert result_without.tier != "TTP"  # no context marker visible without it
    # "action" is in CLOUD_AUDIT_ACTION_FIELD_SUFFIXES; with context it should protect
    assert result_with.tier == "TTP"


def test_kubernetes_verb_field_protected_with_context():
    atoms = _atoms(("verb", "create", False), ("requestObject.spec.type", "NodePort", False))
    result = tf.classify_text_rule(atoms, True, pre_resolution_text="`kube_audit` verb=create")
    assert result.tier == "TTP"


def test_short_tool_name_kept_with_extension_in_text_path():
    atoms = _atoms(("Processes.process_name", "at.exe", False))
    result = tf.classify_text_rule(atoms, True)
    assert result.tier == "Tool"
