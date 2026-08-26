from pathlib import Path

from sigma.exceptions import SigmaRuleLocation
from sigma.rule import SigmaRule

from mechanic import ast_repr, fragility, loader, protected_literals

SIGMA_REPO = Path("D:/sigma-research/sigma")


def _rule(detection: dict, logsource: dict | None = None) -> SigmaRule:
    d = {
        "title": "t",
        "id": "11111111-1111-1111-1111-111111111111",
        "status": "test",
        "logsource": logsource or {"category": "process_creation", "product": "windows"},
        "detection": detection,
        "level": "medium",
    }
    return SigmaRule.from_dict(d, source=SigmaRuleLocation(Path("x.yml")))


def test_canonical_renamed_binary_rule_classifies_ttp():
    """The must-pass test: if this fails, the structural thesis is
    unsupported and everything downstream (Part 2c's re-validation,
    Part 3's priority ranking) is moot."""
    path = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml"
    rules, failures = loader.load_file(path)
    assert failures == []
    tree = ast_repr.build_ast(rules[0].rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"
    assert "FIELD_MISMATCH" in result.structural_findings


def test_and_combination_takes_weaker_link():
    """STP's own documented rule: AND -> MIN, not MAX. Found during the STP
    external-validation pass (Kendall's tau -0.009 -> +0.300 on the same 70
    rules once this was fixed) - a Tool-tier atom AND-linked with a plain
    Artifact-tier literal must score Artifact overall, because the adversary
    only needs to evade the WEAKER of the two AND-linked observables."""
    rule = _rule(
        {"selection": {"Image|endswith": "\\certutil.exe", "TargetFilename|endswith": "\\notes.txt"}, "condition": "selection"}
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"


def test_or_combination_takes_stronger_link():
    """The OR side of the same rule: MAX, since the adversary must defeat
    BOTH branches of an OR to evade the rule entirely."""
    rule = _rule(
        {
            "sel_a": {"TargetFilename|endswith": "\\notes.txt"},
            "sel_b": {"Image|endswith": "\\certutil.exe"},
            "condition": "sel_a or sel_b",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_flat_max_ablation_mode_reproduces_old_behavior():
    """combine_mode="flat_max" exists ONLY for the before/after comparison -
    confirms the ablation hook actually reproduces the original (buggy)
    max-over-everything behavior on the same AND-linked rule."""
    rule = _rule(
        {"selection": {"Image|endswith": "\\certutil.exe", "TargetFilename|endswith": "\\notes.txt"}, "condition": "selection"}
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree, combine_mode="flat_max")
    assert result.tier == "Tool"  # the old, incorrect behavior, preserved only for comparison


def test_selector_all_of_is_and_like():
    rule = _rule(
        {
            "sel_tool": {"Image|endswith": "\\certutil.exe"},
            "sel_artifact": {"TargetFilename|endswith": "\\notes.txt"},
            "condition": "all of sel_*",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"


def test_selector_one_of_is_or_like():
    rule = _rule(
        {
            "sel_tool": {"Image|endswith": "\\certutil.exe"},
            "sel_artifact": {"TargetFilename|endswith": "\\notes.txt"},
            "condition": "1 of sel_*",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_data_source_selector_excluded_from_and_combination():
    """AWS EC2 Disable EBS Encryption-shaped: `eventSource: ec2.amazonaws.com`
    AND-linked with `eventName: DisableEbsEncryptionByDefault` (protected,
    TTP-tier). eventSource is a data-source identifier, not an independently
    evadable observable - must not drag the AND down to Artifact. Found as a
    real regression the very first time the AND/OR fix ran against the LLM
    development set (19/30 SigmaHQ rules flipped, almost all cloud-audit) -
    confirmed to be this exact mechanism before accepting any result."""
    rule = _rule(
        {
            "selection": {"eventSource": "ec2.amazonaws.com", "eventName": "DisableEbsEncryptionByDefault"},
            "condition": "selection",
        },
        logsource={"product": "aws", "service": "cloudtrail"},
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"


def test_negated_atom_does_not_inflate_tier():
    """A rule matching a plain literal path, with a KNOWN TOOL NAME
    (higher-ranked than Artifact) ONLY inside a NOT-exclusion, must score on
    the positive literal (Artifact), not the excluded tool name (which would
    incorrectly promote it to Tool) - v1's negation-blindness bug. If this
    regresses, an exclusion filter for a legitimate tool would silently
    promote every rule containing it, regardless of whether it's matched."""
    rule = _rule(
        {
            "selection": {"TargetFilename|endswith": "\\notes.txt"},
            "filter": {"Image|endswith": "\\certutil.exe"},
            "condition": "selection and not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"


def test_negated_hash_alone_yields_insufficient_information_not_a_guess():
    """A rule whose ONLY positive content is inside a NOT (all-negated,
    ABSENCE didn't classify it as a real absence pattern because... this
    exercises the fallback: no positive leaves survive negation-filtering
    and no structural detector fired -> insufficient_information, not a
    forced guess."""
    rule = _rule(
        {
            "filter": {"Hashes|contains": "44d88612fea8a8f36de82e1278abb02f"},
            "condition": "not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    # This shape IS all-negated-with-no-positive, so ABSENCE's own rule
    # (non-filter selection, all negated) doesn't apply (this is a `filter`
    # kind selection, deliberately excluded from ABSENCE by name convention) -
    # confirm the atom-scoring path correctly finds no positive atoms.
    assert result.tier is None
    assert result.insufficient_information is True


def test_unscoreable_rule_lands_in_unscoreable_bucket_not_ioc():
    from sigma.correlations import SigmaCorrelationRule

    # A standard rule with literally no leaves is contrived (real unscoreable
    # rules are Elastic ML rules, out of this AST's scope entirely) - build
    # the closest in-scope analog: an empty AND with no children is not
    # constructible via normal Sigma YAML, so instead assert the detector
    # contract directly against a hand-built minimal tree.
    tree = {
        "schema_version": 1,
        "type": "standard",
        "id": "x",
        "title": "t",
        "logsource": {"product": None, "category": None, "service": None},
        "tags": [],
        "attack_tags": [],
        "conditions": [],
    }
    result = fragility.classify_rule(tree)
    assert result.unscoreable is True
    assert result.tier is None
    assert result.tier != "IOC"


def test_protected_literal_cloud_context_gating_present():
    field_value_pairs = [("data_stream.dataset", "aws.cloudtrail"), ("event.action", "DeleteImportedKeyMaterial")]
    cloud_context = protected_literals.rule_is_cloud_audit_context(field_value_pairs)
    assert cloud_context is True
    protected, reason = protected_literals.is_protected("event.action", "DeleteImportedKeyMaterial", cloud_context)
    assert protected is True
    assert reason == "cloud_audit_action_name"


def test_protected_literal_cloud_context_gating_absent():
    """The exact same field/value, with NO cloud-audit marker anywhere else
    in the rule, must NOT be protected - `action`/`event.action` is
    semantically overloaded (sometimes a protected platform-API name,
    sometimes generic OS-verb boilerplate like 'creation'/'modification')."""
    field_value_pairs = [("event.action", "creation"), ("file.path", "/tmp/x")]
    cloud_context = protected_literals.rule_is_cloud_audit_context(field_value_pairs)
    assert cloud_context is False
    protected, reason = protected_literals.is_protected("event.action", "creation", cloud_context)
    assert protected is False


def test_dotted_ecs_path_matches_last_segment():
    """The exact bug that caused v1's Elastic TTP share to jump 3.8% ->
    24.8% on a single fix: `event.action` must match against the bare
    `action` protection category via last-dotted-segment, not exact string
    equality against the full dotted path."""
    protected, _ = protected_literals.is_protected(
        "event.action", "DeleteImportedKeyMaterial", cloud_context=True
    )
    assert protected is True


def test_windows_security_subsystem_config_rdp_auth_policy():
    protected, reason = protected_literals.is_protected(
        "registry.path",
        "HKLM\\SYSTEM\\ControlSet001\\Control\\Terminal Server\\WinStations\\RDP-Tcp\\UserAuthentication",
        cloud_context=False,
    )
    assert protected is True
    assert reason == "windows_security_subsystem_config"


def test_windows_security_subsystem_config_rdp_connection_history():
    """splunk#24: same category, different reason (connection-history log,
    not an auth-policy value) - both live under the same Microsoft-defined
    `Terminal Server`-rooted registry area."""
    protected, reason = protected_literals.is_protected(
        "registry_path", "*\\Microsoft\\Terminal Server Client\\Servers\\*", cloud_context=False
    )
    assert protected is True
    assert reason == "windows_security_subsystem_config"


def test_windows_security_subsystem_config_ie_zonemap():
    protected, reason = protected_literals.is_protected(
        "TargetObject",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\ProtocolDefaults",
        cloud_context=False,
    )
    assert protected is True
    assert reason == "windows_security_subsystem_config"


def test_windows_security_subsystem_config_does_not_cover_sysrq():
    """/proc/sysrq-trigger is a disclosed gap, not folded into this category -
    it's a kernel-magic immediate-action interface, a different mechanism
    family from Windows security-subsystem configuration/state."""
    protected, _ = protected_literals.is_protected("CommandLine", "echo b > /proc/sysrq-trigger", cloud_context=False)
    assert protected is False


def test_eventid_excluded_when_data_source_selector_alongside_other_logic():
    rule = _rule(
        {
            "selection": {"EventID": 4688, "CommandLine|contains": "mimikatz"},
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    atom_fields = {a.field: a.reason for a in result.atoms}
    assert atom_fields["EventID"] == "eventid_or_syscall_data_source_selector_excluded"


def test_eventid_not_excluded_when_sole_criterion():
    rule = _rule({"selection": {"EventID": 4688}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    atom_fields = {a.field: a.reason for a in result.atoms}
    assert atom_fields["EventID"] != "eventid_or_syscall_data_source_selector_excluded"


def test_syscall_sole_criterion_scores_as_substantive():
    """auditd.data.syscall in (init_module, finit_module) IS the entire
    rule - must not be excluded as a boilerplate selector."""
    rule = _rule(
        {"selection": {"auditd.data.syscall": ["init_module", "finit_module"]}, "condition": "selection"},
        logsource={"product": "linux", "category": "kernel_module"},
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    reasons = {a.reason for a in result.atoms}
    assert "eventid_or_syscall_data_source_selector_excluded" not in reasons


def test_known_tool_name_scores_tool_tier():
    """`launchctl` is exactly the kind of macOS binary v1's Windows-only
    LOLBIN_NAMES list missed - covered now via LOOBins (see refdata.py /
    data/SOURCES.md). Note `PlistBuddy` specifically remains an honest,
    disclosed gap (in none of the four sources) - not asserted here."""
    rule = _rule({"selection": {"Image|endswith": "\\launchctl"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_field_context_suppresses_tool_match_on_unrelated_field():
    """splunk#18-shaped: `security` is a genuine LOOBins macOS tool name, but
    a Windows EventLog Channel field value has nothing to do with a process."""
    rule = _rule({"selection": {"Channel": "security"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "Tool"


def test_field_context_keeps_tool_match_on_process_field():
    """The same catalog name, in a genuine process-context field, must still
    score Tool - field-context gates the lookup, it doesn't disable it."""
    rule = _rule({"selection": {"Image|endswith": "\\security"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_field_context_suppresses_url_field():
    """splunk#10-shaped: `url` is a genuine LOLBAS entry, but a `location`
    field holding a URL string is not a process reference."""
    rule = _rule({"selection": {"location": "url"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "Tool"


def test_field_context_covers_auditd_execve_a0():
    """Regression check: field-context gating initially broke this real
    SigmaHQ rule (lnx_auditd_unzip_hidden_zip_files_steganography.yml) -
    Linux auditd's EXECVE record convention names argv[0] `a0`, a different
    naming convention for "this is the process" than Windows/ECS/Splunk.

    Isolated to just `a0` (no AND-linked `type: EXECVE` companion field) so
    this tests field-context recognition specifically, not the separate
    AND=MIN combination behavior - a0 AND-linked with an unrelated boilerplate
    literal correctly drags the RULE's overall tier down to the weaker link
    (see test_and_combination_takes_weaker_link), which is a different,
    intentional behavior, not a regression of this one."""
    rule = _rule(
        {"commands": {"a0": "unzip"}, "condition": "commands"},
        logsource={"product": "linux", "service": "auditd"},
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_field_context_covers_ecs_dotted_process_fields():
    rule = _rule({"selection": {"process.name": "launchctl"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_short_tool_name_suppressed_without_executable_context():
    """`at` is a genuine GTFOBins entry, but a bare field value "at" with no
    path separator or extension is exactly the false-positive shape found in
    Part 2c's re-validation (an ordinary word incidentally matching a short
    tool-vocabulary entry in a long enumeration) - must NOT score Tool."""
    rule = _rule({"selection": {"CommandLine|contains": "at"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "Tool"


def test_short_tool_name_kept_with_path_separator():
    rule = _rule({"selection": {"Image|endswith": "\\at"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_short_tool_name_kept_with_extension():
    rule = _rule({"selection": {"Image": "at.exe"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_raw_hash_scores_ioc_tier():
    rule = _rule(
        {"selection": {"Hashes|contains": "d41d8cd98f00b204e9800998ecf8427e"}, "condition": "selection"}
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "IOC"
