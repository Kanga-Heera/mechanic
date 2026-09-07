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


# ---------------------------------------------------------------------------
# Script-content field durability inversion (found via hand-test of a real
# ps_script rule) - RESULTS.md "Bug fix: script-content field durability
# inversion". Positive fixtures: several different script-content rules that
# must now tier Artifact/low, not Tool. Negative fixtures: binary-identity
# rules (including the load-bearing canonical FIELD_MISMATCH case above)
# that must NOT regress - proving this is a field-context fix, not a
# blanket demotion of every tool-vocabulary match everywhere.
# ---------------------------------------------------------------------------

_PS_SCRIPT_LOGSOURCE = {"category": "ps_script", "product": "windows"}


def test_script_content_field_demotes_cmdlet_shaped_match():
    """The hand-tested bug: ScriptBlockText|contains: 'Invoke-WebRequest'
    used to score Tool via the unconditional _CMDLET_RE pattern match. It
    is attacker-authored script source text - `iwr` (a built-in alias)
    defeats the match without switching tools - so it must not earn Tool
    tier."""
    rule = _rule(
        {"selection": {"ScriptBlockText|contains": "Invoke-WebRequest"}, "condition": "selection"},
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "Tool"
    atom = result.atoms[0]
    assert atom.reason == "attacker_authored_script_content_field"


def test_script_content_field_demotes_exe_shaped_match():
    """Same mechanism via the _EXE_RE pattern (a `foo.exe`-shaped string)
    instead of _CMDLET_RE - a download cradle referencing certutil.exe
    inside a script block is still just script text the attacker can
    reword (`cert`+`util.exe`, an environment variable, ...)."""
    rule = _rule(
        {"selection": {"ScriptBlockText|contains": "certutil.exe -urlcache"}, "condition": "selection"},
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "Tool"


def test_script_content_field_multi_atom_rule_from_the_hand_test():
    """The exact rule shape that surfaced this bug: several tool-vocabulary
    hits OR-linked in one ScriptBlockText|contains list. Proves the fix
    generalizes across atoms within one rule, not just a single-value
    fixture."""
    rule = _rule(
        {
            "selection": {
                "ScriptBlockText|contains": [
                    "Invoke-WebRequest",
                    "Net.WebClient",
                    "DownloadString",
                    "DownloadFile",
                ]
            },
            "condition": "selection",
        },
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"


def test_script_content_field_ordinary_literal_keeps_default_reason():
    """An atom in ScriptBlockText that was NEVER tool-vocabulary-shaped
    (doesn't match the catalog or either pattern) must still get the
    ordinary unrecognized-literal reason, not the script-content-specific
    one - that reason is specifically for atoms that WOULD have scored
    Tool, not a blanket relabel of every ScriptBlockText atom. Per the
    field-semantics fix's Part 2 (the GENERIC/unknown-value honest floor),
    this also now carries medium, not high, semantic_confidence - mechanic
    doesn't recognize this specific value's meaning and must not claim it
    does."""
    rule = _rule(
        {"selection": {"ScriptBlockText|contains": "totally ordinary sentence"}, "condition": "selection"},
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"
    assert result.atoms[0].reason == "unrecognized_literal_no_known_signal"
    assert result.atoms[0].semantic_confidence == "medium"


def test_script_content_field_raw_hash_still_scores_ioc():
    """A raw hash/IP embedded in script text is unaffected by this fix -
    IOC is already the lowest tier, and is_raw_ioc is checked before the
    script-content gate."""
    rule = _rule(
        {
            "selection": {"ScriptBlockText|contains": "d41d8cd98f00b204e9800998ecf8427e"},
            "condition": "selection",
        },
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "IOC"


def test_script_content_field_does_not_suppress_protected_literal():
    """Out of scope for this fix, verified rather than assumed: a
    protected-literal match (an OS/protocol-defined string) inside a
    script-content field is unaffected - protected_literals.is_protected is
    checked before the script-content gate in classify_atom, unchanged."""
    rule = _rule(
        {
            "selection": {"ScriptBlockText|contains": "CurrentVersion\\Run"},
            "condition": "selection",
        },
        logsource=_PS_SCRIPT_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"


def test_binary_identity_field_tool_match_unaffected_by_script_content_fix():
    """Negative fixture: the SAME cmdlet-shaped string, in a genuine
    process-identity field, must still score Tool - the fix gates on field
    identity, it does not lower the tool-vocabulary signal globally."""
    rule = _rule({"selection": {"Image|endswith": "\\Invoke-Something.exe"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_commandline_field_is_a_disclosed_gap_not_touched_by_this_fix():
    """CommandLine was explicitly considered and left out (see
    field_semantics.py's `_ATTACKER_AUTHORED_TEXT_FIELDS` comment) - this
    rule keeps its PRE-FIX behavior, proving the fix's scope is exactly
    ScriptBlockText today, not silently broader."""
    rule = _rule({"selection": {"CommandLine|contains": "Invoke-WebRequest"}, "condition": "selection"})
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"


def test_canonical_renamed_binary_rule_still_classifies_ttp_after_script_content_fix():
    """Re-assert the load-bearing canonical case (see
    test_canonical_renamed_binary_rule_classifies_ttp above) explicitly in
    this section - the structural FIELD_MISMATCH promotion happens before
    atom-level classification even runs, so it cannot be touched by this
    fix, but it is re-verified here as a direct regression check for this
    change specifically, not just inherited from an unrelated test."""
    path = SIGMA_REPO / "rules/windows/process_creation/proc_creation_win_renamed_binary_highly_relevant.yml"
    rules, failures = loader.load_file(path)
    assert failures == []
    tree = ast_repr.build_ast(rules[0].rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"
    assert "FIELD_MISMATCH" in result.structural_findings


# ---------------------------------------------------------------------------
# Field-semantics registry (mechanic.field_semantics) - one mechanism
# replacing the ad-hoc ScriptBlockText special case AND fixing the
# GrantedAccess access-mask case (RESULTS.md-style bug: same root cause,
# both directions - ScriptBlockText wrongly durable, GrantedAccess wrongly
# cosmetic). Fixtures below are keyed by FIELD ROLE, not by memorized
# value, per the fix's own brief.
# ---------------------------------------------------------------------------

_PROCESS_ACCESS_LOGSOURCE = {"category": "process_access", "product": "windows"}


def test_functional_constraint_granted_access_scores_ttp_durable():
    """The hand-tested bug: GrantedAccess='0x1010' used to score Artifact
    (an ordinary hex string matching no known signal) - wrongly COSMETIC.
    0x1010 is PROCESS_VM_READ|PROCESS_QUERY_(LIMITED_)INFORMATION, the
    exact rights LSASS credential dumping requires - changing the bit
    pattern forfeits the access, so it must score TTP (durable), not
    Artifact."""
    rule = _rule(
        {"selection": {"GrantedAccess": "0x1010"}, "condition": "selection"},
        logsource=_PROCESS_ACCESS_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"
    assert result.atoms[0].reason == "functional_constraint_field"
    assert result.atoms[0].semantic_confidence == "high"


def test_functional_constraint_any_value_is_durable_not_just_the_canonical_ones():
    """FIELD-level, not a value wordlist: an access-mask value OTHER than
    the canonical 0x1010/0x1410 examples must still score TTP - the
    durability comes from the FIELD (what it represents), not from
    matching one specific memorized hex string."""
    rule = _rule(
        {"selection": {"GrantedAccess": "0x143a"}, "condition": "selection"},
        logsource=_PROCESS_ACCESS_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"


def test_functional_constraint_access_mask_field_variant():
    """The Windows-Security-auditing sibling field (Event ID 4656/4663) -
    same access-control-bitmask mechanism, different telemetry source."""
    rule = _rule(
        {"selection": {"AccessMask": "0x0040"}, "condition": "selection"},
        logsource={"category": "registry_access", "product": "windows"},
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"


def test_functional_constraint_field_not_guessed_for_integrity_level():
    """Negative fixture: IntegrityLevel is a DIFFERENT mechanism (an
    OS-assigned privilege level, not an access-rights bitmask) - explicitly
    excluded from FUNCTIONAL_CONSTRAINT, must NOT score TTP just because it
    superficially resembles GrantedAccess (a Windows security field with a
    short enumerated-looking value)."""
    rule = _rule(
        {"selection": {"IntegrityLevel": "Medium"}, "condition": "selection"},
        logsource=_PROCESS_ACCESS_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier != "TTP"


def test_lsass_access_rule_min_lands_on_real_weakest_atom_not_granted_access():
    """The full hand-tested regression: TargetImage=lsass.exe (Tool, via
    the pre-existing unconditional _EXE_RE pattern - unaffected by this
    fix) AND-linked with GrantedAccess (now TTP, functional constraint).
    Before this fix, GrantedAccess scored Artifact and wrongly dragged the
    whole rule down to Artifact (the weakest-possible reading of a rule
    that is actually durable on both its real atoms). After the fix, MIN
    correctly lands on Tool (TargetImage), the genuine weakest link -
    GrantedAccess is no longer the accidental floor."""
    rule = _rule(
        {
            "selection": {
                "TargetImage|endswith": "\\lsass.exe",
                "GrantedAccess": ["0x1410", "0x1010", "0x410"],
            },
            "condition": "selection",
        },
        logsource=_PROCESS_ACCESS_LOGSOURCE,
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"
    granted_access_atoms = [a for a in result.atoms if a.field == "GrantedAccess"]
    assert granted_access_atoms and all(a.tier == "TTP" for a in granted_access_atoms)
    target_image_atoms = [a for a in result.atoms if a.field == "TargetImage"]
    assert target_image_atoms and target_image_atoms[0].tier == "Tool"


def test_renamed_rundll32_field_mismatch_still_classifies_ttp():
    """Regression (must not move): a renamed-rundll32 FIELD_MISMATCH shape
    (OriginalFileName positive, Image under a NOT filter, opposite
    polarity, same basename) - the structural promotion runs before any
    atom-level field-role logic and must be completely unaffected by it."""
    rule = _rule(
        {
            "selection": {"OriginalFileName": "RUNDLL32.EXE"},
            "filter": {"Image|endswith": "\\rundll32.exe"},
            "condition": "selection and not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "TTP"
    assert "FIELD_MISMATCH" in result.structural_findings


def test_non_system_rundll32_scores_tool_on_rundll32_alone():
    """Regression (must not move): a plain rundll32.exe match with negated
    ParentImage exclusions - the negated filter leaves are excluded from
    the AND/OR combination entirely (unaffected by this fix), so the tier
    is driven by the Image atom alone."""
    rule = _rule(
        {
            "selection": {"Image|endswith": "\\rundll32.exe"},
            "filter": {"ParentImage|endswith": ["\\explorer.exe", "\\svchost.exe"]},
            "condition": "selection and not filter",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Tool"
    assert result.structural_findings == []


def test_temp_path_and_payload_exe_both_present_as_atoms():
    """Rule 2's shape: an unrecognized path literal AND-linked with a
    `*.exe`-shaped filename (scores Tool via the pre-existing unconditional
    _EXE_RE pattern, unrelated to this fix). MIN correctly lands on the
    path (Artifact) - the completeness of the EXPLANATION citing both is
    tested in test_priority.py, this just pins the underlying atom tiers
    the explanation depends on."""
    rule = _rule(
        {
            "selection": {
                "TargetFilename|contains": "\\Temp\\",
                "Image|endswith": "payload.exe",
            },
            "condition": "selection",
        }
    )
    tree = ast_repr.build_ast(rule)
    result = fragility.classify_rule(tree)
    assert result.tier == "Artifact"
    path_atoms = [a for a in result.atoms if a.field == "TargetFilename"]
    image_atoms = [a for a in result.atoms if a.field == "Image"]
    assert path_atoms and path_atoms[0].tier == "Artifact"
    assert path_atoms[0].semantic_confidence == "medium"
    assert image_atoms and image_atoms[0].tier == "Tool"
