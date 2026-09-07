"""Field-semantics registry tests (Stage 2, Part 2d) - tested BY ROLE, not
by memorized value, per the fix's own brief: a value wordlist would be an
unbounded trap, so what actually needs proving is that the bounded,
documented FIELD sets resolve to the right role, under the same
normalization (case-insensitive, underscore-insensitive, last-dotted-
segment) every other field-context check in this codebase already uses."""

from mechanic import field_semantics


def test_binary_identity_examples():
    for f in ["Image", "OriginalFileName", "ParentImage", "TargetImage", "CommandLine", "process.name"]:
        assert field_semantics.field_role(f) == field_semantics.BINARY_IDENTITY, f


def test_binary_identity_covers_auditd_execve_convention():
    """Linux auditd's EXECVE-record convention: a0 is argv[0], exe/comm are
    the executable path/short name - a different naming convention for the
    same "this is the process" concept (regression coverage for the fix
    fragility.py's own history documents finding once already)."""
    for f in ["a0", "exe", "comm"]:
        assert field_semantics.field_role(f) == field_semantics.BINARY_IDENTITY, f


def test_attacker_authored_text_scriptblocktext():
    assert field_semantics.field_role("ScriptBlockText") == field_semantics.ATTACKER_AUTHORED_TEXT


def test_functional_constraint_granted_access_and_access_mask():
    assert field_semantics.field_role("GrantedAccess") == field_semantics.FUNCTIONAL_CONSTRAINT
    assert field_semantics.field_role("AccessMask") == field_semantics.FUNCTIONAL_CONSTRAINT


def test_functional_constraint_normalization_case_and_underscore_insensitive():
    for f in ["grantedaccess", "GRANTED_ACCESS", "Granted_Access", "accessmask", "ACCESS_MASK"]:
        assert field_semantics.field_role(f) == field_semantics.FUNCTIONAL_CONSTRAINT, f


def test_functional_constraint_does_not_cover_integrity_or_elevation_fields():
    """Considered and deliberately excluded (see field_semantics.py's
    _FUNCTIONAL_CONSTRAINT_FIELDS comment): these are OS-assigned privilege
    LEVELS, a different mechanism from an access-rights bitmask - must stay
    GENERIC, not guessed into FUNCTIONAL_CONSTRAINT just because both are
    security-relevant Windows numeric-ish fields."""
    for f in ["IntegrityLevel", "TokenElevationType", "MandatoryLabel"]:
        assert field_semantics.field_role(f) == field_semantics.GENERIC, f


def test_data_source_selector_exact_and_last_segment():
    for f in ["EventID", "EventCode", "event.code", "syscall", "auditd.data.syscall"]:
        assert field_semantics.field_role(f) == field_semantics.DATA_SOURCE_SELECTOR, f
    for f in ["eventSource", "event.provider", "data_stream.dataset", "sourcetype"]:
        assert field_semantics.field_role(f) == field_semantics.DATA_SOURCE_SELECTOR, f


def test_generic_default_for_unknown_and_none_field():
    assert field_semantics.field_role("SomeCompletelyUnknownField") == field_semantics.GENERIC
    assert field_semantics.field_role(None) == field_semantics.GENERIC
    assert field_semantics.field_role("") == field_semantics.GENERIC


def test_roles_constant_lists_every_role_exactly_once():
    assert sorted(field_semantics.ROLES) == sorted(
        {
            field_semantics.BINARY_IDENTITY,
            field_semantics.ATTACKER_AUTHORED_TEXT,
            field_semantics.FUNCTIONAL_CONSTRAINT,
            field_semantics.DATA_SOURCE_SELECTOR,
            field_semantics.GENERIC,
        }
    )
    assert len(field_semantics.ROLES) == 5
