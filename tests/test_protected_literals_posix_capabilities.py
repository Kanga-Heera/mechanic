"""Independent validation sample for the `posix_capabilities` protected-
literal category (mechanic/protected_literals.py).

Per the project's own validation discipline (see docs/core-vs-experiment.md
and the thesis reference doc's "atom-classification gap" entry): a newly
discovered classifier gap must never be validated only by re-running it
against the same data that originally exposed it. This file is a FRESH
fixture, built specifically to test posix_capabilities, containing cases
that never appeared anywhere else in this repo's test data - not a rerun of
whatever rule first surfaced the gap.

Covers, per the task's own checklist:
  - known POSIX capability literals (positive)
  - ordinary strings (negative)
  - unrelated uppercase constants (negative)
  - field names that resemble capability names (negative - the token must be
    in the VALUE text, not merely echoed by a similarly-named field)
  - values that should NOT be classified as capabilities (negative -
    fabricated CAP_-prefixed strings, and the K8s/Docker bare-name spelling,
    both disclosed as out of scope in the module docstring)
"""

import pytest

from mechanic import protected_literals


# ---------------------------------------------------------------------------
# Positive cases: real, capabilities(7)-defined names.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "CAP_NET_ADMIN",
        "CAP_SYS_ADMIN",
        "CAP_DAC_OVERRIDE",
        "cap_sys_ptrace",  # lowercase - setcap/capsh's own convention
        "Cap_Net_Raw",  # mixed case
        "CAP_SETUID",
        "CAP_CHOWN",
        "CAP_AUDIT_WRITE",
        "CAP_BPF",  # a modern (5.8+) capability, confirming the set isn't a
        # truncated/stale copy of an older capabilities(7) revision
    ],
)
def test_known_capability_literal_is_protected(value):
    protected, reason = protected_literals.is_protected("CommandLine", value, cloud_context=False)
    assert protected is True
    assert reason == "posix_capabilities"


def test_capability_inside_a_comma_separated_list_is_protected():
    """setcap's own CLI syntax and audit logs commonly carry more than one
    capability in a single field value - the category must not require the
    value to be the capability name in isolation."""
    protected, reason = protected_literals.is_protected(
        "CommandLine", "setcap cap_net_raw,cap_net_admin+eip /usr/bin/ping", cloud_context=False
    )
    assert protected is True
    assert reason == "posix_capabilities"


def test_capability_field_name_is_irrelevant_to_the_match():
    """The category is about the VALUE being a kernel-defined capability
    name, not about any particular field carrying it - unlike the
    field-name-driven ALWAYS_PROTECTED_FIELD_NAMES category."""
    protected, reason = protected_literals.is_protected(
        "some.arbitrary.audit.field", "CAP_SYS_MODULE", cloud_context=False
    )
    assert protected is True
    assert reason == "posix_capabilities"


# ---------------------------------------------------------------------------
# Negative cases.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "hello world",
        "C:\\Windows\\System32\\cmd.exe",
        "the quick brown fox",
        "capacity",  # shares the "cap" prefix but is an ordinary English word
        "captain",
    ],
)
def test_ordinary_strings_are_not_protected(value):
    protected, _ = protected_literals.is_protected("Description", value, cloud_context=False)
    assert protected is False


@pytest.mark.parametrize(
    "value",
    [
        "MAX_RETRY_COUNT",
        "ERROR_ACCESS_DENIED",
        "TCP_NODELAY",
        "PAGE_EXECUTE_READWRITE",  # a real Windows memory-protection constant -
        # deliberately chosen to be uppercase, underscore-separated, and
        # security-relevant-sounding, to stress-test that resemblance alone
        # doesn't trigger this category
    ],
)
def test_unrelated_uppercase_constants_are_not_protected(value):
    protected, reason = protected_literals.is_protected("Value", value, cloud_context=False)
    assert protected is False


@pytest.mark.parametrize(
    "field_name",
    [
        "cap_net_admin",  # the field's NAME resembles a capability, but its
        "cap_sys_admin",  # VALUE (checked below) does not - the category
        "CapabilitiesRequested",  # must key off the value, not a name that merely
    ],  # resembles one
)
def test_capability_like_field_name_with_unrelated_value_is_not_protected(field_name):
    protected, _ = protected_literals.is_protected(field_name, "true", cloud_context=False)
    assert protected is False


@pytest.mark.parametrize(
    "value",
    [
        "CAP_FOO_BAR",  # fabricated - looks real, is not in capabilities(7)
        "CAP_MADE_UP_PRIVILEGE",
        "CAP_1337",
    ],
)
def test_fabricated_cap_prefixed_strings_are_not_protected(value):
    """The whole point of enumerating the closed set instead of matching a
    bare `CAP_` prefix: a plausible-looking but non-existent capability name
    must NOT be treated as kernel-protected."""
    protected, reason = protected_literals.is_protected("CommandLine", value, cloud_context=False)
    assert protected is False


@pytest.mark.parametrize(
    "value",
    [
        "NET_ADMIN",  # Kubernetes/Docker securityContext.capabilities bare
        "SYS_ADMIN",  # spelling (no CAP_ prefix) - disclosed scope gap in the
        "SYS_PTRACE",  # module docstring, not silently claimed as covered
    ],
)
def test_k8s_bare_capability_spelling_is_a_disclosed_gap_not_protected(value):
    protected, _ = protected_literals.is_protected(
        "securityContext.capabilities.add", value, cloud_context=False
    )
    assert protected is False
