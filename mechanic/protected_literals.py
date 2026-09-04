"""Protected-literal detection (Stage 2, Part 2b), derived from a PRINCIPLE,
not from examples.

PRINCIPLE (stated once, applied everywhere below): a literal is protected
when the attacker cannot rename/replace it without losing the underlying
capability, because an OS, protocol, network-RPC-interface, or directory
schema defines that literal - not because it happened to appear in a
hand-verification example.

v1 built its protected-literal list FROM examples found during hand
verification, then was shown to still be missing others
(`/etc/crontab`, `/etc/systemd/system/*`, `/etc/ld.so.preload`,
`servicePrincipalName`, `azure.identity_protection`, ...) - see RESULTS.md.
Each category below is instead derived from a named, citable, external
definition of the mechanism itself, so completeness is a property of that
external definition, not of what anyone happened to hand-verify:

  windows_autorun_registry   - Windows autostart/hijack registry locations
                               (Run/RunOnce keys, Winlogon Userinit/Shell,
                               IFEO Debugger value, AppInit_DLLs, LSA
                               package lists, Safe Boot service keys) -
                               Microsoft-documented autorun mechanisms.
  windows_rpc_named_pipes    - well-known DCE/RPC named-pipe endpoints
                               ([MS-RPCE] / SMB named-pipe conventions).
                               Cross-checked directly against SigmaHQ's own
                               `win_security_lm_namedpipe.yml` false-positive
                               list (`sigma/rules/windows/builtin/security/`),
                               which independently enumerates this same
                               protocol-defined set for a different purpose
                               (FP suppression) - convergent evidence this is
                               the real "well-known pipe" set, not a
                               hand-pick for this classifier specifically.
  windows_well_known_sids    - Microsoft's published "Well-known security
                               identifiers" (SYSTEM, Administrators, ...).
  ad_schema_attributes       - Active Directory schema attribute names
                               (servicePrincipalName, userAccountControl,
                               adminCount, ...) - the AD/LDAP schema defines
                               these; an attacker cannot rename an LDAP
                               attribute and keep its effect (e.g.
                               Kerberoasting fundamentally requires *a*
                               principal with a servicePrincipalName set -
                               there is no alternate attribute that does the
                               same thing).
  linux_persistence_paths    - paths defined by a specific OS subsystem's own
                               manual/spec (cron(5)/crontab(5), systemd.unit(5),
                               ld.so(8), sudoers(5)) - not "sensitive files" in
                               general, but locations where the *existence of
                               a file there* is what triggers OS behavior.
  macos_persistence_paths    - the launchd(8)/launchd.plist(5)-defined agent/
                               daemon directories - same rationale as above,
                               macOS's mechanism instead of systemd/cron.
  windows_security_subsystem_config - registry areas Windows dedicates to a
                               specific security-relevant subsystem's own
                               configuration AND connection/session state -
                               added after Part 2c's hand-label re-validation
                               found FOUR separate disagreements (NLA
                               disabled, RDP registry deletion, IE ZoneMap
                               downgrade x2) that were being treated as four
                               unrelated gaps when they share one root cause:
                               `windows_autorun_registry` is deliberately
                               scoped to autorun/persistence mechanisms, and
                               none of these four are autorun - they're a
                               different OS-defined mechanism entirely.
                               Two subsystems, same principle: (a) Terminal
                               Services/RDP - Microsoft roots BOTH its
                               authentication-policy values (e.g.
                               `WinStations/RDP-Tcp/UserAuthentication`) AND
                               its connection-history log (`Terminal Server
                               Client/Servers`) under the same
                               `Terminal Server`-prefixed registry area; an
                               attacker cannot downgrade RDP auth OR erase
                               its connection history anywhere else, because
                               Windows hardcodes both to this location. (b)
                               Internet Explorer/WinINET security-zone
                               assignment (`Internet Settings/ZoneMap`) -
                               Microsoft-documented
                               (learn.microsoft.com "IE security zones
                               registry entries"); the zone a protocol is
                               assigned to is read from exactly this key,
                               nowhere else.
                               NOTE what this does NOT cover:
                               `/proc/sysrq-trigger` (a Linux kernel-magic
                               immediate-action interface, not a Windows
                               security-subsystem configuration/state area -
                               a different mechanism family, left as a
                               disclosed gap rather than folded in here just
                               because it shares the "OS-defined path"
                               shape - see RESULTS.md).
  posix_capabilities         - the fixed, kernel-defined Linux capability
                               names (capabilities(7)) - CAP_SYS_ADMIN,
                               CAP_NET_ADMIN, CAP_DAC_OVERRIDE, etc. An
                               attacker cannot rename a capability and keep
                               its kernel-enforced effect (granting
                               CAP_SYS_ADMIN under any other name is not
                               possible - the kernel checks the numeric
                               capability bit, and CAP_* is the one
                               spelling the kernel/libcap headers define for
                               it), the same rationale as `ad_schema_attributes`
                               applied to the kernel's own schema instead of
                               AD's. Enumerated as the FULL closed set from
                               capabilities(7) (39 names as of Linux 6.x),
                               not a `CAP_\\w+` prefix match - a prefix match
                               would also protect fabricated, non-existent
                               "CAP_"-prefixed strings that carry no real
                               kernel meaning, which is exactly the kind of
                               example-shaped overreach this module's
                               principle (derive from the external
                               definition, not from what looks similar) is
                               meant to avoid. Fixed as a known, disclosed
                               gap (RESULTS.md / thesis reference doc, "atom-
                               classification gap") found as a side effect of
                               the AND/OR fix and deliberately left unpatched
                               pending a fresh, held-out validation sample -
                               that sample is the `posix_capabilities`-tagged
                               fixture in `tests/test_protected_literals_posix_capabilities.py`,
                               built fresh rather than replayed against
                               whatever originally exposed the gap.
                               DISCLOSED SCOPE LIMIT: matching requires the
                               `cap_`/`CAP_` prefix (the setcap/getcap/capsh/
                               auditd textual convention). Kubernetes and
                               Docker security-context capability lists
                               conventionally OMIT that prefix (`NET_ADMIN`,
                               `SYS_ADMIN`), which is indistinguishable from
                               an ordinary uppercase constant without
                               additional schema context (a `securityContext.
                               capabilities.add` field path) this module does
                               not currently examine - left unmatched rather
                               than risking exactly the false-positive class
                               (unrelated uppercase literals) the fresh
                               validation sample was built to check for.

Cloud-provider audit action names (eventName/operationName/...) are NOT
included as unconditionally protected - see `CLOUD_AUDIT_*` below, kept
separate because that category is context-gated (protected only alongside a
recognized cloud-audit data source marker in the same rule), unlike every
category above which is unconditional.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Always-protected FIELD NAMES: the field itself carries protocol-defined
# meaning regardless of its value, so no value-pattern match is needed.
# ---------------------------------------------------------------------------

ALWAYS_PROTECTED_FIELD_NAMES = {
    "ticketencryptiontype",  # Kerberos encryption-type enum (RFC 3961/4120) - the
                              # field name IS the protected signal; an attacker
                              # cannot make a downgraded ticket "look like" AES.
    "logontype",  # Windows logon-type enum (2=Interactive, 3=Network, ...) -
                  # the OS assigns this at logon time; it cannot be spoofed by
                  # renaming anything client-side.
}


@dataclass(frozen=True)
class ProtectedValueCategory:
    name: str
    pattern: re.Pattern
    rationale: str
    # False (default) preserves every existing category's behavior: the
    # pattern is checked against the combined "field value" haystack, which
    # is correct for path-fragment patterns (a registry path, a named pipe)
    # where the protected token is unambiguous wherever it appears. True
    # restricts the match to the VALUE alone - for a category like
    # `posix_capabilities` where the protected thing is a specific literal
    # value, not the concept of a field being named after one (a field
    # literally named `cap_net_admin` used as an unrelated boolean flag must
    # not be protected just because its name echoes a real capability).
    value_only: bool = False


PROTECTED_VALUE_CATEGORIES: list[ProtectedValueCategory] = [
    ProtectedValueCategory(
        "windows_autorun_registry",
        re.compile(
            r"currentversion\\+run(once|services(once)?)?\b"
            r"|winlogon\\+(userinit|shell|notify)\b"
            r"|image file execution options\\+.*\\debugger"
            r"|windows nt\\+currentversion\\+windows\\+appinit_dlls"
            r"|control\\+lsa\\+(authentication|notification|security) packages"
            r"|control\\+safeboot\\+(minimal|network)\b",
            re.I,
        ),
        "Microsoft-documented autostart/hijack registry locations - Run/RunOnce/"
        "RunServices keys, Winlogon Userinit/Shell/Notify, IFEO Debugger value, "
        "AppInit_DLLs, LSA package lists, Safe Boot service keys.",
    ),
    ProtectedValueCategory(
        "windows_rpc_named_pipes",
        re.compile(
            r"\\pipe\\+(svcctl|atsvc|lsarpc|samr|netlogon|spoolss|eventlog|winreg|"
            r"browser|wkssvc|srvsvc|ntsvcs|protected_storage|netdfs|lsass|"
            r"lsm_api_service|hydralspipe|termsrv_api_service|msftewds)\b"
            r"|^(svcctl|atsvc|lsarpc|samr|netlogon|spoolss|eventlog|winreg|browser|"
            r"wkssvc|srvsvc|ntsvcs|protected_storage|netdfs|lsass|lsm_api_service|"
            r"hydralspipe|termsrv_api_service|msftewds)$",
            re.I,
        ),
        "Well-known DCE/RPC named-pipe endpoints ([MS-RPCE] convention) - "
        "independently cross-checked against SigmaHQ's own "
        "win_security_lm_namedpipe.yml false-positive list.",
    ),
    ProtectedValueCategory(
        "windows_well_known_sids",
        re.compile(r"\bs-1-(1-0|5-(11|18|19|20|32-54[45]))\b", re.I),
        "Microsoft's published well-known SIDs (Everyone, Authenticated Users, "
        "SYSTEM, LOCAL SERVICE, NETWORK SERVICE, Administrators, Users).",
    ),
    ProtectedValueCategory(
        "ad_schema_attributes",
        re.compile(
            r"^(serviceprincipalname|useraccountcontrol|primarygroupid|admincount|"
            r"msds-allowedtodelegateto|msds-allowedtoactonbehalfofotheridentity|"
            r"ntsecuritydescriptor|unicodepwd|sidhistory|dnshostname)$",
            re.I,
        ),
        "Active Directory schema attribute names - defined by the AD/LDAP "
        "schema itself; there is no alternate attribute name that carries "
        "the same semantics (e.g. Kerberoasting requires *a* principal with "
        "servicePrincipalName set - renaming the attribute isn't possible).",
    ),
    ProtectedValueCategory(
        "linux_persistence_paths",
        re.compile(
            r"/etc/crontab\b"
            r"|/etc/cron\.(d|daily|hourly|weekly|monthly|allow|deny)\b"
            r"|/var/spool/(cron/crontabs|at|atjobs|anacron)/"
            r"|/etc/systemd/(system|user)/"
            r"|/(usr/lib|lib|usr/local/lib)/systemd/(system|user)/"
            r"|/etc/ld\.so\.preload\b"
            r"|/etc/ld\.so\.conf(\.d/)?\b"
            r"|/etc/rc\.local\b"
            r"|/etc/init\.d/"
            r"|/etc/sudoers(\.d/)?\b",
            re.I,
        ),
        "Locations defined by a specific Linux subsystem's own spec "
        "(crontab(5), systemd.unit(5), ld.so(8), sudoers(5)) - the OS/service "
        "manager acts on anything placed there, not on this being a "
        "conventionally 'sensitive' path.",
    ),
    ProtectedValueCategory(
        "macos_persistence_paths",
        re.compile(
            r"/library/launchagents/"
            r"|/library/launchdaemons/"
            r"|/system/library/launchdaemons/"
            r"|/library/startupitems/",
            re.I,
        ),
        "launchd(8)/launchd.plist(5)-defined agent/daemon directories - "
        "macOS's equivalent mechanism to systemd unit directories/cron.",
    ),
    ProtectedValueCategory(
        "windows_security_subsystem_config",
        re.compile(
            r"terminal server"  # matches BOTH "...Terminal Server\WinStations\..."
                                 # (RDP auth policy) and "...Terminal Server
                                 # Client/Servers..." (RDP connection history) -
                                 # same Microsoft-defined registry area either way.
            r"|internet settings\\+.*zonemap"
            r"|\bzonemap\b",
            re.I,
        ),
        "Registry areas Windows dedicates to a security-relevant subsystem's "
        "own configuration and connection/session state - Terminal Services/"
        "RDP (both its auth-policy values and its connection-history log, "
        "both rooted under the same Microsoft-defined 'Terminal Server' "
        "registry area) and Internet Explorer/WinINET's security-zone "
        "assignment (ZoneMap) - distinct from windows_autorun_registry, "
        "which is deliberately scoped to autorun/persistence mechanisms only.",
    ),
    ProtectedValueCategory(
        "posix_capabilities",
        re.compile(
            r"\bcap_(chown|dac_override|dac_read_search|fowner|fsetid|kill|setgid|"
            r"setuid|setpcap|linux_immutable|net_bind_service|net_broadcast|"
            r"net_admin|net_raw|ipc_lock|ipc_owner|sys_module|sys_rawio|sys_chroot|"
            r"sys_ptrace|sys_pacct|sys_admin|sys_boot|sys_nice|sys_resource|"
            r"sys_time|sys_tty_config|mknod|lease|audit_write|audit_control|"
            r"setfcap|mac_override|mac_admin|syslog|wake_alarm|block_suspend|"
            r"audit_read|perfmon|bpf|checkpoint_restore)\b",
            re.I,
        ),
        "The fixed, kernel-defined Linux capability names (capabilities(7)) - "
        "an attacker cannot rename a capability and keep its kernel-enforced "
        "effect, so the full closed set is treated as unconditionally "
        "protected rather than a `CAP_` prefix guess.",
        value_only=True,
    ),
]

# ---------------------------------------------------------------------------
# Cloud-provider audit action names - CONTEXT-GATED, not unconditional.
# ---------------------------------------------------------------------------

CLOUD_AUDIT_ACTION_FIELD_SUFFIXES = {
    "eventname",
    "event_name",
    "operationname",
    "operation_name",
    "methodname",
    "method_name",
    "eventtype",
    "event_type",
    "operation",
    "action",
    "verb",  # Kubernetes' own audit-log schema field name for the action
             # performed (create/update/delete/...) - documented in the
             # Kubernetes API audit policy spec, the same tier of
             # platform-schema justification as the other entries here.
             # Added after Part 2c's re-validation (splunk `Kubernetes Node
             # Port Creation`) - see RESULTS.md.
}

CLOUD_AUDIT_CONTEXT_RE = re.compile(
    r"cloudtrail"
    r"|azure\.\w+"  # any Azure ECS dataset (auditlogs, identity_protection,
                     # signinlogs, activitylogs, ...) - all under Azure's own
                     # audit/log integration namespace, not generic
    r"|gcp\.audit"
    r"|kubernetes\.audit|kube_audit"
    r"|\bokta"  # no trailing \b: Splunk macro-name convention compounds with
                # underscores (`okta_new_api_token_created_filter`), and `_`
                # is a \w character - a trailing \b would never match there.
                # See RESULTS.md's CIM finding.
    r"|office365|o365|m365|unifiedauditlog"
    r"|onelogin"
    r"|amazonaws\.com"
    r"|\.azure\.com",
    re.I,
)


def rule_is_cloud_audit_context(field_value_pairs: list[tuple[str, str]]) -> bool:
    """Scans the WHOLE rule (every field/value pair seen, not just the one
    atom under consideration) for a recognizable cloud-audit data-source
    marker, so an overloaded field name (`action`, `event.action`, ...) is
    only treated as a protected platform-API name when the rest of the rule
    actually establishes a cloud-audit context - see module docstring."""
    for field, value in field_value_pairs:
        haystack = f"{field or ''} {value if isinstance(value, str) else ''}"
        if CLOUD_AUDIT_CONTEXT_RE.search(haystack):
            return True
    return False


def _last_segment(field: str) -> str:
    return field.rsplit(".", 1)[-1].lower() if field else ""


def is_protected(field: str, value: object, cloud_context: bool) -> tuple[bool, str]:
    """Returns (is_protected, category_or_reason). Checked in this order:
    always-protected field name -> unconditional value-pattern categories ->
    context-gated cloud-audit action name."""
    field_l = _last_segment(field)
    if field_l in ALWAYS_PROTECTED_FIELD_NAMES:
        return True, f"always_protected_field:{field_l}"

    value_str = value if isinstance(value, str) else ""
    haystack = f"{field or ''} {value_str}"
    for cat in PROTECTED_VALUE_CATEGORIES:
        # Checked against the combined "field value" haystack (for path-
        # fragment patterns like registry paths, which are unambiguous
        # regardless of anchoring) AND against value_str alone (required for
        # any `^...$`-anchored bare-name alternative - e.g. a rule's
        # `RelativeTargetName: svcctl` carries the pipe name as a clean,
        # unprefixed value; `^svcctl$` can never match "RelativeTargetName
        # svcctl" but matches "svcctl" alone). Found via exactly this bug in
        # Part 2c's hand-label re-validation (sigma `win_security_svcctl_
        # remote_service.yml`, elastic `credential_access_spn_attribute_
        # modified.toml`) - both were silently unreachable before this fix.
        if cat.value_only:
            if value_str and cat.pattern.search(value_str):
                return True, cat.name
        elif cat.pattern.search(haystack) or (value_str and cat.pattern.search(value_str)):
            return True, cat.name

    if cloud_context and field_l in CLOUD_AUDIT_ACTION_FIELD_SUFFIXES:
        return True, "cloud_audit_action_name"

    return False, ""
