"""Hardening Part 0: the CORE (mechanic.cli and everything it imports) must
have zero dependency on the EXPERIMENT (Stage 3 repair-verification
pipeline) - see docs/core-vs-experiment.md.

Every test here runs in a FRESH subprocess, deliberately - the pytest
process running this whole suite has already imported test_llm_client.py,
test_verify.py, etc. by the time this file's tests run, so checking
`sys.modules` in-process would be meaningless (everything would already be
"imported"). A subprocess with a clean `sys.modules` is the only way to
actually prove `import mechanic.cli` alone doesn't pull in the experiment.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

EXPERIMENT_MODULES = [
    "mechanic.verify",
    "mechanic.gate",
    "mechanic.evasion",
    "mechanic.synthetic_benign",
    "mechanic.llm_client",
    "mechanic.repair_generator",
    "mechanic.repair_outcome",
    "mechanic.cli_repair",
    # Elastic/Splunk multiformat fragility - quarantined per
    # docs/multiformat-experimental.md, same as the repair pipeline above.
    "mechanic.experimental.multiformat.text_fragility",
    "mechanic.experimental.multiformat.splunk_macros",
    "mechanic.experimental.multiformat.multiformat_fragility",
    "mechanic.experimental.multiformat.triage",
]

CORE_MODULES = [
    "mechanic.loader",
    "mechanic.categories",
    "mechanic.discovery",
    "mechanic.churn",
    "mechanic.semantic_diff",
    "mechanic.ast_repr",
    "mechanic.fragility",
    "mechanic.structural_detectors",
    "mechanic.protected_literals",
    "mechanic.refdata",
    "mechanic.priority",
    "mechanic.legacy_v1",
    "mechanic.cli",
]


def _stripped_env() -> dict:
    """Environment with every experiment-only signal removed: no API key,
    no pinned RSigma binary override. `requests` may or may not be
    installed in this dev venv (it's still a transitive dep of other
    tooling) - the point of these tests is the import graph and the
    command's own behavior never *reaching* for any of it, not that the
    package is physically absent."""
    env = dict(os.environ)
    env.pop("GROQ_API_KEY", None)
    env.pop("MECHANIC_RSIGMA_BIN", None)
    return env


def _run_py(code: str, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        env=env if env is not None else _stripped_env(),
        cwd=str(cwd) if cwd else None,
    )


def test_importing_core_cli_does_not_import_experiment_modules():
    """Importing mechanic.cli alone must not pull in verify/gate/evasion/
    llm_client/repair_generator/repair_outcome/synthetic_benign/cli_repair -
    the reactor cannot depend on the thing bolted to its side."""
    proc = _run_py(
        """
        import sys
        import mechanic.cli  # noqa: F401
        loaded = sorted(m for m in sys.modules if m.startswith("mechanic."))
        print("\\n".join(loaded))
        """
    )
    assert proc.returncode == 0, proc.stderr
    loaded = set(proc.stdout.splitlines())
    leaked = loaded & set(EXPERIMENT_MODULES)
    assert not leaked, f"mechanic.cli import leaked experiment modules: {leaked}"


@pytest.mark.parametrize("module", CORE_MODULES)
def test_each_core_module_source_has_no_experiment_import(module: str):
    """Same check, per core module, so a future edit that adds an import to
    e.g. fragility.py or priority.py is caught immediately rather than only
    when someone happens to run mechanic.cli."""
    rel = module.split(".", 1)[1] + ".py"
    src = Path(__file__).parent.parent.joinpath("mechanic", rel).read_text(encoding="utf-8")
    import_lines = [ln for ln in src.splitlines() if ln.strip().startswith(("import ", "from "))]
    for ln in import_lines:
        for exp_mod in EXPERIMENT_MODULES:
            leaf = exp_mod.split(".")[-1]
            assert leaf not in ln, f"{module} imports experiment module via: {ln!r}"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def core_only_repo(tmp_path: Path) -> Path:
    """A minimal real git repo with a couple of valid Sigma rules and one
    deliberately broken one, so scan/staleness/triage/explain all have
    something real to chew on end-to-end."""
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    _git(repo.parent, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "a@example.com")
    _git(repo, "config", "user.name", "Author A")

    (repo / "rules" / "good1.yml").write_text(
        "title: Suspicious Certutil Download\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: test\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    Image|endswith: '\\\\certutil.exe'\n"
        "    CommandLine|contains: '-urlcache'\n"
        "  condition: selection\n"
    )
    (repo / "rules" / "broken.yml").write_text("id: 12345\ntitle: [this is not valid\n")
    env = {**os.environ, "GIT_AUTHOR_DATE": "2023-01-01T00:00:00", "GIT_COMMITTER_DATE": "2023-01-01T00:00:00"}
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "add rules"], cwd=repo, check=True, capture_output=True, env=env)

    (repo / "rules" / "good2.yml").write_text(
        "title: Suspicious Rundll32 Network Call\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "status: test\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n"
        "  selection:\n"
        "    Image|endswith: '\\\\rundll32.exe'\n"
        "    CommandLine|contains: 'javascript:'\n"
        "  condition: selection\n"
    )
    env2 = {**os.environ, "GIT_AUTHOR_DATE": "2023-06-01T00:00:00", "GIT_COMMITTER_DATE": "2023-06-01T00:00:00"}
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", "add good2"], cwd=repo, check=True, capture_output=True, env=env2)
    return repo


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "{repo}/rules"],
        ["staleness", "{repo}"],
        ["triage", "{repo}"],
    ],
)
def test_core_commands_run_with_no_network_no_key_no_rsigma(core_only_repo: Path, argv: list[str]):
    """Every core command must complete against a real repo with GROQ_API_KEY
    unset, MECHANIC_RSIGMA_BIN unset, and requests/rsigma never touched -
    the behavioral proof that "zero dependency on the experiment" is true,
    not just true of the import graph."""
    args = [a.format(repo=str(core_only_repo)) for a in argv]
    proc = subprocess.run(
        [sys.executable, "-m", "mechanic.cli", *args, "--json"],
        capture_output=True,
        text=True,
        env=_stripped_env(),
    )
    assert proc.returncode in (0, 1), f"unexpected crash: {proc.stderr}"
    assert "GROQ_API_KEY" not in proc.stderr
    assert "rsigma" not in proc.stderr.lower()
    assert "Traceback" not in proc.stderr, proc.stderr


def test_core_explain_runs_with_no_network_no_key_no_rsigma(core_only_repo: Path):
    rule_path = core_only_repo / "rules" / "good1.yml"
    proc = subprocess.run(
        [sys.executable, "-m", "mechanic.cli", "explain", str(rule_path), "--json"],
        capture_output=True,
        text=True,
        env=_stripped_env(),
    )
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr


def test_mechanic_repair_cli_is_the_only_verify_importer():
    """mechanic-repair (mechanic/cli_repair.py) is allowed - indeed
    expected - to import mechanic.verify. This test exists so that fact is
    asserted explicitly rather than only proven by omission elsewhere."""
    src = Path(__file__).parent.parent.joinpath("mechanic", "cli_repair.py").read_text(encoding="utf-8")
    assert "from mechanic import verify" in src or "import mechanic.verify" in src
