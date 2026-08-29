"""Stage 3 Phase 3, Part 0: model-agnostic LLM client - config-only tests.

No network calls here (those belong to the one-time smoke test, run
manually with a real key - see docs/stage3-phase3-status.md). These tests
cover exactly the REFUSE-LOUD contract and the "never commit a key"
guarantee, both required by the task spec regardless of whether a key is
available in this environment.
"""

from pathlib import Path

import pytest

from mechanic import llm_client


def test_env_dot_env_is_gitignored():
    gitignore = (Path(__file__).parent.parent / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore.splitlines(), ".env must be gitignored - see mechanic/llm_client.py"


def test_no_env_example_leaks_a_real_looking_key():
    example = (Path(__file__).parent.parent / ".env.example").read_text(encoding="utf-8")
    assert "gsk_" not in example, ".env.example must never contain a real (or real-shaped) API key"


def test_resolve_api_key_refuses_loud_when_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    # Also redirect the .env convenience-loader away from the real repo
    # root, so a developer's own local .env (if any) can't make this test
    # environment-dependent.
    monkeypatch.setattr(llm_client, "_REPO_ROOT", tmp_path)
    with pytest.raises(llm_client.LLMConfigError, match="GROQ_API_KEY is not set"):
        llm_client.resolve_api_key()


def test_resolve_api_key_never_fabricates_a_default(monkeypatch, tmp_path):
    # Redirect the .env convenience-loader too - this test must fail loud
    # even on a machine that has a real .env at the repo root (e.g. after
    # the Part 0 smoke test below has been run locally).
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_REPO_ROOT", tmp_path)
    with pytest.raises(llm_client.LLMConfigError):
        llm_client.chat_completion([{"role": "user", "content": "hi"}])


def test_resolve_api_key_reads_the_env_var(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-value-not-real")
    assert llm_client.resolve_api_key() == "test-value-not-real"


def test_resolve_api_key_not_required_returns_none_when_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setattr(llm_client, "_REPO_ROOT", tmp_path)
    assert llm_client.resolve_api_key(required=False) is None


def test_dotenv_convenience_loader_populates_environ_without_overriding(monkeypatch, tmp_path):
    import os

    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("SOME_OTHER_VAR", raising=False)
    (tmp_path / ".env").write_text('GROQ_API_KEY=from-dotenv\nSOME_OTHER_VAR="quoted"\n# a comment\n', encoding="utf-8")
    try:
        llm_client._load_dotenv_if_present(tmp_path / ".env")
        assert os.environ["GROQ_API_KEY"] == "from-dotenv"
        assert os.environ["SOME_OTHER_VAR"] == "quoted"
    finally:
        # _load_dotenv_if_present writes directly to os.environ, which
        # monkeypatch does not track/restore on its own (only its own
        # setenv/delenv calls are) - clean up explicitly so this test can't
        # leak state into later tests in the same process.
        os.environ.pop("GROQ_API_KEY", None)
        os.environ.pop("SOME_OTHER_VAR", None)


def test_resolve_base_url_and_model_defaults():
    assert llm_client.resolve_base_url() == llm_client.DEFAULT_BASE_URL
    assert llm_client.resolve_model() == llm_client.DEFAULT_MODEL


def test_resolve_base_url_and_model_env_override(monkeypatch):
    monkeypatch.setenv("MECHANIC_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("MECHANIC_LLM_MODEL", "llama3.3:70b")
    assert llm_client.resolve_base_url() == "http://localhost:11434/v1"
    assert llm_client.resolve_model() == "llama3.3:70b"
