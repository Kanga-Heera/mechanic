"""Stage 3 Phase 3, Part 0: model-agnostic LLM client, Groq default.

A thin wrapper around the OpenAI chat-completions HTTP format (which Groq,
most local runtimes, and most paid providers all speak), so switching
providers is a base_url + model change, not a rewrite:

    Groq (default)  base_url="https://api.groq.com/openai/v1"
    local Ollama    base_url="http://localhost:11434/v1"
    paid provider   base_url=<their OpenAI-compatible endpoint>

Rationale for the Groq default, recorded here because it affects how any
acceptance-rate result using this client should be read: the target
machine for this project is an 8GB laptop, which cannot run a capable
(70B-class) model locally. Generation therefore uses a free-tier hosted
model while every verification step (the harness, the gate, the evasion
transformer) runs entirely locally and deterministically. This means an
acceptance-rate result measures the REPAIR-GENERATION FRAMEWORK, not what
a larger or differently-hosted model could do - a real limitation, stated
here once and repeated wherever a Phase 3 result is reported.

Model id: DEFAULT_MODEL below was looked up live against
console.groq.com/docs/models on 2026-08-29 (see docs/stage3-phase3-status.md
for the lookup trail) rather than assumed from training data - Groq rotates
model ids over time, and a hardcoded assumption would silently go stale.
llama-3.3-70b-versatile is Groq's current production 70B-class Llama model
(131,072-token context, ~280 tok/s) - the right capability tier for
rule-repair reasoning per the Phase 3 spec. If it is later deprecated,
update DEFAULT_MODEL (or pass model= / set MECHANIC_LLM_MODEL) after
re-checking that same page - never guess a replacement id.

REFUSE-LOUD CONTRACT (never fabricate a repair without a real model call):
`resolve_api_key()` raises `LLMConfigError` - not a fallback, not a
default, not a fabricated response - the instant the configured API-key
env var is unset. Every code path in this module that would otherwise
silently proceed without a key instead stops here. Callers (the Part 1
generator) must let this propagate rather than catching it and inventing
a repair.

KEY HANDLING: the key is read from `os.environ[api_key_env]`
(default `GROQ_API_KEY`) at CALL time, never hardcoded, never written to
any file by this module. `_load_dotenv_if_present()` is a convenience
ONLY: if a gitignored `.env` file exists at the repo root and the env var
isn't already set, it loads `KEY=VALUE` lines from that file into
`os.environ` - the file must be created by the user's own hand (this
module never writes one), and `tests/test_llm_client.py` asserts `.env` is
listed in `.gitignore` so this convenience path can never smuggle a key
into git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.3-70b-versatile"
API_KEY_ENV = "GROQ_API_KEY"

# Optional overrides so switching providers never requires editing this
# file: base_url and model are read from these env vars if set, before
# falling back to the Groq defaults above.
BASE_URL_ENV = "MECHANIC_LLM_BASE_URL"
MODEL_ENV = "MECHANIC_LLM_MODEL"

_REPO_ROOT = Path(__file__).resolve().parent.parent


class LLMConfigError(Exception):
    """Setup/configuration problem - no API key, no reachable endpoint
    configured. The client refuses to run rather than proceeding with a
    guessed or empty credential. Never raised for a model simply declining
    to answer, which is a normal LLMRequestError-free response."""


class LLMRequestError(Exception):
    """The HTTP call itself failed (network error, non-2xx status, or a
    response body that isn't valid chat-completions JSON) - distinguished
    from LLMConfigError so callers can tell "never even tried" (bad config)
    from "tried, and the endpoint/network failed" apart."""


@dataclass
class ChatResponse:
    text: str
    raw: dict
    model: str
    endpoint: str


def _load_dotenv_if_present(dotenv_path: Optional[Path] = None) -> None:
    """See module docstring's KEY HANDLING section. Skips (does not raise
    on) malformed lines and comments - this is a convenience loader, not a
    validating config parser."""
    path = dotenv_path or (_REPO_ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def resolve_api_key(api_key_env: str = API_KEY_ENV, *, required: bool = True) -> Optional[str]:
    """Read the API key from the environment. Raises LLMConfigError (never
    fabricates, never falls back to a hardcoded value) if `required` and
    the env var is unset after also checking a local .env for convenience.
    `required=False` is for providers that don't need a key at all (e.g. a
    local Ollama instance) - returns None in that case if genuinely unset."""
    _load_dotenv_if_present()
    key = os.environ.get(api_key_env)
    if key:
        return key
    if not required:
        return None
    raise LLMConfigError(
        f"${api_key_env} is not set. This generator refuses to run without a real API key - "
        f"it will never fabricate a repair. Export it in your shell before running:\n"
        f"  PowerShell:  $env:{api_key_env} = \"your-key-here\"\n"
        f"  persistent:  setx {api_key_env} \"your-key-here\"\n"
        f"  bash:        export {api_key_env}=your-key-here\n"
        f"Get a free-tier key at https://console.groq.com/keys if you don't have one."
    )


def resolve_base_url(base_url: Optional[str] = None) -> str:
    return base_url or os.environ.get(BASE_URL_ENV) or DEFAULT_BASE_URL


def resolve_model(model: Optional[str] = None) -> str:
    return model or os.environ.get(MODEL_ENV) or DEFAULT_MODEL


def chat_completion(
    messages: list[dict],
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key_env: str = API_KEY_ENV,
    require_api_key: bool = True,
    temperature: float = 0.2,
    max_tokens: int = 2000,
    timeout: int = 60,
) -> ChatResponse:
    """One OpenAI-compatible chat-completions call. Raises LLMConfigError
    before ever making a network request if the key is required and
    missing; raises LLMRequestError for any network/HTTP/parsing failure.
    Never returns a fabricated ChatResponse - a return value here always
    means a real HTTP round trip to `endpoint` succeeded and was parsed."""
    resolved_base_url = resolve_base_url(base_url)
    resolved_model = resolve_model(model)
    api_key = resolve_api_key(api_key_env, required=require_api_key)

    endpoint = resolved_base_url.rstrip("/") + "/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    payload = {
        "model": resolved_model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as e:
        raise LLMRequestError(f"request to {endpoint} failed: {e}") from e

    if resp.status_code != 200:
        raise LLMRequestError(f"{endpoint} returned HTTP {resp.status_code}: {resp.text[:2000]}")

    try:
        body = resp.json()
    except ValueError as e:
        raise LLMRequestError(f"{endpoint} returned a non-JSON body: {resp.text[:2000]}") from e

    try:
        text = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as e:
        raise LLMRequestError(f"{endpoint} response missing choices[0].message.content: {body}") from e

    return ChatResponse(text=text, raw=body, model=resolved_model, endpoint=endpoint)
