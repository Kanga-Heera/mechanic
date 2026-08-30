"""Stage 3 Phase 3: 429 retry behavior - no real network call, requests.post
is monkeypatched. Split from test_llm_client.py only for focus; same
no-network-needed constraint applies."""

from types import SimpleNamespace

from mechanic import llm_client


class _FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body
        self.text = str(body)
        self.headers = {}

    def json(self):
        return self._body


def test_chat_completion_retries_on_429_then_succeeds(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(1)
        if len(calls) == 1:
            return _FakeResponse(429, {"error": {"message": "Rate limit reached. Please try again in 0.01s."}})
        return _FakeResponse(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    resp = llm_client.chat_completion([{"role": "user", "content": "hi"}], max_retries=3)
    assert resp.text == "ok"
    assert len(calls) == 2


def test_chat_completion_raises_after_exhausting_retries(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    def fake_post(url, headers=None, json=None, timeout=None):
        return _FakeResponse(429, {"error": {"message": "Rate limit reached. Please try again in 0.01s."}})

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    try:
        llm_client.chat_completion([{"role": "user", "content": "hi"}], max_retries=2)
        assert False, "expected LLMRequestError"
    except llm_client.LLMRequestError as e:
        assert "429" in str(e)


def test_parse_retry_after_seconds_from_body():
    resp = _FakeResponse(429, {"error": {"message": "Please try again in 6.29s."}})
    assert llm_client._parse_retry_after_seconds(resp, fallback=99) == 6.29


def test_chat_completion_retries_on_connection_timeout_then_succeeds(monkeypatch):
    """A stale/hung connection (observed in practice as TCP CLOSE_WAIT
    outliving the read timeout) raises a requests exception - must be
    retried with a fresh connection, not immediately fail the whole call."""
    import requests as requests_module

    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(1)
        if len(calls) == 1:
            raise requests_module.exceptions.ReadTimeout("simulated stale connection")
        return _FakeResponse(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    resp = llm_client.chat_completion([{"role": "user", "content": "hi"}], max_retries=3)
    assert resp.text == "ok"
    assert len(calls) == 2


def test_chat_completion_raises_after_exhausting_retries_on_timeout(monkeypatch):
    import requests as requests_module

    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    def fake_post(url, headers=None, json=None, timeout=None):
        raise requests_module.exceptions.ReadTimeout("simulated stale connection")

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    try:
        llm_client.chat_completion([{"role": "user", "content": "hi"}], max_retries=2)
        assert False, "expected LLMRequestError"
    except llm_client.LLMRequestError as e:
        assert "3 attempt" in str(e)


def test_parse_retry_after_seconds_falls_back_when_unparseable():
    resp = _FakeResponse(429, {"error": {"message": "no timing info here"}})
    assert llm_client._parse_retry_after_seconds(resp, fallback=3.5) == 3.5
