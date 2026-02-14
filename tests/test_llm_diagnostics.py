"""Tests for LLM offline diagnostics."""

from app.core.llm_config import LLMConfigManager, LLMProviderConfig


def _provider() -> LLMProviderConfig:
    return LLMProviderConfig(
        name="Test Provider",
        type="openai",
        base_url="http://localhost:8000/v1",
        api_key="test-key",
        model="test-model",
        max_tokens=128,
        temperature=0.0,
        context_window=4096,
    )


def test_provider_from_dict_parses_request_timeout_seconds():
    cfg = LLMProviderConfig.from_dict(
        {
            "name": "Timeout Provider",
            "type": "openai",
            "base_url": "http://localhost:8000/v1",
            "api_key": "test-key",
            "model": "test-model",
            "max_tokens": 128,
            "temperature": 0.0,
            "context_window": 4096,
            "request_timeout_seconds": "42.5",
        }
    )
    assert cfg.request_timeout_seconds == 42.5


def test_test_connection_reports_auth_diagnostics(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()

    monkeypatch.setattr(manager, "get_active_provider", lambda: provider)
    def _raise_auth_error(provider, timeout_seconds):
        raise Exception("401 Unauthorized: invalid api key")

    monkeypatch.setattr(manager, "_test_openai_provider_connectivity", _raise_auth_error)

    result = manager.test_connection()

    assert result["success"] is False
    assert result["diagnostics"]["code"] == "auth_failed"
    assert "authentication" in result["diagnostics"]["summary"].lower()


def test_test_connection_reports_connection_diagnostics(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()

    monkeypatch.setattr(manager, "get_active_provider", lambda: provider)
    def _raise_connection_error(provider, timeout_seconds):
        raise Exception("Connection refused while calling upstream")

    monkeypatch.setattr(manager, "_test_openai_provider_connectivity", _raise_connection_error)

    result = manager.test_connection()

    assert result["success"] is False
    assert result["diagnostics"]["code"] == "connection_refused"
    assert result["diagnostics"]["base_url"] == provider.base_url


def test_test_connection_timeout_diagnostics_include_timeout_check(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()

    monkeypatch.setattr(manager, "get_provider", lambda provider_name: provider if provider_name == "slow" else None)
    def _raise_timeout(provider, timeout_seconds):
        raise Exception("request timed out")

    monkeypatch.setattr(manager, "_test_openai_provider_connectivity", _raise_timeout)

    result = manager.test_connection(provider_name="slow", timeout_seconds=7.5)

    assert result["success"] is False
    assert result["diagnostics"]["code"] == "timeout"
    assert "7.5s" in result["diagnostics"]["summary"]
    assert any("Client timeout: 7.5s" in check for check in result["diagnostics"]["checks"])


def test_test_connection_can_target_specific_provider_with_timeout(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()
    captured = {}

    monkeypatch.setattr(manager, "get_provider", lambda provider_name: provider if provider_name == "target" else None)

    def _fake_probe(p, timeout_seconds):
        captured["provider"] = p
        captured["timeout_seconds"] = timeout_seconds
        return {
            "success": True,
            "provider": p.name,
            "model": p.model,
            "response": "Connectivity OK",
            "endpoint": "models_list",
            "usage": None,
            "estimated_cost_usd": None,
        }

    monkeypatch.setattr(manager, "_test_openai_provider_connectivity", _fake_probe)

    result = manager.test_connection(provider_name="target", timeout_seconds=7.5)

    assert result["success"] is True
    assert result["provider"] == provider.name
    assert captured["provider"] == provider
    assert captured["timeout_seconds"] == 7.5


def test_create_client_uses_provider_request_timeout(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()
    provider.request_timeout_seconds = 88.0
    captured = {}

    class DummyOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("app.core.llm_config.OpenAI", DummyOpenAI)
    monkeypatch.setattr(manager, "_default_timeout_seconds", lambda: 35.0)
    monkeypatch.setattr(manager, "_default_max_retries", lambda: 0)

    manager._create_client_for_provider(provider)

    assert captured["timeout"] == 88.0


def test_create_client_timeout_override_takes_precedence(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()
    provider.request_timeout_seconds = 88.0
    captured = {}

    class DummyOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("app.core.llm_config.OpenAI", DummyOpenAI)
    monkeypatch.setattr(manager, "_default_timeout_seconds", lambda: 35.0)
    monkeypatch.setattr(manager, "_default_max_retries", lambda: 0)

    manager._create_client_for_provider(provider, timeout_seconds=12.5)

    assert captured["timeout"] == 12.5
