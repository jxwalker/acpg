"""Tests for LLM offline diagnostics."""

from app.core.llm_config import LLMConfigManager, LLMProviderConfig
import app.core.llm_config as llm_config_module


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


def test_test_connection_reports_auth_diagnostics(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()

    monkeypatch.setattr(manager, "get_active_provider", lambda: provider)
    monkeypatch.setattr(manager, "get_client", lambda: object())

    def _raise_auth_error(*args, **kwargs):
        raise Exception("401 Unauthorized: invalid api key")

    monkeypatch.setattr(llm_config_module, "openai_text", _raise_auth_error)

    result = manager.test_connection()

    assert result["success"] is False
    assert result["diagnostics"]["code"] == "auth_failed"
    assert "authentication" in result["diagnostics"]["summary"].lower()


def test_test_connection_reports_connection_diagnostics(monkeypatch):
    manager = LLMConfigManager()
    provider = _provider()

    monkeypatch.setattr(manager, "get_active_provider", lambda: provider)
    monkeypatch.setattr(manager, "get_client", lambda: object())

    def _raise_connection_error(*args, **kwargs):
        raise Exception("Connection refused while calling upstream")

    monkeypatch.setattr(llm_config_module, "openai_text", _raise_connection_error)

    result = manager.test_connection()

    assert result["success"] is False
    assert result["diagnostics"]["code"] == "connection_refused"
    assert result["diagnostics"]["base_url"] == provider.base_url
