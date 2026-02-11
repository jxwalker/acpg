"""Tests for provider defaults and endpoint preference behavior."""

from backend.app.core.llm_config import LLMProviderConfig


def test_openai_provider_defaults_to_responses():
    cfg = LLMProviderConfig.from_dict(
        {
            "type": "openai",
            "name": "OpenAI",
            "base_url": "https://api.openai.com/v1",
            "api_key": "test",
            "model": "gpt-5-mini",
            "max_tokens": 2000,
            "temperature": 0.3,
            "context_window": 400000,
        }
    )

    assert cfg.preferred_endpoint == "responses"


def test_legacy_text_model_defaults_to_legacy_completions():
    cfg = LLMProviderConfig.from_dict(
        {
            "type": "openai",
            "name": "Legacy",
            "base_url": "https://api.openai.com/v1",
            "api_key": "test",
            "model": "text-davinci-003",
            "max_tokens": 2000,
            "temperature": 0.3,
            "context_window": 4097,
        }
    )

    assert cfg.preferred_endpoint == "completions_legacy"
