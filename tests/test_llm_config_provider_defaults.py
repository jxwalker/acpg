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


def test_anthropic_provider_defaults_max_output_tokens_to_safe_non_streaming_limit():
    cfg = LLMProviderConfig.from_dict(
        {
            "type": "anthropic",
            "name": "Kimi",
            "base_url": "https://api.kimi.com/coding/",
            "api_key": "test",
            "model": "kimi-for-coding",
            "max_tokens": 32768,
            "temperature": 0.3,
            "context_window": 262144,
        }
    )

    assert cfg.preferred_endpoint == "anthropic_messages"
    assert cfg.max_output_tokens == 4096
