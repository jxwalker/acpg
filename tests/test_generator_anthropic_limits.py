"""Generator behavior tests for Anthropic-compatible providers."""

from types import SimpleNamespace

from backend.app.core.llm_config import LLMProviderConfig
from backend.app.services.generator import Generator


class _DummyMessages:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(text="print('fixed')")],
            usage=SimpleNamespace(input_tokens=5, output_tokens=3),
        )


class _DummyAnthropicClient:
    def __init__(self):
        self.messages = _DummyMessages()


class _DummyLLMConfig:
    def __init__(self, provider):
        self._provider = provider

    def get_active_provider(self):
        return self._provider

    def get_max_tokens(self):
        return self._provider.max_tokens

    def get_temperature(self):
        return self._provider.temperature


class _DummyPolicyCompiler:
    @staticmethod
    def get_policy(_):
        return None

    @staticmethod
    def get_all_policies():
        return []


def test_generator_caps_anthropic_output_tokens_for_non_streaming_requests(monkeypatch):
    provider = LLMProviderConfig.from_dict(
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
    llm_config = _DummyLLMConfig(provider)
    client = _DummyAnthropicClient()

    monkeypatch.setattr("backend.app.services.generator.get_llm_config", lambda: llm_config)
    monkeypatch.setattr("backend.app.services.generator.get_llm_client", lambda: client)
    monkeypatch.setattr("backend.app.services.generator.get_policy_compiler", lambda: _DummyPolicyCompiler())

    generator = Generator()
    text = generator._generate_text(system_prompt="system", user_prompt="user", operation="test")

    assert text == "print('fixed')"
    assert client.messages.calls
    assert client.messages.calls[-1]["max_tokens"] == 2048
