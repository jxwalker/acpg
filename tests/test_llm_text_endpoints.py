"""Tests for OpenAI endpoint routing and usage normalization."""

from types import SimpleNamespace

from backend.app.core.llm_text import openai_text_with_usage


def _usage(prompt: int, completion: int):
    return SimpleNamespace(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
    )


def test_legacy_model_uses_completions_endpoint():
    class FakeCompletions:
        def create(self, **kwargs):
            return SimpleNamespace(
                choices=[SimpleNamespace(text="legacy-ok")],
                usage=_usage(12, 4),
            )

    class FakeClient:
        completions = FakeCompletions()

    result = openai_text_with_usage(
        FakeClient(),
        model="text-davinci-003",
        system_prompt="system",
        user_prompt="hello",
        temperature=0,
        max_output_tokens=32,
        max_tokens_fallback=32,
        preferred_endpoint="responses",
    )

    assert result.endpoint == "completions_legacy"
    assert result.text == "legacy-ok"
    assert result.usage is not None
    assert result.usage["total_tokens"] == 16


def test_responses_model_returns_responses_usage():
    usage = SimpleNamespace(
        input_tokens=20,
        output_tokens=5,
        total_tokens=25,
        input_tokens_details=SimpleNamespace(cached_tokens=3),
        output_tokens_details=SimpleNamespace(reasoning_tokens=2),
    )

    class FakeResponses:
        def create(self, **kwargs):
            return SimpleNamespace(output_text="modern-ok", usage=usage)

    class FakeClient:
        responses = FakeResponses()

    result = openai_text_with_usage(
        FakeClient(),
        model="gpt-5-mini",
        system_prompt=None,
        user_prompt="hello",
        temperature=0,
        max_output_tokens=32,
        max_tokens_fallback=32,
        preferred_endpoint="responses",
    )

    assert result.endpoint == "responses"
    assert result.text == "modern-ok"
    assert result.usage is not None
    assert result.usage["input_tokens"] == 20
    assert result.usage["cached_input_tokens"] == 3
    assert result.usage["reasoning_tokens"] == 2
