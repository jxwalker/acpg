"""LLM text generation helpers.

Goal: centralize endpoint selection behavior:
- Responses API first for modern models.
- Chat Completions / legacy Completions for legacy models when required.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import openai


@dataclass
class OpenAITextResult:
    """Normalized text + usage result across OpenAI endpoints."""
    text: str
    endpoint: str
    usage: Optional[Dict[str, int]] = None


def is_legacy_model(model: str) -> bool:
    """Best-effort classification for legacy models that should avoid Responses first."""
    legacy_exact = {
        "gpt-3.5-turbo-instruct",
        "davinci-002",
        "babbage-002",
    }
    if model in legacy_exact:
        return True
    lowered = model.lower()
    if lowered.startswith("text-"):
        return True
    if lowered.endswith("-instruct"):
        return True
    return False


def _to_dict(obj: Any) -> Dict[str, Any]:
    """Convert SDK objects/dicts to a plain dict."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump()  # pydantic models
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    return {}


def _extract_responses_usage(resp: Any) -> Optional[Dict[str, int]]:
    usage_obj = getattr(resp, "usage", None)
    usage = _to_dict(usage_obj)
    if not usage:
        return None

    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens))

    input_details = _to_dict(usage.get("input_tokens_details"))
    output_details = _to_dict(usage.get("output_tokens_details"))

    cached_input_tokens = int(input_details.get("cached_tokens") or 0)
    reasoning_tokens = int(output_details.get("reasoning_tokens") or 0)

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cached_input_tokens": cached_input_tokens,
        "reasoning_tokens": reasoning_tokens,
    }


def _extract_chat_usage(resp: Any) -> Optional[Dict[str, int]]:
    usage_obj = getattr(resp, "usage", None)
    usage = _to_dict(usage_obj)
    if not usage:
        return None

    input_tokens = int(usage.get("prompt_tokens") or 0)
    output_tokens = int(usage.get("completion_tokens") or 0)
    total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens))

    prompt_details = _to_dict(usage.get("prompt_tokens_details"))
    completion_details = _to_dict(usage.get("completion_tokens_details"))

    cached_input_tokens = int(prompt_details.get("cached_tokens") or 0)
    reasoning_tokens = int(completion_details.get("reasoning_tokens") or 0)

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cached_input_tokens": cached_input_tokens,
        "reasoning_tokens": reasoning_tokens,
    }


def _looks_like_responses_unsupported(err: Exception) -> bool:
    """Heuristic for OpenAI-compatible servers that don't implement /responses."""
    status = getattr(err, "status_code", None)
    if status in (404, 405):
        return True
    msg = str(err).lower()
    return ("/responses" in msg and ("not found" in msg or "404" in msg or "unknown" in msg))


def openai_text_response(
    client: Any,
    *,
    model: str,
    instructions: Optional[str],
    input_text: str,
    temperature: float,
    max_output_tokens: int,
) -> OpenAITextResult:
    """Call the OpenAI Responses API and return normalized text + usage."""
    resp = client.responses.create(
        model=model,
        instructions=instructions or None,
        input=input_text,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
    )
    return OpenAITextResult(
        text=(resp.output_text or "").strip(),
        endpoint="responses",
        usage=_extract_responses_usage(resp),
    )


def openai_text_chat_completions(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_tokens: int,
) -> OpenAITextResult:
    """Call the OpenAI Chat Completions API and return normalized text + usage."""
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    resp = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    text = (resp.choices[0].message.content or "").strip() if resp.choices else ""
    return OpenAITextResult(
        text=text,
        endpoint="chat_completions",
        usage=_extract_chat_usage(resp),
    )


def openai_text_completions_legacy(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_tokens: int,
) -> OpenAITextResult:
    """Call the legacy Completions API for models that require it."""
    prompt = user_prompt
    if system_prompt:
        prompt = f"{system_prompt}\n\n{user_prompt}"

    resp = client.completions.create(
        model=model,
        prompt=prompt,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    text = (resp.choices[0].text or "").strip() if resp.choices else ""
    return OpenAITextResult(
        text=text,
        endpoint="completions_legacy",
        usage=_extract_chat_usage(resp),
    )


def openai_text_with_usage(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_output_tokens: int,
    max_tokens_fallback: int,
    preferred_endpoint: str = "responses",
) -> OpenAITextResult:
    """Endpoint-aware text generation with normalized usage.

    preferred_endpoint values:
    - responses
    - chat_completions
    - completions_legacy
    """
    if preferred_endpoint == "completions_legacy" or is_legacy_model(model):
        return openai_text_completions_legacy(
            client,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=max_tokens_fallback,
        )

    if preferred_endpoint == "chat_completions":
        return openai_text_chat_completions(
            client,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            max_tokens=max_tokens_fallback,
        )

    # Default: Responses-first for modern models.
    try:
        return openai_text_response(
            client,
            model=model,
            instructions=system_prompt,
            input_text=user_prompt,
            temperature=temperature,
            max_output_tokens=max_output_tokens,
        )
    except openai.NotFoundError as e:
        if _looks_like_responses_unsupported(e):
            return openai_text_chat_completions(
                client,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens_fallback,
            )
        raise
    except Exception as e:
        if _looks_like_responses_unsupported(e):
            return openai_text_chat_completions(
                client,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens_fallback,
            )
        raise


def openai_text(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_output_tokens: int,
    max_tokens_fallback: int,
    preferred_endpoint: str = "responses",
) -> str:
    """Compatibility wrapper: returns plain text only."""
    result = openai_text_with_usage(
        client,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
        max_tokens_fallback=max_tokens_fallback,
        preferred_endpoint=preferred_endpoint,
    )
    return result.text
