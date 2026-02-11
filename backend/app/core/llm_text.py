"""LLM text generation helpers.

Goal: centralize "Responses API first, Chat Completions fallback" behavior.
"""

from __future__ import annotations

from typing import Any, Optional

import openai


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
) -> str:
    """Call the OpenAI Responses API and return plain text."""
    resp = client.responses.create(
        model=model,
        instructions=instructions or None,
        input=input_text,
        temperature=temperature,
        max_output_tokens=max_output_tokens,
    )
    return (resp.output_text or "").strip()


def openai_text_chat_completions(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_tokens: int,
) -> str:
    """Call the OpenAI Chat Completions API and return plain text."""
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
    return text


def openai_text(
    client: Any,
    *,
    model: str,
    system_prompt: Optional[str],
    user_prompt: str,
    temperature: float,
    max_output_tokens: int,
    max_tokens_fallback: int,
) -> str:
    """Responses-first text generation with Chat Completions fallback."""
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

