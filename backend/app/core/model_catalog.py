"""Curated model metadata catalog for provider auto-population."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# Source: OpenAI model docs + pricing pages (manually curated).
# Keep this intentionally explicit so regulated workflows can audit assumptions.
OPENAI_MODEL_CATALOG: List[Dict[str, Any]] = [
    {
        "model": "gpt-5.2",
        "display_name": "GPT-5.2",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 1.75,
        "cached_input_cost_per_1m": 0.175,
        "output_cost_per_1m": 14.0,
        "knowledge_cutoff": "2025-06",
        "docs_url": "https://platform.openai.com/docs/models/gpt-5.2",
    },
    {
        "model": "gpt-5.2-pro",
        "display_name": "GPT-5.2 Pro",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 15.0,
        "cached_input_cost_per_1m": None,
        "output_cost_per_1m": 120.0,
        "knowledge_cutoff": "2025-06",
        "docs_url": "https://platform.openai.com/docs/models/gpt-5.2",
    },
    {
        "model": "gpt-5",
        "display_name": "GPT-5",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 1.25,
        "cached_input_cost_per_1m": 0.125,
        "output_cost_per_1m": 10.0,
        "knowledge_cutoff": "2024-09",
        "docs_url": "https://developers.openai.com/api/docs/models/gpt-5",
    },
    {
        "model": "gpt-5-mini",
        "display_name": "GPT-5 Mini",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 0.25,
        "cached_input_cost_per_1m": 0.025,
        "output_cost_per_1m": 2.0,
        "knowledge_cutoff": "2024-09",
        "docs_url": "https://developers.openai.com/api/docs/models/gpt-5-mini",
    },
    {
        "model": "gpt-5-nano",
        "display_name": "GPT-5 Nano",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 0.05,
        "cached_input_cost_per_1m": 0.005,
        "output_cost_per_1m": 0.4,
        "knowledge_cutoff": "2024-09",
        "docs_url": "https://developers.openai.com/api/docs/models/gpt-5-nano",
    },
    {
        "model": "gpt-5-pro",
        "display_name": "GPT-5 Pro",
        "family": "gpt-5",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 400000,
        "max_output_tokens": 128000,
        "input_cost_per_1m": 15.0,
        "cached_input_cost_per_1m": None,
        "output_cost_per_1m": 120.0,
        "knowledge_cutoff": "2024-09",
        "docs_url": "https://developers.openai.com/api/docs/models/gpt-5-pro",
    },
    {
        "model": "gpt-4o",
        "display_name": "GPT-4o",
        "family": "gpt-4o",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 128000,
        "max_output_tokens": 16384,
        "input_cost_per_1m": 2.5,
        "cached_input_cost_per_1m": 1.25,
        "output_cost_per_1m": 10.0,
        "knowledge_cutoff": None,
        "docs_url": "https://platform.openai.com/docs/models/gpt-4o",
    },
    {
        "model": "gpt-4o-mini",
        "display_name": "GPT-4o Mini",
        "family": "gpt-4o",
        "preferred_endpoint": "responses",
        "is_legacy": False,
        "context_window": 128000,
        "max_output_tokens": 16384,
        "input_cost_per_1m": 0.15,
        "cached_input_cost_per_1m": 0.075,
        "output_cost_per_1m": 0.6,
        "knowledge_cutoff": None,
        "docs_url": "https://platform.openai.com/docs/models/gpt-4o-mini",
    },
    {
        "model": "gpt-4",
        "display_name": "GPT-4 (Legacy)",
        "family": "gpt-4",
        "preferred_endpoint": "chat_completions",
        "is_legacy": True,
        "context_window": 8192,
        "max_output_tokens": 4096,
        "input_cost_per_1m": None,
        "cached_input_cost_per_1m": None,
        "output_cost_per_1m": None,
        "knowledge_cutoff": None,
        "docs_url": "https://platform.openai.com/docs/models/gpt-4-and-gpt-4-turbo",
    },
    {
        "model": "gpt-3.5-turbo",
        "display_name": "GPT-3.5 Turbo (Legacy)",
        "family": "gpt-3.5",
        "preferred_endpoint": "chat_completions",
        "is_legacy": True,
        "context_window": 16385,
        "max_output_tokens": 4096,
        "input_cost_per_1m": None,
        "cached_input_cost_per_1m": None,
        "output_cost_per_1m": None,
        "knowledge_cutoff": None,
        "docs_url": "https://platform.openai.com/docs/models/gpt-3-5-turbo",
    },
]


def get_openai_catalog() -> List[Dict[str, Any]]:
    """Return OpenAI model metadata sorted by display name."""
    return sorted(OPENAI_MODEL_CATALOG, key=lambda item: item["display_name"].lower())


def get_openai_model_metadata(model_name: str) -> Optional[Dict[str, Any]]:
    """Find metadata for a single OpenAI model id."""
    for item in OPENAI_MODEL_CATALOG:
        if item["model"] == model_name:
            return dict(item)
    return None
