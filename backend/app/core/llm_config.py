"""LLM Configuration Management for ACPG.

Supports multiple LLM providers:
- OpenAI API
- OpenAI-compatible APIs (vLLM, Ollama, etc.)
- Anthropic API (Claude, Kimi, etc.)
- Local models
"""
import os
import yaml
import httpx
from pathlib import Path
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass
from openai import OpenAI
try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None
from dotenv import load_dotenv
from .llm_text import is_legacy_model

# Load .env file if it exists
_env_path = Path(__file__).parent.parent.parent.parent / ".env"
if _env_path.exists():
    load_dotenv(_env_path)


@dataclass
class LLMProviderConfig:
    """Configuration for an LLM provider."""
    name: str
    type: str  # 'openai', 'openai_compatible', 'anthropic'
    base_url: str
    api_key: str
    model: str
    max_tokens: int
    temperature: float
    context_window: int
    max_output_tokens: Optional[int] = None
    preferred_endpoint: str = "responses"
    request_timeout_seconds: Optional[float] = None
    input_cost_per_1m: Optional[float] = None
    cached_input_cost_per_1m: Optional[float] = None
    output_cost_per_1m: Optional[float] = None
    docs_url: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LLMProviderConfig':
        """Create config from dictionary, expanding env vars."""
        api_key = data.get('api_key', '')
        
        # Expand environment variables in api_key
        if api_key.startswith('${') and api_key.endswith('}'):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, '')
        
        provider_type = data.get('type', 'openai')
        model = data.get('model', 'gpt-4')
        preferred_endpoint = data.get('preferred_endpoint')
        if not preferred_endpoint:
            if provider_type == 'anthropic':
                preferred_endpoint = "anthropic_messages"
            elif is_legacy_model(model):
                preferred_endpoint = "completions_legacy"
            else:
                preferred_endpoint = "responses"

        def _as_float(value: Any) -> Optional[float]:
            if value is None:
                return None
            try:
                return float(value)
            except Exception:
                return None

        max_tokens = data.get('max_tokens')
        try:
            max_tokens = int(max_tokens) if max_tokens is not None else 2000
        except Exception:
            max_tokens = 2000

        max_output_tokens = data.get('max_output_tokens')
        if max_output_tokens is not None:
            try:
                max_output_tokens = int(max_output_tokens)
            except Exception:
                max_output_tokens = None

        # Anthropic-compatible providers can reject non-streaming requests with very large
        # output budgets. Set a safe default unless explicitly configured.
        if max_output_tokens is None and provider_type == 'anthropic':
            max_output_tokens = min(max_tokens, 2048)

        temperature = data.get('temperature')
        try:
            temperature = float(temperature) if temperature is not None else 0.3
        except Exception:
            temperature = 0.3

        context_window = data.get('context_window')
        try:
            context_window = int(context_window) if context_window is not None else 8192
        except Exception:
            context_window = 8192

        return cls(
            name=data.get('name', 'Unknown'),
            type=provider_type,
            base_url=data.get('base_url', 'https://api.openai.com/v1'),
            api_key=api_key,
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            context_window=context_window,
            max_output_tokens=max_output_tokens,
            preferred_endpoint=preferred_endpoint,
            request_timeout_seconds=_as_float(data.get('request_timeout_seconds')),
            input_cost_per_1m=_as_float(data.get('input_cost_per_1m')),
            cached_input_cost_per_1m=_as_float(data.get('cached_input_cost_per_1m')),
            output_cost_per_1m=_as_float(data.get('output_cost_per_1m')),
            docs_url=data.get('docs_url'),
        )


class LLMConfigManager:
    """Manages LLM configuration and client creation."""
    
    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "llm_config.yaml"
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self._config: Optional[Dict[str, Any]] = None
        self._active_provider: Optional[LLMProviderConfig] = None
        self._client: Optional[Union[OpenAI, Any]] = None

    @staticmethod
    def _default_timeout_seconds() -> float:
        """Default per-request timeout for generation calls (seconds)."""
        raw = os.environ.get("ACPG_LLM_REQUEST_TIMEOUT_SECONDS", "35")
        try:
            parsed = float(raw)
            if parsed <= 0:
                raise ValueError
            return parsed
        except Exception:
            return 35.0

    @staticmethod
    def _default_max_retries() -> int:
        """Default SDK retry count for generation calls."""
        raw = os.environ.get("ACPG_LLM_MAX_RETRIES", "0")
        try:
            parsed = int(raw)
            return max(0, min(parsed, 5))
        except Exception:
            return 0
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if self._config is not None:
            return self._config
        
        if not self.config_path.exists():
            print(f"⚠️  LLM config not found at {self.config_path}, using defaults")
            self._config = self._default_config()
            return self._config
        
        with open(self.config_path, 'r') as f:
            self._config = yaml.safe_load(f)
        
        return self._config
    
    def _default_config(self) -> Dict[str, Any]:
        """Return default configuration."""
        return {
            'active_provider': 'openai_gpt4',
            'providers': {
                'openai_gpt4': {
                    'type': 'openai',
                    'name': 'OpenAI GPT-4',
                    'base_url': 'https://api.openai.com/v1',
                    'api_key': '${OPENAI_API_KEY}',
                    'model': 'gpt-4',
                    'max_tokens': 2000,
                    'temperature': 0.3,
                    'context_window': 8192,
                    'max_output_tokens': 8192,
                    'preferred_endpoint': 'chat_completions',
                }
            }
        }
    
    def get_active_provider(self) -> LLMProviderConfig:
        """Get the currently active LLM provider configuration."""
        if self._active_provider is not None:
            return self._active_provider
        
        config = self.load_config()
        active_name = os.environ.get('ACPG_LLM_PROVIDER') or config.get('active_provider', 'openai_gpt4')
        self._active_provider = self.get_provider(active_name)
        return self._active_provider

    def get_provider(self, provider_name: str) -> LLMProviderConfig:
        """Get a specific provider configuration by id."""
        config = self.load_config()
        providers = config.get('providers', {})
        if provider_name not in providers:
            raise ValueError(f"Unknown LLM provider: {provider_name}")
        return LLMProviderConfig.from_dict(providers[provider_name])

    def _create_client_for_provider(
        self,
        provider: LLMProviderConfig,
        *,
        timeout_seconds: Optional[float] = None,
    ) -> Union[OpenAI, Any]:
        """Create a client for a given provider, optionally overriding request timeout."""
        if timeout_seconds is not None:
            effective_timeout = float(timeout_seconds)
        elif provider.request_timeout_seconds is not None and provider.request_timeout_seconds > 0:
            effective_timeout = float(provider.request_timeout_seconds)
        else:
            effective_timeout = self._default_timeout_seconds()
        max_retries = self._default_max_retries()

        if provider.type == 'anthropic':
            if Anthropic is None:
                raise ImportError("anthropic package is required for Anthropic API. Install with: pip install anthropic")
            kwargs: Dict[str, Any] = {
                "api_key": provider.api_key or "",
                "base_url": provider.base_url,
                "timeout": effective_timeout,
                "max_retries": max_retries,
            }
            return Anthropic(**kwargs)

        kwargs = {
            "api_key": provider.api_key or "not-needed",
            "base_url": provider.base_url,
            "timeout": effective_timeout,
            "max_retries": max_retries,
        }
        return OpenAI(**kwargs)

    def _test_openai_provider_connectivity(
        self,
        provider: LLMProviderConfig,
        timeout_seconds: float,
    ) -> Dict[str, Any]:
        """Fast connectivity test for OpenAI/OpenAI-compatible providers via /models."""
        base = provider.base_url.rstrip("/")
        urls = [f"{base}/models"]
        if not base.endswith("/v1"):
            urls.append(f"{base}/v1/models")

        # Keep total probe time bounded across URL attempts.
        per_attempt_timeout = max(1.0, timeout_seconds / max(1, len(urls)))
        timeout = httpx.Timeout(per_attempt_timeout)
        headers: Dict[str, str] = {"accept": "application/json"}
        api_key = provider.api_key or ""
        if api_key and api_key not in ("not-needed", "ollama"):
            headers["authorization"] = f"Bearer {api_key}"

        errors: List[str] = []
        for url in urls:
            try:
                with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                    resp = client.get(url, headers=headers)

                if resp.status_code >= 400:
                    snippet = (resp.text or "").strip().replace("\n", " ")
                    if len(snippet) > 180:
                        snippet = snippet[:180] + "..."
                    raise RuntimeError(f"HTTP {resp.status_code} from {url}: {snippet}")

                payload = resp.json()
                model_ids: List[str] = []
                if isinstance(payload, dict) and isinstance(payload.get("data"), list):
                    for item in payload["data"]:
                        if isinstance(item, dict) and item.get("id"):
                            model_ids.append(str(item["id"]))

                if model_ids and provider.model not in model_ids:
                    preview = ", ".join(model_ids[:5]) if model_ids else "none"
                    raise RuntimeError(
                        f"Model not found in provider catalog: {provider.model}. "
                        f"Sample available models: {preview}"
                    )

                return {
                    "success": True,
                    "provider": provider.name,
                    "model": provider.model,
                    "response": f"Connectivity OK via {url}",
                    "endpoint": "models_list",
                    "usage": None,
                    "estimated_cost_usd": None,
                }
            except Exception as e:
                errors.append(str(e))

        # Surface the first failure with details for diagnostics classification.
        raise RuntimeError(errors[0] if errors else "Provider connectivity check failed")
    
    def get_client(self) -> Union[OpenAI, Any]:
        """Get a client configured for the active provider (OpenAI or Anthropic)."""
        if self._client is not None:
            return self._client
        
        provider = self.get_active_provider()
        self._client = self._create_client_for_provider(provider)
        
        return self._client
    
    def get_model(self) -> str:
        """Get the model name for the active provider."""
        return self.get_active_provider().model
    
    def get_max_tokens(self) -> int:
        """Get max tokens for the active provider."""
        return self.get_active_provider().max_tokens
    
    def get_temperature(self) -> float:
        """Get temperature for the active provider."""
        return self.get_active_provider().temperature
    
    def list_providers(self) -> Dict[str, str]:
        """List all available providers."""
        config = self.load_config()
        providers = config.get('providers', {})
        return {
            name: data.get('name', name)
            for name, data in providers.items()
        }
    
    def switch_provider(self, provider_name: str) -> LLMProviderConfig:
        """Switch to a different provider."""
        config = self.load_config()
        providers = config.get('providers', {})
        
        if provider_name not in providers:
            raise ValueError(f"Unknown provider: {provider_name}. Available: {list(providers.keys())}")
        
        # Reset cached values
        self._active_provider = None
        self._client = None
        
        # Update config
        self._config['active_provider'] = provider_name
        
        return self.get_active_provider()

    def _build_connection_diagnostics(
        self,
        provider: LLMProviderConfig,
        error: Exception,
        timeout_seconds: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Build structured diagnostics for offline/unavailable model scenarios."""
        error_text = str(error).strip()
        error_lower = error_text.lower()

        code = "unknown_error"
        summary = "Unable to reach the configured model."
        suggestions: List[str] = [
            "Run provider test again after verifying endpoint and credentials.",
            "Check ACPG logs for full stack traces around /api/v1/llm/test.",
        ]

        if any(token in error_lower for token in ["connection refused", "failed to establish", "name or service not known", "nodename nor servname", "temporary failure in name resolution"]):
            code = "connection_refused"
            summary = "Provider endpoint is unreachable."
            suggestions = [
                "Verify the provider base URL and that the service is running.",
                "If using a local model server, confirm the process and port are up.",
                "Check firewall/network rules between ACPG and the model endpoint.",
            ]
        elif ("http 404" in error_lower and "/models" in error_lower) or ("404" in error_lower and "models" in error_lower):
            code = "models_endpoint_missing"
            summary = "Provider did not expose a compatible models endpoint."
            suggestions = [
                "Verify base URL points to an OpenAI-compatible API root (often ending in /v1).",
                "Test manually with: curl <base_url>/models (or <base_url>/v1/models).",
                "If provider is non-OpenAI-compatible, use the matching provider type/settings.",
            ]
        elif any(token in error_lower for token in ["timed out", "timeout"]):
            code = "timeout"
            if timeout_seconds is not None:
                summary = f"Provider did not respond before timeout ({timeout_seconds:.1f}s)."
            else:
                summary = "Provider did not respond before timeout."
            suggestions = [
                "Confirm endpoint responsiveness with a quick models-list request.",
                "Check provider load and increase server-side request timeout if needed.",
                "Try a smaller/faster model to confirm baseline connectivity.",
                "Verify network latency between ACPG and the provider endpoint.",
            ]
        elif any(token in error_lower for token in ["401", "403", "unauthorized", "forbidden", "invalid api key", "authentication"]):
            code = "auth_failed"
            summary = "Provider rejected authentication credentials."
            suggestions = [
                "Verify the API key/env-var mapping for this provider.",
                "Confirm key permissions include inference for the configured model.",
                "Rotate/regenerate the key if credentials may be stale.",
            ]
        elif "429" in error_lower or "rate limit" in error_lower or "quota" in error_lower:
            code = "rate_limited"
            summary = "Provider rate limit or quota was exceeded."
            suggestions = [
                "Retry after cooldown or reduce request concurrency.",
                "Check account quota and billing limits.",
                "Use an alternate provider/model as fallback.",
            ]
        elif ("404" in error_lower and "responses" in error_lower) or ("/responses" in error_lower and "not found" in error_lower):
            code = "responses_unsupported"
            summary = "Provider does not expose Responses API."
            suggestions = [
                "This can be expected on some OpenAI-compatible servers.",
                "ACPG will attempt Chat Completions fallback automatically.",
                "If fallback also fails, verify the provider's OpenAI compatibility mode.",
            ]
        elif ("404" in error_lower and "model" in error_lower) or ("model" in error_lower and "not found" in error_lower):
            code = "model_not_found"
            summary = "Configured model was not found on the provider."
            suggestions = [
                "Verify the model identifier exactly matches the provider catalog.",
                "Update the provider configuration to a model that exists on this endpoint.",
                "Check whether the model requires a specific account tier/access flag.",
            ]
        elif "500" in error_lower or "502" in error_lower or "503" in error_lower or "504" in error_lower:
            code = "provider_server_error"
            summary = "Provider returned a server-side error."
            suggestions = [
                "Retry request after short delay.",
                "Check provider health/status page if available.",
                "Use an alternate provider while upstream recovers.",
            ]

        checks = [
            f"Provider name: {provider.name}",
            f"Provider type: {provider.type}",
            f"Base URL: {provider.base_url}",
            f"Model: {provider.model}",
            f"Client retries: {self._default_max_retries()}",
        ]
        if timeout_seconds is not None:
            checks.append(f"Client timeout: {timeout_seconds:.1f}s")

        return {
            "code": code,
            "summary": summary,
            "checks": checks,
            "suggestions": suggestions,
            "base_url": provider.base_url,
            "model": provider.model,
            "provider_type": provider.type,
            "raw_error": error_text,
        }
    
    def test_connection(
        self,
        provider_name: Optional[str] = None,
        timeout_seconds: Optional[float] = 12.0,
    ) -> Dict[str, Any]:
        """Test connection to an LLM provider (active by default)."""
        provider = self.get_provider(provider_name) if provider_name else self.get_active_provider()
        timeout_seconds = float(timeout_seconds or 12.0)
        
        try:
            if provider.type in ("openai", "openai_compatible"):
                return self._test_openai_provider_connectivity(provider, timeout_seconds)

            # Anthropic-compatible probe: tiny message request with strict timeout.
            client = self._create_client_for_provider(provider, timeout_seconds=timeout_seconds)
            prompt = "OK?"
            if provider.type == "anthropic":
                response = client.messages.create(
                    model=provider.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=1,
                    temperature=0,
                )
                text = response.content[0].text.strip() if response.content else ""
                endpoint_used = "anthropic_messages"
                usage_data = None
                if hasattr(response, "usage") and response.usage is not None:
                    input_tokens = int(getattr(response.usage, "input_tokens", 0) or 0)
                    output_tokens = int(getattr(response.usage, "output_tokens", 0) or 0)
                    usage_data = {
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                        "total_tokens": input_tokens + output_tokens,
                        "cached_input_tokens": 0,
                        "reasoning_tokens": 0,
                    }
            estimated_cost_usd = None
            if usage_data and provider.input_cost_per_1m is not None and provider.output_cost_per_1m is not None:
                input_tokens = int(usage_data.get("input_tokens") or 0)
                output_tokens = int(usage_data.get("output_tokens") or 0)
                cached_input_tokens = int(usage_data.get("cached_input_tokens") or 0)
                billable_input_tokens = max(0, input_tokens - cached_input_tokens)
                input_cost = (billable_input_tokens / 1_000_000) * provider.input_cost_per_1m
                output_cost = (output_tokens / 1_000_000) * provider.output_cost_per_1m
                cached_cost = 0.0
                if provider.cached_input_cost_per_1m is not None and cached_input_tokens > 0:
                    cached_cost = (cached_input_tokens / 1_000_000) * provider.cached_input_cost_per_1m
                estimated_cost_usd = round(input_cost + cached_cost + output_cost, 8)

            return {
                "success": True,
                "provider": provider.name,
                "model": provider.model,
                "response": text,
                "endpoint": endpoint_used,
                "usage": usage_data,
                "estimated_cost_usd": estimated_cost_usd,
            }
        
        except Exception as e:
            return {
                "success": False,
                "provider": provider.name,
                "model": provider.model,
                "error": str(e),
                "diagnostics": self._build_connection_diagnostics(provider, e, timeout_seconds=timeout_seconds),
            }


# Global config manager instance
_config_manager: Optional[LLMConfigManager] = None


def get_llm_config() -> LLMConfigManager:
    """Get the global LLM config manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = LLMConfigManager()
    return _config_manager


def get_llm_client() -> OpenAI:
    """Get the configured LLM client."""
    return get_llm_config().get_client()
