"""LLM Configuration Management for ACPG.

Supports multiple LLM providers:
- OpenAI API
- OpenAI-compatible APIs (vLLM, Ollama, etc.)
- Anthropic API (Claude, Kimi, etc.)
- Local models
"""
import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any, Union
from dataclasses import dataclass
from openai import OpenAI
try:
    from anthropic import Anthropic
except ImportError:
    Anthropic = None
from dotenv import load_dotenv
from .llm_text import openai_text

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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LLMProviderConfig':
        """Create config from dictionary, expanding env vars."""
        api_key = data.get('api_key', '')
        
        # Expand environment variables in api_key
        if api_key.startswith('${') and api_key.endswith('}'):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, '')
        
        return cls(
            name=data.get('name', 'Unknown'),
            type=data.get('type', 'openai'),
            base_url=data.get('base_url', 'https://api.openai.com/v1'),
            api_key=api_key,
            model=data.get('model', 'gpt-4'),
            max_tokens=data.get('max_tokens', 2000),
            temperature=data.get('temperature', 0.3),
            context_window=data.get('context_window', 8192)
        )


class LLMConfigManager:
    """Manages LLM configuration and client creation."""
    
    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "llm_config.yaml"
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self._config: Optional[Dict[str, Any]] = None
        self._active_provider: Optional[LLMProviderConfig] = None
        self._client: Optional[Union[OpenAI, Any]] = None
    
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
                    'context_window': 8192
                }
            }
        }
    
    def get_active_provider(self) -> LLMProviderConfig:
        """Get the currently active LLM provider configuration."""
        if self._active_provider is not None:
            return self._active_provider
        
        config = self.load_config()
        active_name = os.environ.get('ACPG_LLM_PROVIDER') or config.get('active_provider', 'openai_gpt4')
        
        providers = config.get('providers', {})
        if active_name not in providers:
            raise ValueError(f"Unknown LLM provider: {active_name}")
        
        self._active_provider = LLMProviderConfig.from_dict(providers[active_name])
        return self._active_provider
    
    def get_client(self) -> Union[OpenAI, Any]:
        """Get a client configured for the active provider (OpenAI or Anthropic)."""
        if self._client is not None:
            return self._client
        
        provider = self.get_active_provider()
        
        if provider.type == 'anthropic':
            if Anthropic is None:
                raise ImportError("anthropic package is required for Anthropic API. Install with: pip install anthropic")
            self._client = Anthropic(
                api_key=provider.api_key or "",
                base_url=provider.base_url
            )
        else:
            # OpenAI or OpenAI-compatible
            self._client = OpenAI(
                api_key=provider.api_key or "not-needed",
                base_url=provider.base_url
            )
        
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
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to the active LLM provider."""
        provider = self.get_active_provider()
        client = self.get_client()
        
        try:
            prompt = "Say 'OK' if you can hear me."
            if provider.type == "anthropic":
                response = client.messages.create(
                    model=provider.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=10,
                    temperature=0,
                )
                text = response.content[0].text.strip() if response.content else ""
            else:
                text = openai_text(
                    client,
                    model=provider.model,
                    system_prompt=None,
                    user_prompt=prompt,
                    temperature=0,
                    max_output_tokens=10,
                    max_tokens_fallback=10,
                )

            return {
                "success": True,
                "provider": provider.name,
                "model": provider.model,
                "response": text
            }
        
        except Exception as e:
            return {
                "success": False,
                "provider": provider.name,
                "model": provider.model,
                "error": str(e)
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
