"""Generator Service - AI-powered code generation and fixing using configurable LLMs."""
from typing import List, Optional, Dict, Any
from datetime import datetime


from ..models.schemas import (
    GeneratorRequest, GeneratorResponse, Violation, PolicyRule, ArtifactMetadata
)
from ..core.config import settings
from ..core.llm_config import get_llm_config, get_llm_client
from ..core.llm_text import openai_text_with_usage
from .policy_compiler import get_policy_compiler


class Generator:
    """
    The Generator agent creates and fixes code with policy awareness.
    
    Uses configurable LLM backends (OpenAI, vLLM, Ollama, etc.) to:
    1. Generate code from specifications with policy constraints
    2. Fix code based on violation reports
    3. Provide explanations for changes made
    """
    
    def __init__(self):
        self.llm_config = get_llm_config()
        # Do not permanently bind a client/provider here: model management can switch providers at runtime.
        # We refresh `self.client/self.provider` at the start of each LLM call.
        self.client = None
        self.provider = None
        self.model = None
        self.model_name = None  # Human-readable name for metadata
        self._usage_events: List[Dict[str, Any]] = []
        self.policy_compiler = get_policy_compiler()
        
        # Log current provider (best-effort; may change later)
        try:
            self._refresh_llm()
            print(f"🤖 Generator using: {self.provider.name} ({self.provider.model})")
        except Exception:
            pass

    def _effective_max_output_tokens(self, requested_max_output_tokens: Optional[int]) -> int:
        """Resolve a safe max output token budget for the active provider."""
        provider_max = None
        if self.provider is not None:
            provider_max = self.provider.max_output_tokens

        if requested_max_output_tokens is not None:
            max_out = int(requested_max_output_tokens)
        elif provider_max is not None:
            max_out = int(provider_max)
        else:
            max_out = int(self.llm_config.get_max_tokens())

        # Non-streaming Anthropic/Kimi requests can fail with very large budgets.
        if self.provider is not None and self.provider.type == "anthropic":
            max_out = min(max_out, 4096)

        return max(1, max_out)

    def _refresh_llm(self):
        """Refresh LLM client/provider for the currently active config."""
        self.client = get_llm_client()
        self.provider = self.llm_config.get_active_provider()
        self.model = self.provider.model
        self.model_name = self.provider.name

    def reset_usage_tracking(self) -> None:
        """Reset accumulated usage for a single app run/enforcement cycle."""
        self._usage_events = []

    def _record_usage(self, *, endpoint: str, usage: Optional[Dict[str, int]], operation: str) -> None:
        """Record a normalized usage event for cost accounting."""
        usage = usage or {}
        input_tokens = int(usage.get("input_tokens") or 0)
        output_tokens = int(usage.get("output_tokens") or 0)
        total_tokens = int(usage.get("total_tokens") or (input_tokens + output_tokens))
        cached_input_tokens = int(usage.get("cached_input_tokens") or 0)
        reasoning_tokens = int(usage.get("reasoning_tokens") or 0)

        self._usage_events.append(
            {
                "operation": operation,
                "provider": self.model_name,
                "model": self.model,
                "endpoint": endpoint,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "cached_input_tokens": cached_input_tokens,
                "reasoning_tokens": reasoning_tokens,
            }
        )

    def get_usage_summary(self) -> Dict[str, Any]:
        """Aggregate usage and estimated costs across accumulated LLM calls."""
        if self.provider is None:
            try:
                self._refresh_llm()
            except Exception:
                pass

        endpoint_breakdown: Dict[str, int] = {}
        input_tokens = 0
        output_tokens = 0
        total_tokens = 0
        cached_input_tokens = 0
        reasoning_tokens = 0

        for event in self._usage_events:
            endpoint = str(event.get("endpoint") or "unknown")
            endpoint_breakdown[endpoint] = endpoint_breakdown.get(endpoint, 0) + 1
            input_tokens += int(event.get("input_tokens") or 0)
            output_tokens += int(event.get("output_tokens") or 0)
            total_tokens += int(event.get("total_tokens") or 0)
            cached_input_tokens += int(event.get("cached_input_tokens") or 0)
            reasoning_tokens += int(event.get("reasoning_tokens") or 0)

        pricing = {
            "input_cost_per_1m": self.provider.input_cost_per_1m if self.provider else None,
            "cached_input_cost_per_1m": self.provider.cached_input_cost_per_1m if self.provider else None,
            "output_cost_per_1m": self.provider.output_cost_per_1m if self.provider else None,
        }

        estimated_cost_usd = None
        if self.provider and self.provider.input_cost_per_1m is not None and self.provider.output_cost_per_1m is not None:
            billable_input_tokens = max(0, input_tokens - cached_input_tokens)
            input_cost = (billable_input_tokens / 1_000_000) * self.provider.input_cost_per_1m
            output_cost = (output_tokens / 1_000_000) * self.provider.output_cost_per_1m
            cached_cost = 0.0
            if self.provider.cached_input_cost_per_1m is not None and cached_input_tokens > 0:
                cached_cost = (cached_input_tokens / 1_000_000) * self.provider.cached_input_cost_per_1m
            estimated_cost_usd = round(input_cost + cached_cost + output_cost, 8)

        return {
            "provider": self.model_name,
            "model": self.model,
            "call_count": len(self._usage_events),
            "endpoint_breakdown": endpoint_breakdown,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "cached_input_tokens": cached_input_tokens,
            "reasoning_tokens": reasoning_tokens,
            "estimated_cost_usd": estimated_cost_usd,
            "pricing": pricing,
        }

    def _generate_text(self, *, system_prompt: str, user_prompt: str, max_output_tokens: Optional[int] = None, operation: str = "unknown") -> str:
        """Generate text using the active provider.

        OpenAI providers: Responses API first, Chat Completions fallback.
        Anthropic providers: messages API.
        """
        self._refresh_llm()
        max_out = self._effective_max_output_tokens(max_output_tokens)

        if self.provider.type == 'anthropic':
            # Anthropic API format
            response = self.client.messages.create(
                model=self.model,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                temperature=self.llm_config.get_temperature(),
                max_tokens=max_out,
            )
            anthropic_usage = None
            if hasattr(response, "usage") and response.usage is not None:
                anthropic_usage = {
                    "input_tokens": int(getattr(response.usage, "input_tokens", 0) or 0),
                    "output_tokens": int(getattr(response.usage, "output_tokens", 0) or 0),
                    "total_tokens": int((getattr(response.usage, "input_tokens", 0) or 0) + (getattr(response.usage, "output_tokens", 0) or 0)),
                    "cached_input_tokens": 0,
                    "reasoning_tokens": 0,
                }
            self._record_usage(endpoint="anthropic_messages", usage=anthropic_usage, operation=operation)
            return response.content[0].text.strip() if response.content else ""

        # OpenAI / OpenAI-compatible
        result = openai_text_with_usage(
            self.client,
            model=self.model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=self.llm_config.get_temperature(),
            max_output_tokens=max_out,
            max_tokens_fallback=max_out,
            preferred_endpoint=self.provider.preferred_endpoint,
        )
        self._record_usage(endpoint=result.endpoint, usage=result.usage, operation=operation)
        return result.text
    
    def generate_code(self, request: GeneratorRequest) -> GeneratorResponse:
        """
        Generate code from a specification with policy awareness.
        
        Args:
            request: GeneratorRequest with spec and optional policy IDs
            
        Returns:
            GeneratorResponse with generated code
        """
        # Get relevant policies
        policies = self._get_policy_context(request.policies)
        
        # Build the prompt
        system_prompt = self._build_generation_system_prompt(policies, request.language)
        user_prompt = f"""Generate {request.language} code for the following specification:

{request.spec}

Ensure the code follows all the security policies listed in your instructions.
Return ONLY the code, no explanations."""

        code = self._generate_text(system_prompt=system_prompt, user_prompt=user_prompt, operation="generate_code")
        
        # Clean up code (remove markdown fences if present)
        code = self._clean_code_response(code, request.language)
        
        return GeneratorResponse(
            code=code,
            analysis=[f"Generated {request.language} code following {len(policies)} policies"]
        )
    
    def fix_violations(self, code: str, violations: List[Violation], 
                       language: str = "python") -> str:
        """
        Fix code to resolve policy violations.
        
        Args:
            code: Original source code with violations
            violations: List of violations to fix
            language: Programming language
            
        Returns:
            Fixed code string
        """
        if not violations:
            return code
        
        # Build violation report for the prompt
        violation_report = self._format_violations(violations)
        
        # Get fix suggestions from policies
        fix_suggestions = self._get_fix_suggestions(violations)
        
        system_prompt = """You are a security-focused code remediation expert. Your task is to fix security violations in code while preserving its functionality.

Rules:
1. Fix ONLY the specific violations mentioned
2. Preserve the original code structure and logic
3. Use secure alternatives (environment variables, parameterized queries, etc.)
4. Do not add unnecessary code or comments
5. Return ONLY the fixed code, no explanations"""

        user_prompt = f"""Fix the following {language} code to resolve these security violations:

VIOLATIONS:
{violation_report}

SUGGESTED FIXES:
{fix_suggestions}

ORIGINAL CODE:
```{language}
{code}
```

        Return ONLY the fixed code, no explanations or markdown."""

        try:
            fixed_code = self._generate_text(system_prompt=system_prompt, user_prompt=user_prompt, operation="fix_violations")
            if not fixed_code:
                raise ValueError("LLM returned empty response")
            
            # Clean up response
            fixed_code = self._clean_code_response(fixed_code, language)
            
            return fixed_code
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            error_msg = str(e)
            error_type = type(e).__name__
            
            # Check for specific exception types first
            if "ConnectionError" in error_type or "ConnectTimeout" in error_type or "ConnectionRefusedError" in error_type:
                raise ValueError(f"LLM connection failed. Cannot reach {self.provider.name} at {self.llm_config.get_active_provider().base_url}. Is the service running? Error: {error_msg}")
            elif "Timeout" in error_type or "timeout" in error_msg.lower():
                raise ValueError(f"LLM request timed out. The service at {self.llm_config.get_active_provider().base_url} may be slow or overloaded. Error: {error_msg}")
            elif "api_key" in error_msg.lower() or "authentication" in error_msg.lower() or "401" in error_msg or "403" in error_msg:
                raise ValueError(f"LLM authentication failed. Check your API key configuration. Error: {error_msg}")
            elif "rate limit" in error_msg.lower() or "429" in error_msg:
                raise ValueError(f"LLM rate limit exceeded. Please try again later. Error: {error_msg}")
            elif "connection" in error_msg.lower() or "network" in error_msg.lower() or "NameResolutionError" in error_type:
                raise ValueError(f"LLM connection failed. Cannot reach {self.provider.name} at {self.llm_config.get_active_provider().base_url}. Check your network and LLM service configuration. Error: {error_msg}")
            elif "model" in error_msg.lower() and "not found" in error_msg.lower() or "404" in error_msg:
                raise ValueError(f"LLM model '{self.model}' not found. Check your LLM configuration. Error: {error_msg}")
            elif "streaming is required" in error_msg.lower():
                raise ValueError(
                    f"LLM request exceeded non-streaming limits for {self.provider.name}. "
                    "Set a smaller max_output_tokens (e.g., <= 4096) or use streaming-capable handling. "
                    f"Error: {error_msg}"
                )
            else:
                logger.error(f"LLM fix_violations error ({error_type}): {e}", exc_info=True)
                raise ValueError(f"Failed to fix code with LLM ({self.provider.name}): {error_msg}")
    
    def explain_fix(self, original: str, fixed: str, violations: List[Violation]) -> str:
        """
        Generate an explanation of the fixes applied.
        
        Args:
            original: Original code
            fixed: Fixed code
            violations: Violations that were addressed
            
        Returns:
            Human-readable explanation
        """
        violation_summary = "\n".join([
            f"- {v.rule_id}: {v.description} (line {v.line})"
            for v in violations
        ])
        
        prompt = f"""Explain the security fixes made to this code.

VIOLATIONS FIXED:
{violation_summary}

ORIGINAL CODE:
{original}

FIXED CODE:
{fixed}

Provide a brief, clear explanation of each fix."""

        # Explanations don't need a system prompt.
        return self._generate_text(system_prompt="", user_prompt=prompt, max_output_tokens=500, operation="explain_fix")
    
    def create_artifact_metadata(self, code: str, language: str, 
                                  name: Optional[str] = None) -> ArtifactMetadata:
        """
        Create metadata for a code artifact.
        
        Args:
            code: The code content
            language: Programming language
            name: Optional artifact name
            
        Returns:
            ArtifactMetadata with hash and provenance info
        """
        import hashlib
        
        # Ensure we record the active provider used at this time.
        try:
            self._refresh_llm()
        except Exception:
            # Fall back to settings/default metadata if LLM isn't configured.
            self.model_name = self.model_name or settings.OPENAI_MODEL

        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        return ArtifactMetadata(
            name=name,
            hash=code_hash,
            language=language,
            generator=f"ACPG-{self.model_name}",
            timestamp=datetime.utcnow()
        )
    
    def _get_policy_context(self, policy_ids: Optional[List[str]] = None) -> List[PolicyRule]:
        """Get policies to include in generation context."""
        if policy_ids:
            return [
                self.policy_compiler.get_policy(pid) 
                for pid in policy_ids 
                if self.policy_compiler.get_policy(pid)
            ]
        return self.policy_compiler.get_all_policies()
    
    def _build_generation_system_prompt(self, policies: List[PolicyRule], 
                                         language: str) -> str:
        """Build the system prompt for code generation."""
        policy_rules = "\n".join([
            f"- {p.id}: {p.description}" + 
            (f" (Fix: {p.fix_suggestion})" if p.fix_suggestion else "")
            for p in policies
        ])
        
        return f"""You are a secure code generation assistant. Generate {language} code that follows these security policies:

SECURITY POLICIES:
{policy_rules}

REQUIREMENTS:
1. Never hardcode credentials - use environment variables
2. Use parameterized queries for database operations
3. Validate and sanitize all inputs
4. Use secure cryptographic algorithms (SHA-256+)
5. Use HTTPS for external communications
6. Handle exceptions properly without exposing internals
7. Avoid eval(), exec(), and similar dangerous functions

Generate clean, secure, production-ready code."""
    
    def _format_violations(self, violations: List[Violation]) -> str:
        """Format violations for the prompt."""
        lines = []
        for v in violations:
            line_info = f" (line {v.line})" if v.line else ""
            evidence_info = f"\n  Evidence: {v.evidence}" if v.evidence else ""
            lines.append(f"- [{v.rule_id}] {v.description}{line_info}{evidence_info}")
        return "\n".join(lines)
    
    def _get_fix_suggestions(self, violations: List[Violation]) -> str:
        """Get fix suggestions from policy definitions."""
        suggestions = []
        seen_rules = set()
        
        for v in violations:
            if v.rule_id in seen_rules:
                continue
            seen_rules.add(v.rule_id)
            
            policy = self.policy_compiler.get_policy(v.rule_id)
            if policy and policy.fix_suggestion:
                suggestions.append(f"- {v.rule_id}: {policy.fix_suggestion}")
        
        return "\n".join(suggestions) if suggestions else "Apply security best practices."
    
    def _clean_code_response(self, code: str, language: str) -> str:
        """Remove markdown code fences from LLM response."""
        # Remove ```python or ```language prefix
        if code.startswith(f"```{language}"):
            code = code[len(f"```{language}"):].strip()
        elif code.startswith("```"):
            code = code[3:].strip()
            # Check if first line is the language identifier
            lines = code.split('\n')
            if lines and lines[0].strip().lower() in ['python', 'javascript', 'typescript', 'java', 'go']:
                code = '\n'.join(lines[1:])
        
        # Remove trailing ```
        if code.endswith("```"):
            code = code[:-3].strip()
        
        return code


# Global generator instance
_generator: Optional[Generator] = None


def get_generator() -> Generator:
    """Get or create the global generator instance."""
    global _generator
    if _generator is None:
        _generator = Generator()
    return _generator


def reset_generator():
    """Reset the global generator so it picks up new provider/client config."""
    global _generator
    _generator = None
