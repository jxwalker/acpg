"""Generator Service - AI-powered code generation and fixing using configurable LLMs."""
import json
from typing import List, Optional, Dict, Any
from datetime import datetime

from openai import OpenAI

from ..models.schemas import (
    GeneratorRequest, GeneratorResponse, FixRequest,
    Violation, PolicyRule, ArtifactMetadata
)
from ..core.config import settings
from ..core.llm_config import get_llm_config, get_llm_client
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
        self.client = get_llm_client()
        self.model = self.llm_config.get_model()
        self.policy_compiler = get_policy_compiler()
        
        # Log which LLM we're using
        provider = self.llm_config.get_active_provider()
        print(f"🤖 Generator using: {provider.name} ({provider.model})")
    
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

        # Call LLM
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=self.llm_config.get_temperature(),
            max_tokens=self.llm_config.get_max_tokens()
        )
        
        code = response.choices[0].message.content.strip()
        
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

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=self.llm_config.get_temperature(),
            max_tokens=self.llm_config.get_max_tokens()
        )
        
        fixed_code = response.choices[0].message.content.strip()
        
        # Clean up response
        fixed_code = self._clean_code_response(fixed_code, language)
        
        return fixed_code
    
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

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.5,
            max_tokens=500
        )
        
        return response.choices[0].message.content.strip()
    
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
        
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        return ArtifactMetadata(
            name=name,
            hash=code_hash,
            language=language,
            generator=f"ACPG-Generator-{self.model}",
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

