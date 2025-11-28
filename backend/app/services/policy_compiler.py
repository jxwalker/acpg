"""Policy Compiler Service - Load and compile policy rules into executable checks."""
import json
import re
from pathlib import Path
from typing import Dict, List, Callable, Optional, Any
from functools import lru_cache

from ..models.schemas import PolicyRule, PolicyCheck, PolicySet, Violation
from ..core.config import settings


class PolicyCompiler:
    """
    Compiles policy definitions from JSON into an executable knowledge base.
    
    Responsibilities:
    - Load policies from JSON files
    - Validate rule definitions
    - Create executable check functions from patterns
    - Maintain policy knowledge base for runtime queries
    """
    
    def __init__(self):
        self._policies: Dict[str, PolicyRule] = {}
        self._compiled_checks: Dict[str, Callable] = {}
    
    def load_policies(self, path: Optional[Path] = None) -> PolicySet:
        """
        Load policies from a JSON file.
        
        Args:
            path: Path to JSON file. Defaults to settings.POLICIES_DIR / settings.DEFAULT_POLICIES_FILE
            
        Returns:
            PolicySet containing all loaded policies
        """
        if path is None:
            path = settings.POLICIES_DIR / settings.DEFAULT_POLICIES_FILE
        
        with open(path, 'r') as f:
            data = json.load(f)
        
        policies = []
        for policy_data in data.get('policies', []):
            # Parse the check definition
            check_data = policy_data.get('check', {})
            check = PolicyCheck(
                type=check_data.get('type', 'manual'),
                pattern=check_data.get('pattern'),
                function=check_data.get('function'),
                target=check_data.get('target'),
                message=check_data.get('message'),
                languages=check_data.get('languages', [])
            )
            
            # Create the policy rule
            policy = PolicyRule(
                id=policy_data['id'],
                description=policy_data['description'],
                type=policy_data.get('type', 'strict'),
                severity=policy_data.get('severity', 'medium'),
                check=check,
                fix_suggestion=policy_data.get('fix_suggestion')
            )
            
            # Validate and store
            if self.validate_rule(policy):
                self._policies[policy.id] = policy
                self._compile_check(policy)
                policies.append(policy)
        
        return PolicySet(policies=policies)
    
    def validate_rule(self, rule: PolicyRule) -> bool:
        """
        Validate a policy rule definition.
        
        Args:
            rule: The policy rule to validate
            
        Returns:
            True if valid, raises ValueError if invalid
        """
        # Check required fields
        if not rule.id or not rule.description:
            raise ValueError(f"Policy rule must have id and description")
        
        # Validate check type
        if rule.check.type not in ('regex', 'ast', 'manual'):
            raise ValueError(f"Invalid check type: {rule.check.type}")
        
        # Regex checks must have a pattern
        if rule.check.type == 'regex' and not rule.check.pattern:
            raise ValueError(f"Regex check must have a pattern: {rule.id}")
        
        # Validate regex pattern compiles
        if rule.check.type == 'regex' and rule.check.pattern:
            try:
                re.compile(rule.check.pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern in {rule.id}: {e}")
        
        # Validate severity
        if rule.severity not in ('low', 'medium', 'high', 'critical'):
            raise ValueError(f"Invalid severity: {rule.severity}")
        
        # Validate type
        if rule.type not in ('strict', 'defeasible'):
            raise ValueError(f"Invalid rule type: {rule.type}")
        
        return True
    
    def _compile_check(self, rule: PolicyRule) -> None:
        """
        Compile a policy rule into an executable check function.
        
        The compiled function takes (code: str, language: str) and returns
        a list of Violation objects.
        """
        if rule.check.type == 'regex':
            self._compiled_checks[rule.id] = self._create_regex_checker(rule)
        elif rule.check.type == 'ast':
            self._compiled_checks[rule.id] = self._create_ast_checker(rule)
        else:
            # Manual checks return empty - they require human review
            self._compiled_checks[rule.id] = lambda code, lang: []
    
    def _create_regex_checker(self, rule: PolicyRule) -> Callable[[str, str], List[Violation]]:
        """Create a regex-based check function."""
        pattern = re.compile(rule.check.pattern, re.MULTILINE | re.IGNORECASE)
        languages = rule.check.languages
        
        def check(code: str, language: str) -> List[Violation]:
            # Skip if language not applicable
            if languages and language.lower() not in [l.lower() for l in languages]:
                return []
            
            violations = []
            lines = code.split('\n')
            
            for line_num, line in enumerate(lines, start=1):
                matches = pattern.finditer(line)
                for match in matches:
                    violations.append(Violation(
                        rule_id=rule.id,
                        description=rule.description,
                        line=line_num,
                        evidence=match.group(0),
                        detector="regex",
                        severity=rule.severity
                    ))
            
            return violations
        
        return check
    
    def _create_ast_checker(self, rule: PolicyRule) -> Callable[[str, str], List[Violation]]:
        """Create an AST-based check function (placeholder for now)."""
        # AST checking would require parsing the code
        # For now, we'll implement basic pattern matching on the target
        target_pattern = rule.check.target
        
        def check(code: str, language: str) -> List[Violation]:
            if language.lower() != 'python':
                return []
            
            violations = []
            # Simple heuristic: look for print/log statements containing sensitive vars
            if target_pattern:
                sensitive_pattern = re.compile(
                    rf'(print|logging\.\w+|logger\.\w+)\s*\([^)]*({target_pattern})[^)]*\)',
                    re.IGNORECASE | re.MULTILINE
                )
                
                lines = code.split('\n')
                for line_num, line in enumerate(lines, start=1):
                    if sensitive_pattern.search(line):
                        violations.append(Violation(
                            rule_id=rule.id,
                            description=rule.description,
                            line=line_num,
                            evidence=line.strip(),
                            detector="ast",
                            severity=rule.severity
                        ))
            
            return violations
        
        return check
    
    def run_check(self, rule_id: str, code: str, language: str = "python") -> List[Violation]:
        """
        Run a specific policy check against code.
        
        Args:
            rule_id: ID of the policy to check
            code: Source code to analyze
            language: Programming language of the code
            
        Returns:
            List of violations found
        """
        if rule_id not in self._compiled_checks:
            raise ValueError(f"Unknown policy rule: {rule_id}")
        
        return self._compiled_checks[rule_id](code, language)
    
    def run_all_checks(self, code: str, language: str = "python", 
                       policy_ids: Optional[List[str]] = None) -> List[Violation]:
        """
        Run all applicable policy checks against code.
        
        Args:
            code: Source code to analyze
            language: Programming language of the code
            policy_ids: Optional list of policy IDs to check (None = all)
            
        Returns:
            List of all violations found
        """
        all_violations = []
        
        policies_to_check = policy_ids if policy_ids else list(self._compiled_checks.keys())
        
        for rule_id in policies_to_check:
            if rule_id in self._compiled_checks:
                violations = self._compiled_checks[rule_id](code, language)
                all_violations.extend(violations)
        
        return all_violations
    
    def get_policy(self, rule_id: str) -> Optional[PolicyRule]:
        """Get a policy rule by ID."""
        return self._policies.get(rule_id)
    
    def get_all_policies(self) -> List[PolicyRule]:
        """Get all loaded policy rules."""
        return list(self._policies.values())
    
    def get_strict_policies(self) -> List[PolicyRule]:
        """Get all strict (non-defeasible) policies."""
        return [p for p in self._policies.values() if p.type == 'strict']
    
    def get_defeasible_policies(self) -> List[PolicyRule]:
        """Get all defeasible policies."""
        return [p for p in self._policies.values() if p.type == 'defeasible']
    
    def get_policies_by_severity(self, severity: str) -> List[PolicyRule]:
        """Get policies filtered by severity level."""
        return [p for p in self._policies.values() if p.severity == severity]
    
    def get_knowledge_base(self) -> Dict[str, Any]:
        """
        Get the full policy knowledge base for the adjudicator.
        
        Returns a dictionary with:
        - policies: Dict of policy rules
        - strict_rules: List of strict rule IDs
        - defeasible_rules: List of defeasible rule IDs
        - severity_order: Priority ordering by severity
        """
        return {
            'policies': self._policies,
            'strict_rules': [p.id for p in self.get_strict_policies()],
            'defeasible_rules': [p.id for p in self.get_defeasible_policies()],
            'severity_order': ['critical', 'high', 'medium', 'low'],
            'severity_map': {p.id: p.severity for p in self._policies.values()}
        }


# Global compiler instance
_compiler: Optional[PolicyCompiler] = None


def get_policy_compiler() -> PolicyCompiler:
    """Get or create the global policy compiler instance."""
    global _compiler
    if _compiler is None:
        _compiler = PolicyCompiler()
        # Load default policies
        _compiler.load_policies()
        
        # Load additional policy files if they exist
        additional_files = ['owasp_policies.json', 'nist_policies.json']
        for filename in additional_files:
            filepath = settings.POLICIES_DIR / filename
            if filepath.exists():
                try:
                    _compiler.load_policies(filepath)
                except Exception as e:
                    print(f"Warning: Could not load {filename}: {e}")
    return _compiler

