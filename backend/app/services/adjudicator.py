"""Adjudicator Service - Argumentation-based compliance decision engine.

Implements Dung's Abstract Argumentation Framework with grounded semantics
to make formal compliance decisions based on competing arguments.
"""
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

from ..models.schemas import (
    Argument, Attack, ArgumentationGraph, AdjudicationResult,
    Violation, PolicyRule, AnalysisResult
)
from .policy_compiler import get_policy_compiler


@dataclass
class ArgumentNode:
    """Internal representation of an argument node."""
    id: str
    rule_id: str
    arg_type: str  # 'compliance', 'violation', 'exception', 'priority'
    evidence: Optional[str] = None
    details: Optional[str] = None
    attackers: Set[str] = field(default_factory=set)
    attacks: Set[str] = field(default_factory=set)


class Adjudicator:
    """
    The Adjudicator resolves compliance using formal argumentation.
    
    Implements Dung's Abstract Argumentation Framework:
    - Arguments: Claims about compliance or violation
    - Attacks: Relationships where one argument defeats another
    - Grounded Semantics: Computes the minimal defensible set of arguments
    
    Argument Types:
    - Compliance (C): "Artifact complies with rule R"
    - Violation (V): "Artifact violates rule R under scenario S"
    - Exception (E): "Exception condition applies, defeating violation"
    - Priority (H): "Higher priority rule overrides lower priority"
    """
    
    def __init__(self):
        self.policy_compiler = get_policy_compiler()
    
    def adjudicate(self, analysis: AnalysisResult, 
                   policy_ids: Optional[List[str]] = None) -> AdjudicationResult:
        """
        Make a compliance decision based on analysis results.
        
        Args:
            analysis: AnalysisResult from prosecutor
            policy_ids: Optional list of policies to consider
            
        Returns:
            AdjudicationResult with compliance decision and reasoning
        """
        # Build argumentation graph
        graph = self.build_argumentation_graph(analysis.violations, policy_ids)
        
        # Compute grounded extension
        accepted = self.compute_grounded_extension(graph)
        
        # Determine compliance
        violation_args = [a for a in graph.arguments if a.type == 'violation']
        accepted_violations = [a for a in violation_args if a.id in accepted]
        
        # Get satisfied and unsatisfied rules
        kb = self.policy_compiler.get_knowledge_base()
        all_policies = policy_ids if policy_ids else list(kb['policies'].keys())
        
        violated_rules = set(a.rule_id for a in accepted_violations)
        satisfied_rules = [r for r in all_policies if r not in violated_rules]
        unsatisfied_rules = list(violated_rules)
        
        # Build reasoning trace
        reasoning = self._build_reasoning_trace(graph, accepted, accepted_violations)
        
        return AdjudicationResult(
            compliant=len(accepted_violations) == 0,
            unsatisfied_rules=unsatisfied_rules,
            satisfied_rules=satisfied_rules,
            reasoning=reasoning
        )
    
    def build_argumentation_graph(self, violations: List[Violation],
                                   policy_ids: Optional[List[str]] = None) -> ArgumentationGraph:
        """
        Build an argumentation graph from violations and policies.
        
        The graph structure:
        - For each policy: Create compliance argument C_r
        - For each violation: Create violation argument V_r that attacks C_r
        - For defeasible rules: Create exception arguments E that attack V
        - For priority conflicts: Create priority arguments H that attack lower priority V
        """
        arguments: List[Argument] = []
        attacks: List[Attack] = []
        
        kb = self.policy_compiler.get_knowledge_base()
        policies_to_check = policy_ids if policy_ids else list(kb['policies'].keys())
        
        # Track which rules have violations
        violation_map: Dict[str, List[Violation]] = {}
        for v in violations:
            if v.rule_id not in violation_map:
                violation_map[v.rule_id] = []
            violation_map[v.rule_id].append(v)
        
        # Create arguments for each policy
        for rule_id in policies_to_check:
            policy = kb['policies'].get(rule_id)
            if not policy:
                continue
            
            # Create compliance argument
            compliance_arg = Argument(
                id=f"C_{rule_id}",
                rule_id=rule_id,
                type="compliance",
                details=f"Artifact complies with {rule_id}: {policy.description}"
            )
            arguments.append(compliance_arg)
            
            # If there are violations for this rule, create violation arguments
            if rule_id in violation_map:
                for i, v in enumerate(violation_map[rule_id]):
                    violation_arg = Argument(
                        id=f"V_{rule_id}_{i}",
                        rule_id=rule_id,
                        type="violation",
                        evidence=v.evidence,
                        details=f"Violation of {rule_id} at line {v.line}: {v.description}"
                    )
                    arguments.append(violation_arg)
                    
                    # Violation attacks compliance
                    attacks.append(Attack(
                        attacker=violation_arg.id,
                        target=compliance_arg.id
                    ))
                    
                    # For defeasible rules, check for exception conditions
                    if policy.type == 'defeasible':
                        exception_arg = self._check_exceptions(rule_id, v, len(arguments))
                        if exception_arg:
                            arguments.append(exception_arg)
                            # Exception attacks the violation
                            attacks.append(Attack(
                                attacker=exception_arg.id,
                                target=violation_arg.id
                            ))
        
        # Add priority-based attacks between violations of different rules
        priority_attacks = self._compute_priority_attacks(arguments, kb)
        attacks.extend(priority_attacks)
        
        return ArgumentationGraph(arguments=arguments, attacks=attacks)
    
    def compute_grounded_extension(self, graph: ArgumentationGraph) -> Set[str]:
        """
        Compute the grounded extension using fixpoint iteration.
        
        The grounded extension is the minimal complete extension,
        containing only arguments that must be accepted.
        
        Algorithm:
        1. Start with unattacked arguments (they must be accepted)
        2. Remove arguments attacked by accepted arguments
        3. Repeat until no changes
        """
        # Build internal graph structure
        nodes: Dict[str, ArgumentNode] = {}
        for arg in graph.arguments:
            nodes[arg.id] = ArgumentNode(
                id=arg.id,
                rule_id=arg.rule_id,
                arg_type=arg.type,
                evidence=arg.evidence,
                details=arg.details
            )
        
        for attack in graph.attacks:
            if attack.attacker in nodes and attack.target in nodes:
                nodes[attack.target].attackers.add(attack.attacker)
                nodes[attack.attacker].attacks.add(attack.target)
        
        # Compute grounded extension via characteristic function iteration
        accepted: Set[str] = set()
        rejected: Set[str] = set()
        
        changed = True
        while changed:
            changed = False
            
            for arg_id, node in nodes.items():
                if arg_id in accepted or arg_id in rejected:
                    continue
                
                # Check if all attackers are rejected
                all_attackers_rejected = all(
                    attacker in rejected 
                    for attacker in node.attackers
                )
                
                if all_attackers_rejected:
                    # Accept this argument
                    accepted.add(arg_id)
                    changed = True
                    
                    # Reject all arguments this one attacks
                    for target in node.attacks:
                        if target not in rejected:
                            rejected.add(target)
                            changed = True
        
        return accepted
    
    def generate_guidance(self, analysis: AnalysisResult) -> str:
        """
        Generate guidance for the generator to fix violations.
        
        Prioritizes fixes based on:
        1. Severity (critical > high > medium > low)
        2. Rule type (strict before defeasible)
        3. Margin to compliance
        """
        kb = self.policy_compiler.get_knowledge_base()
        severity_order = kb['severity_order']
        
        # Sort violations by priority
        def violation_priority(v: Violation) -> Tuple[int, int, str]:
            policy = kb['policies'].get(v.rule_id)
            severity_rank = severity_order.index(v.severity) if v.severity in severity_order else 99
            type_rank = 0 if policy and policy.type == 'strict' else 1
            return (severity_rank, type_rank, v.rule_id)
        
        sorted_violations = sorted(analysis.violations, key=violation_priority)
        
        # Build guidance
        lines = ["COMPLIANCE GUIDANCE:", "=" * 40, ""]
        lines.append(f"Found {len(sorted_violations)} violation(s) to address:")
        lines.append("")
        
        for i, v in enumerate(sorted_violations, 1):
            policy = kb['policies'].get(v.rule_id)
            type_label = "STRICT" if policy and policy.type == 'strict' else "DEFEASIBLE"
            
            lines.append(f"{i}. [{v.severity.upper()}] [{type_label}] {v.rule_id}")
            lines.append(f"   Issue: {v.description}")
            if v.line:
                lines.append(f"   Location: Line {v.line}")
            if v.evidence:
                lines.append(f"   Evidence: {v.evidence}")
            if policy and policy.fix_suggestion:
                lines.append(f"   Suggested Fix: {policy.fix_suggestion}")
            lines.append("")
        
        lines.append("=" * 40)
        lines.append("Address violations in order of priority (highest severity first).")
        
        return "\n".join(lines)
    
    def _check_exceptions(self, rule_id: str, violation: Violation, 
                          arg_count: int) -> Optional[Argument]:
        """
        Check if an exception condition applies to a defeasible rule violation.
        
        This is a simplified implementation. In a full system, this would:
        - Parse exception conditions from policy definitions
        - Check artifact metadata for exception applicability
        - Support custom exception logic
        """
        # For now, we don't have automatic exception detection
        # This would be extended based on policy definitions
        # Example: INPUT-001 might have exceptions for internal APIs
        
        return None
    
    def _compute_priority_attacks(self, arguments: List[Argument],
                                   kb: Dict[str, Any]) -> List[Attack]:
        """
        Compute attacks based on rule priorities.
        
        Higher severity violations can attack (override) lower severity ones
        when they conflict.
        """
        attacks = []
        severity_order = kb['severity_order']
        
        # Get violation arguments
        violation_args = [a for a in arguments if a.type == 'violation']
        
        # For conflicting rules, higher priority attacks lower
        # (This is simplified - real implementation would check for actual conflicts)
        
        return attacks
    
    def _build_reasoning_trace(self, graph: ArgumentationGraph,
                                accepted: Set[str],
                                accepted_violations: List[Argument]) -> List[Dict[str, Any]]:
        """Build a human-readable reasoning trace."""
        trace = []
        
        # Document accepted arguments
        for arg in graph.arguments:
            status = "accepted" if arg.id in accepted else "rejected"
            trace.append({
                "argument": arg.id,
                "type": arg.type,
                "rule": arg.rule_id,
                "status": status,
                "details": arg.details
            })
        
        # Document attacks
        for attack in graph.attacks:
            attacker_accepted = attack.attacker in accepted
            trace.append({
                "attack": f"{attack.attacker} → {attack.target}",
                "effective": attacker_accepted,
                "explanation": f"{'Successful' if attacker_accepted else 'Defeated'} attack"
            })
        
        # Summary
        if accepted_violations:
            trace.append({
                "conclusion": "Non-compliant",
                "reason": f"{len(accepted_violations)} violation argument(s) accepted",
                "violations": [a.rule_id for a in accepted_violations]
            })
        else:
            trace.append({
                "conclusion": "Compliant",
                "reason": "No violation arguments accepted",
                "violations": []
            })
        
        return trace


# Global adjudicator instance
_adjudicator: Optional[Adjudicator] = None


def get_adjudicator() -> Adjudicator:
    """Get or create the global adjudicator instance."""
    global _adjudicator
    if _adjudicator is None:
        _adjudicator = Adjudicator()
    return _adjudicator

