"""Adjudicator Service - Argumentation-based compliance decision engine.

Implements Dung's Abstract Argumentation Framework with grounded semantics
to make formal compliance decisions based on competing arguments.
"""
import shutil
from typing import List, Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

from ..models.schemas import (
    Argument, Attack, ArgumentationGraph, AdjudicationResult,
    Violation, PolicyRule, AnalysisResult
)
from .policy_compiler import get_policy_compiler
from .tool_reliability import get_reliability_checker
from .argumentation_asp import compute_stable_extensions, compute_preferred_extensions


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
    # Joint attacks against this node: each entry is a set of attacker IDs.
    joint_attackers: List[Set[str]] = field(default_factory=list)


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
        self.reliability_checker = get_reliability_checker()
    
    def adjudicate(
        self,
        analysis: AnalysisResult,
        policy_ids: Optional[List[str]] = None,
        semantics: str = "grounded",
    ) -> AdjudicationResult:
        """
        Make a compliance decision based on analysis results.
        
        Args:
            analysis: AnalysisResult from prosecutor
            policy_ids: Optional list of policies to consider
            
        Returns:
            AdjudicationResult with compliance decision and reasoning
        """
        requested_semantics = (semantics or "grounded").lower()
        semantics = requested_semantics
        if semantics == "auto":
            # Auto: always decide with grounded (skeptical, deterministic),
            # and optionally compute other semantics as additional evidence.
            semantics = "grounded"

        # Build argumentation graph
        graph = self.build_argumentation_graph(analysis.violations, policy_ids)
        
        # Compute extension
        if semantics != "grounded":
            # Stable/preferred semantics are NP-hard in general; we treat them as optional
            # and require an external solver integration (planned).
            raise ValueError(
                f"Unsupported semantics '{semantics}' in this build. "
                "Supported: grounded, auto. Planned: stable, preferred (via ASP/clingo)."
            )

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

        secondary_semantics = None
        if requested_semantics == "auto":
            secondary_semantics = self._auto_secondary_semantics(graph)
            reasoning.insert(
                0,
                {
                    "phase": "semantics_selection",
                    "requested": requested_semantics,
                    "decision_semantics": semantics,
                    "secondary_semantics": secondary_semantics,
                    "description": (
                        "AUTO mode decides using grounded semantics for conservative compliance. "
                        "Other semantics may be computed as additional evidence when a solver is available."
                    ),
                },
            )
        
        return AdjudicationResult(
            semantics=semantics,
            secondary_semantics=secondary_semantics,
            compliant=len(accepted_violations) == 0,
            unsatisfied_rules=unsatisfied_rules,
            satisfied_rules=satisfied_rules,
            reasoning=reasoning
        )

    def _auto_secondary_semantics(self, graph: ArgumentationGraph) -> Dict[str, Any]:
        """Optional cross-checks under other semantics (preferred/stable).

        This is intentionally best-effort: if no solver is available, it returns a skipped status.
        """
        # We currently do not ship a solver; we only detect availability so proofs are explicit.
        # Future: export AF to ASP and compute stable/preferred extensions via clingo.
        clingo_path = shutil.which("clingo")
        if not clingo_path:
            return {
                "enabled": False,
                "reason": "clingo not available; skipping stable/preferred cross-checks",
                "stable": None,
                "preferred": None,
            }

        result: Dict[str, Any] = {
            "enabled": True,
            "clingo_path": clingo_path,
            "stable": None,
            "preferred": None,
            "errors": [],
        }

        # Stable semantics cross-check
        try:
            stable = compute_stable_extensions(graph, clingo_path=clingo_path)
            result["stable"] = {
                "extensions": stable.extensions,
                "count": len(stable.extensions),
            }
        except Exception as e:
            result["errors"].append({"semantics": "stable", "error": str(e)})

        # Preferred semantics cross-check (not yet implemented)
        try:
            pref = compute_preferred_extensions(graph, clingo_path=clingo_path)
            result["preferred"] = {
                "extensions": pref.extensions,
                "count": len(pref.extensions),
            }
        except NotImplementedError as e:
            result["preferred"] = {"enabled": False, "reason": str(e)}
        except Exception as e:
            result["errors"].append({"semantics": "preferred", "error": str(e)})

        return result
    
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
                    
                    # Check for exception conditions (defeasible rules or tool reliability)
                    exception_arg = None
                    if policy.type == 'defeasible':
                        exception_arg = self._check_exceptions(rule_id, v, len(arguments))
                    
                    # Check for tool reliability exceptions (applies to all violations from tools)
                    tool_exception = self._check_tool_reliability(v, len(arguments))
                    if tool_exception:
                        # Tool reliability exception takes precedence
                        exception_arg = tool_exception
                    
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

        # Joint attacks (Nielsen & Parsons style): a set of attackers jointly defeats a target.
        # A joint attack is effective when *all* attackers in the set are accepted.
        for set_attack in getattr(graph, "set_attacks", []) or []:
            if set_attack.target in nodes:
                attackers = set(a for a in set_attack.attackers if a in nodes)
                if attackers:
                    nodes[set_attack.target].joint_attackers.append(attackers)
        
        # Compute grounded extension via characteristic function iteration
        accepted: Set[str] = set()
        rejected: Set[str] = set()
        
        changed = True
        while changed:
            changed = False
            
            for arg_id, node in nodes.items():
                if arg_id in accepted or arg_id in rejected:
                    continue
                
                # Accept when:
                # - all individual attackers are rejected
                # - and every joint attack set is "broken" (at least one member is rejected)
                all_attackers_rejected = all(attacker in rejected for attacker in node.attackers)
                all_joint_attacks_broken = all(
                    any(attacker in rejected for attacker in attacker_set)
                    for attacker_set in node.joint_attackers
                )
                
                if all_attackers_rejected and all_joint_attacks_broken:
                    # Accept this argument
                    accepted.add(arg_id)
                    changed = True
                    
                    # Reject all arguments this one attacks
                    for target in node.attacks:
                        if target not in rejected:
                            rejected.add(target)
                            changed = True

                    # Reject targets of any joint attacks that are now fully satisfied
                    # (i.e., the entire attacker set is accepted).
                    for tgt_id, tgt_node in nodes.items():
                        if tgt_id in accepted or tgt_id in rejected:
                            continue
                        if any(attacker_set.issubset(accepted) for attacker_set in tgt_node.joint_attackers):
                            rejected.add(tgt_id)
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
    
    def _check_tool_reliability(self, violation: Violation, 
                                arg_count: int) -> Optional[Argument]:
        """
        Check if a tool finding is unreliable and should be defeated by exception.
        
        Args:
            violation: Violation to check
            arg_count: Current argument count (for ID generation)
            
        Returns:
            Exception argument if finding is unreliable, None otherwise
        """
        # Extract tool information from violation
        tool_name = violation.detector if violation.detector not in ("regex", "ast") else None
        if not tool_name:
            return None
        
        # Check reliability (we don't have tool_version/confidence in Violation model yet,
        # but we can check patterns)
        reliability_exception = self.reliability_checker.check_reliability(
            violation=violation,
            tool_name=tool_name,
            tool_version=None,  # TODO: Add to Violation model
            confidence=None     # TODO: Add to Violation model
        )
        
        if reliability_exception:
            exception_id = f"E_TOOL_{violation.rule_id}_{arg_count}"
            return Argument(
                id=exception_id,
                rule_id=violation.rule_id,
                type="exception",
                evidence=reliability_exception.details,
                details=f"Tool reliability exception: {reliability_exception.reason}. "
                       f"{reliability_exception.details}"
            )
        
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
        """Build a human-readable reasoning trace with formal logic steps."""
        trace = []
        
        # Step 1: Framework Definition
        trace.append({
            "step": 1,
            "phase": "framework_definition",
            "title": "Argumentation Framework Definition",
            "description": "Constructing an Abstract Argumentation Framework (Args, Attacks), with optional joint attacks",
            "details": {
                "total_arguments": len(graph.arguments),
                "total_attacks": len(graph.attacks) + len(getattr(graph, "set_attacks", []) or []),
                "binary_attacks": len(graph.attacks),
                "joint_attacks": len(getattr(graph, "set_attacks", []) or []),
                "argument_types": {
                    "compliance": len([a for a in graph.arguments if a.type == "compliance"]),
                    "violation": len([a for a in graph.arguments if a.type == "violation"]),
                    "exception": len([a for a in graph.arguments if a.type == "exception"])
                }
            }
        })
        
        # Step 2: Arguments enumeration
        arguments_by_type = {"compliance": [], "violation": [], "exception": []}
        for arg in graph.arguments:
            status = "accepted" if arg.id in accepted else "rejected"
            arg_entry = {
                "id": arg.id,
                "type": arg.type,
                "rule": arg.rule_id,
                "status": status,
                "claim": arg.details,
                "evidence": arg.evidence
            }
            arguments_by_type.get(arg.type, []).append(arg_entry)
        
        trace.append({
            "step": 2,
            "phase": "arguments",
            "title": "Argument Construction",
            "description": "For each policy P and evidence E, construct arguments:",
            "logic": [
                "∀ policy P: Create compliance argument C_P claiming 'artifact satisfies P'",
                "∀ violation V of policy P: Create violation argument V_P attacking C_P",
                "∀ exception E defeating V: Create exception argument E defeating V"
            ],
            "arguments": arguments_by_type
        })
        
        # Step 3: Attack Relations
        attack_list = []
        for attack in graph.attacks:
            attacker_accepted = attack.attacker in accepted
            attacker_arg = next((a for a in graph.arguments if a.id == attack.attacker), None)
            target_arg = next((a for a in graph.arguments if a.id == attack.target), None)
            
            attack_list.append({
                "attacker": attack.attacker,
                "target": attack.target,
                "attacker_type": attacker_arg.type if attacker_arg else "unknown",
                "target_type": target_arg.type if target_arg else "unknown",
                "effective": attacker_accepted,
                "reason": self._explain_attack(attacker_arg, target_arg, attacker_accepted)
            })

        # Joint attacks: effective iff all attackers in the set are accepted
        for set_attack in getattr(graph, "set_attacks", []) or []:
            attackers = list(set_attack.attackers or [])
            effective = all(a in accepted for a in attackers)
            attack_list.append({
                "attacker": attackers,
                "target": set_attack.target,
                "attacker_type": "joint",
                "target_type": next((a.type for a in graph.arguments if a.id == set_attack.target), "unknown"),
                "effective": effective,
                "reason": (
                    "Joint attack succeeds when all attackers are accepted"
                    if effective else
                    "Joint attack defeated because at least one attacker was rejected"
                )
            })
        
        trace.append({
            "step": 3,
            "phase": "attacks",
            "title": "Attack Relation Construction",
            "description": "Define attack relations between arguments:",
            "logic": [
                "Violation V_P attacks Compliance C_P (evidence contradicts compliance claim)",
                "Exception E attacks Violation V (exception condition defeats violation)",
                "Joint attacks: a set of attackers jointly defeats a target (Nielsen & Parsons style)",
                "Higher priority arguments attack lower priority ones"
            ],
            "attacks": attack_list
        })
        
        # Step 4: Grounded Extension Computation
        trace.append({
            "step": 4,
            "phase": "grounded_extension",
            "title": "Grounded Extension Computation",
            "description": "Computing the grounded extension using fixpoint iteration:",
            "algorithm": [
                "1. Initialize: accepted = ∅, rejected = ∅",
                "2. Find unattacked arguments → add to accepted",
                "3. Arguments attacked by accepted → add to rejected",
                "4. Repeat until fixpoint (no changes)",
                "5. Result: minimal complete extension"
            ],
            "result": {
                "accepted": list(accepted),
                "rejected": [a.id for a in graph.arguments if a.id not in accepted],
                "accepted_count": len(accepted),
                "rejected_count": len(graph.arguments) - len(accepted)
            }
        })
        
        # Step 5: Compliance Decision
        violated_rules = list(set(a.rule_id for a in accepted_violations))
        satisfied_rules = list(set(
            a.rule_id for a in graph.arguments 
            if a.type == "compliance" and a.id in accepted
        ))
        
        trace.append({
            "step": 5,
            "phase": "decision",
            "title": "Compliance Decision",
            "description": "Deriving compliance decision from grounded extension:",
            "logic": [
                "IF ∃ accepted violation argument V_P THEN artifact violates policy P",
                "IF ∀ policies P: C_P ∈ accepted THEN artifact is COMPLIANT",
                "ELSE artifact is NON-COMPLIANT"
            ],
            "decision": "COMPLIANT" if not accepted_violations else "NON-COMPLIANT",
            "satisfied_policies": satisfied_rules,
            "violated_policies": violated_rules,
            "reasoning": self._explain_decision(accepted_violations, satisfied_rules)
        })
        
        # Legacy format for backwards compatibility
        for arg in graph.arguments:
            status = "accepted" if arg.id in accepted else "rejected"
            trace.append({
                "argument": arg.id,
                "type": arg.type,
                "rule": arg.rule_id,
                "status": status,
                "details": arg.details,
                "evidence": arg.evidence
            })
        
        for attack in graph.attacks:
            attacker_accepted = attack.attacker in accepted
            trace.append({
                "attack": f"{attack.attacker} → {attack.target}",
                "effective": attacker_accepted,
                "explanation": f"{'Successful' if attacker_accepted else 'Defeated'} attack"
            })

        for set_attack in getattr(graph, "set_attacks", []) or []:
            attackers = list(set_attack.attackers or [])
            effective = all(a in accepted for a in attackers)
            trace.append({
                "attack": f"{{{', '.join(attackers)}}} → {set_attack.target}",
                "attackers": attackers,
                "target": set_attack.target,
                "effective": effective,
                "explanation": (
                    "Successful joint attack (all attackers accepted)"
                    if effective else
                    "Defeated joint attack (at least one attacker rejected)"
                )
            })
        
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
    
    def _explain_attack(self, attacker: Optional[Argument], target: Optional[Argument], 
                        effective: bool) -> str:
        """Generate human-readable explanation for an attack."""
        if not attacker or not target:
            return "Unknown attack relation"
        
        if attacker.type == "violation" and target.type == "compliance":
            if effective:
                return f"Violation evidence at line {attacker.evidence or 'N/A'} defeats compliance claim"
            else:
                return "Violation was defeated by exception or higher priority argument"
        elif attacker.type == "exception" and target.type == "violation":
            if effective:
                return "Exception condition applies, defeating the violation"
            else:
                return "Exception was overridden"
        else:
            return f"{'Effective' if effective else 'Ineffective'} attack"
    
    def _explain_decision(self, violations: List[Argument], satisfied: List[str]) -> str:
        """Generate human-readable explanation for the decision."""
        if not violations:
            return f"All {len(satisfied)} policies are satisfied. No violation arguments were accepted in the grounded extension."
        else:
            rules = list(set(v.rule_id for v in violations))
            return f"Violation arguments for {rules} were accepted in the grounded extension, indicating policy violations."


# Global adjudicator instance
_adjudicator: Optional[Adjudicator] = None


def get_adjudicator() -> Adjudicator:
    """Get or create the global adjudicator instance."""
    global _adjudicator
    if _adjudicator is None:
        _adjudicator = Adjudicator()
    return _adjudicator
