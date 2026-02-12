"""Data models for ACPG system."""
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime


class PolicyCheck(BaseModel):
    """Definition of how to check a policy rule."""
    type: Literal["regex", "ast", "manual"]
    pattern: Optional[str] = None
    function: Optional[str] = None
    target: Optional[str] = None
    message: Optional[str] = None
    languages: List[str] = Field(default_factory=list)


class PolicyRule(BaseModel):
    """A compliance policy rule."""
    id: str
    description: str
    type: Literal["strict", "defeasible"]
    severity: Literal["low", "medium", "high", "critical"]
    check: PolicyCheck
    fix_suggestion: Optional[str] = None


class PolicySet(BaseModel):
    """Collection of policy rules."""
    policies: List[PolicyRule]


class Violation(BaseModel):
    """A policy violation found in code."""
    rule_id: str
    description: str
    line: Optional[int] = None
    evidence: Optional[str] = None
    detector: str
    severity: str


class ToolExecutionInfo(BaseModel):
    """Information about tool execution."""
    tool_name: str
    success: bool
    findings_count: int = 0
    mapped_findings: int = 0
    unmapped_findings: int = 0
    execution_time: Optional[float] = None
    tool_version: Optional[str] = None  # Tool version (e.g., "1.7.5")
    error: Optional[str] = None
    policy_decision: Optional[Dict[str, Any]] = None  # Runtime guard allow/deny decision
    findings: Optional[List[Dict[str, Any]]] = None  # Raw findings for debugging


class AnalysisPerformance(BaseModel):
    """Performance timing breakdown for analysis/adjudication phases."""
    total_seconds: float
    static_tools_seconds: float = 0.0
    policy_checks_seconds: float = 0.0
    dynamic_analysis_seconds: float = 0.0
    dedupe_seconds: float = 0.0
    adjudication_seconds: Optional[float] = None
    tool_count: int = 0


class DynamicReplayArtifact(BaseModel):
    """Deterministic replay metadata for dynamic analysis execution."""

    runner: str
    command: List[str]
    timeout_seconds: int
    deterministic_fingerprint: str
    language: str


class DynamicExecutionArtifact(BaseModel):
    """Output from one sandboxed dynamic analysis execution."""

    artifact_id: str
    duration_seconds: float
    return_code: Optional[int] = None
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    replay: DynamicReplayArtifact


class DynamicAnalysisResult(BaseModel):
    """Dynamic analysis summary and replay artifacts."""

    executed: bool
    runner: str
    timeout_seconds: int
    artifacts: List[DynamicExecutionArtifact] = Field(default_factory=list)
    violations: List[Violation] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Result of static/dynamic analysis."""
    artifact_id: str
    violations: List[Violation]
    tool_execution: Optional[Dict[str, ToolExecutionInfo]] = None  # Tool execution metadata
    dynamic_analysis: Optional[DynamicAnalysisResult] = None
    performance: Optional[AnalysisPerformance] = None


class GeneratorRequest(BaseModel):
    """Request to generate code."""
    spec: str
    policies: Optional[List[str]] = None  # Policy IDs to consider
    language: str = "python"


class GeneratorResponse(BaseModel):
    """Response from code generator."""
    code: str
    analysis: Optional[List[str]] = None  # Self-assessment


class FixRequest(BaseModel):
    """Request to fix code violations."""
    code: str
    violations: List[Violation]
    language: str = "python"


class Argument(BaseModel):
    """An argument in the argumentation framework."""
    id: str
    rule_id: str
    type: Literal["compliance", "violation", "exception"]
    evidence: Optional[str] = None
    details: Optional[str] = None


class Attack(BaseModel):
    """Attack relationship between arguments."""
    attacker: str
    target: str


class SetAttack(BaseModel):
    """Joint attack: a set of attackers jointly defeats a target (Nielsen & Parsons style)."""
    attackers: List[str]
    target: str


class ArgumentationGraph(BaseModel):
    """Graph of arguments and attacks."""
    arguments: List[Argument]
    attacks: List[Attack]
    set_attacks: List[SetAttack] = Field(default_factory=list)


class AdjudicationResult(BaseModel):
    """Result of adjudication."""
    semantics: Optional[str] = None  # grounded, stable, preferred, auto
    requested_semantics: Optional[str] = None
    solver_decision_mode: Optional[str] = None  # skeptical|credulous
    secondary_semantics: Optional[Dict[str, Any]] = None  # Optional solver-backed cross-checks
    timing_seconds: Optional[float] = None
    compliant: bool
    unsatisfied_rules: List[str]
    satisfied_rules: List[str]
    reasoning: List[Dict[str, Any]]


class ArtifactMetadata(BaseModel):
    """Metadata about a code artifact."""
    name: Optional[str] = None
    hash: str
    language: str
    generator: str = "unknown"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PolicyOutcome(BaseModel):
    """Outcome for a single policy rule."""
    id: str
    description: str
    result: Literal["satisfied", "violated", "waived"]


class Evidence(BaseModel):
    """Evidence supporting a compliance decision."""
    rule_id: str
    type: str
    tool: Optional[str] = None  # Tool name (e.g., "bandit", "eslint", "regex", "ast")
    tool_version: Optional[str] = None  # Tool version
    tool_rule_id: Optional[str] = None  # Tool-specific rule ID (e.g., "B608")
    detector: Optional[str] = None  # Keep for backward compatibility (same as tool)
    test: Optional[str] = None
    output: str
    confidence: Optional[str] = None  # "low", "medium", "high"
    location: Optional[Dict[str, Any]] = None  # file, line, column


class ProofBundle(BaseModel):
    """Complete proof-carrying artifact."""
    artifact: ArtifactMetadata
    code: str  # The actual code artifact (included for tamper detection)
    policies: List[PolicyOutcome]
    evidence: List[Evidence]
    argumentation: Optional[Dict[str, Any]] = None
    decision: Literal["Compliant", "Non-compliant"]
    signed: Dict[str, str]  # signature, signer, algorithm


class ComplianceRequest(BaseModel):
    """Request to check compliance."""
    code: str
    language: str = "python"
    policies: Optional[List[str]] = None


class EnforceRequest(BaseModel):
    """Request to enforce compliance (check + auto-fix)."""
    code: str
    language: str = "python"
    max_iterations: int = 3
    policies: Optional[List[str]] = None
    semantics: Optional[str] = None  # grounded, stable, preferred, auto
    solver_decision_mode: Optional[str] = None  # auto, skeptical, credulous
    stop_on_stagnation: bool = True


class EnforceIterationMetrics(BaseModel):
    """Per-iteration performance and progress details."""
    iteration: int
    violation_count: int
    compliant: bool
    analysis_seconds: float
    adjudication_seconds: float
    fix_seconds: Optional[float] = None
    fix_attempted: bool = False
    fix_error: Optional[str] = None
    semantics_used: Optional[str] = None


class EnforcePerformance(BaseModel):
    """Aggregated performance details for an enforce run."""
    total_seconds: float
    analysis_seconds: float
    adjudication_seconds: float
    fix_seconds: float
    proof_seconds: float
    stopped_early_reason: Optional[str] = None
    iterations: List[EnforceIterationMetrics] = Field(default_factory=list)


class EnforceResponse(BaseModel):
    """Response from enforcement."""
    original_code: str
    final_code: str
    iterations: int
    compliant: bool
    violations_fixed: List[str]
    llm_usage: Optional[Dict[str, Any]] = None
    performance: Optional[EnforcePerformance] = None
    proof_bundle: Optional[ProofBundle] = None
