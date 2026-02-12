// API Types matching backend schemas

export interface PolicyCheck {
  type: 'regex' | 'ast' | 'manual';
  pattern?: string;
  function?: string;
  target?: string;
  message?: string;
  languages: string[];
}

export interface PolicyRule {
  id: string;
  description: string;
  type: 'strict' | 'defeasible';
  severity: 'low' | 'medium' | 'high' | 'critical';
  check: PolicyCheck;
  fix_suggestion?: string;
}

export interface Violation {
  rule_id: string;
  description: string;
  line?: number;
  evidence?: string;
  detector: string;
  severity: string;
}

export interface ToolExecutionInfo {
  tool_name: string;
  success: boolean;
  findings_count: number;
  mapped_findings: number;
  unmapped_findings: number;
  execution_time?: number;
  tool_version?: string;  // Tool version (e.g., "1.7.5")
  error?: string;
  findings?: Array<{
    rule_id: string;
    line: number;
    message: string;
    severity: string;
    mapped?: boolean;
    policy_id?: string;
  }>;
}

export interface AnalysisResult {
  artifact_id: string;
  violations: Violation[];
  tool_execution?: Record<string, ToolExecutionInfo>;
  dynamic_analysis?: {
    executed: boolean;
    runner: string;
    timeout_seconds: number;
    artifacts: Array<{
      artifact_id: string;
      duration_seconds: number;
      return_code?: number | null;
      timed_out: boolean;
      stdout: string;
      stderr: string;
      replay: {
        runner: string;
        command: string[];
        timeout_seconds: number;
        deterministic_fingerprint: string;
        language: string;
      };
    }>;
    violations: Violation[];
  };
  performance?: {
    total_seconds: number;
    static_tools_seconds: number;
    policy_checks_seconds: number;
    dynamic_analysis_seconds?: number;
    dedupe_seconds: number;
    adjudication_seconds?: number;
    tool_count: number;
  };
}

export interface AdjudicationResult {
  compliant: boolean;
  semantics?: string; // grounded, auto, stable, preferred
  requested_semantics?: string;
  solver_decision_mode?: string;
  secondary_semantics?: Record<string, unknown>;
  timing_seconds?: number;
  unsatisfied_rules: string[];
  satisfied_rules: string[];
  reasoning: Record<string, unknown>[];
}

export interface ArtifactMetadata {
  name?: string;
  hash: string;
  language: string;
  generator: string;
  timestamp: string;
}

export interface PolicyOutcome {
  id: string;
  description: string;
  result: 'satisfied' | 'violated' | 'waived';
}

export interface Evidence {
  rule_id: string;
  type: string;
  tool?: string;
  test?: string;
  output: string;
}

export interface ArgumentEntry {
  id: string;
  type: string;
  rule_id: string;
  status: string;
  details: string;
  evidence?: string;
}

export interface AttackEntry {
  relation: string;
  effective: boolean;
  explanation: string;
  attackers?: string[]; // present for joint attacks
}

export interface GroundedExtension {
  accepted: string[];
  rejected: string[];
}

export interface ArgumentationSummary {
  total_arguments: number;
  accepted_arguments: number;
  rejected_arguments: number;
  total_attacks: number;
  effective_attacks: number;
  satisfied_rules: number;
  unsatisfied_rules: number;
}

export interface WhatHappened {
  policy: string;
  result: string;
  reason: string;
  evidence: string;
  explanation: string;
}

export interface ProofExplanation {
  summary: string;
  terminology: Record<string, string>;
  what_happened: WhatHappened[];
  step_by_step: Array<{
    step: number;
    title: string;
    description: string;
    result?: string;
  }>;
  decision_logic: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  accepted: boolean;
  evidence?: string;
}

export interface GraphViolation {
  rule_id: string;
  violation: GraphNode;
  compliance: GraphNode;
  exception: GraphNode | null;
}

export interface GraphVisual {
  violations: GraphViolation[];
  compliant_policies: string[];
  legend: {
    accepted: string;
    rejected: string;
    attacks: string;
  };
}

export interface FormalProof {
  framework: string;
  semantics: string;
  decision: string;
  arguments: ArgumentEntry[];
  attacks: AttackEntry[];
  grounded_extension: GroundedExtension;
  reasoning_trace: Record<string, unknown>[];
  summary: ArgumentationSummary;
  graph_visual?: GraphVisual;
  explanation?: ProofExplanation;
  conclusion?: {
    decision: string;
    reason: string;
    violated_rules: string[];
  };
}

export interface ProofBundle {
  artifact: ArtifactMetadata;
  code: string;  // The actual code artifact (included for tamper detection)
  policies: PolicyOutcome[];
  evidence: Evidence[];
  argumentation?: FormalProof;
  decision: 'Compliant' | 'Non-compliant';
  signed: {
    signature: string;
    signer: string;
    algorithm: string;
    public_key_fingerprint: string;
  };
}

export interface EnforceResponse {
  original_code: string;
  final_code: string;
  iterations: number;
  compliant: boolean;
  violations_fixed: string[];
  performance?: {
    total_seconds: number;
    analysis_seconds: number;
    adjudication_seconds: number;
    fix_seconds: number;
    proof_seconds: number;
    stopped_early_reason?: string | null;
    iterations: Array<{
      iteration: number;
      violation_count: number;
      compliant: boolean;
      analysis_seconds: number;
      adjudication_seconds: number;
      fix_seconds?: number | null;
      fix_attempted: boolean;
      fix_error?: string | null;
      semantics_used?: string | null;
    }>;
  };
  llm_usage?: {
    provider?: string;
    model?: string;
    call_count: number;
    endpoint_breakdown: Record<string, number>;
    input_tokens: number;
    output_tokens: number;
    total_tokens: number;
    cached_input_tokens?: number;
    reasoning_tokens?: number;
    estimated_cost_usd?: number | null;
    pricing?: {
      input_cost_per_1m?: number | null;
      cached_input_cost_per_1m?: number | null;
      output_cost_per_1m?: number | null;
    };
  };
  proof_bundle?: ProofBundle;
}

export interface ViolationSummary {
  total: number;
  by_severity: Record<string, number>;
  by_rule: Record<string, number>;
  by_detector: Record<string, number>;
  violations: Violation[];
}

export interface PolicyInput {
  id: string;
  description: string;
  type: 'strict' | 'defeasible';
  severity: 'low' | 'medium' | 'high' | 'critical';
  check: {
    type: 'regex' | 'ast' | 'manual';
    pattern?: string;
    function?: string;
    target?: string;
    message?: string;
    languages: string[];
  };
  fix_suggestion?: string;
  category?: string;
}

export interface PolicyHistoryEntry {
  id: number;
  policy_id: string;
  action: string;
  timestamp?: string | null;
  changed_by?: string;
  version?: number;
  source?: string;
  reason?: string;
  changed_fields?: string[];
  summary?: string;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
}

export interface PolicyDiffResponse {
  policy_id: string;
  from_version: number;
  to_version: number;
  changed_fields: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  before_json: string;
  after_json: string;
}

export interface SampleFile {
  name: string;
  path: string;
  description: string;
  violations: string[];
}

export interface VerificationResult {
  valid: boolean;
  tampered: boolean;
  details: {
    signature_valid: boolean;
    hash_valid: boolean;
    timestamp_present: boolean;
    signer_match: boolean;
  };
  original_hash: string | null;
  computed_hash: string | null;
  checks: string[];
  errors: string[];
}
