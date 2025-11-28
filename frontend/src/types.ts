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

export interface AnalysisResult {
  artifact_id: string;
  violations: Violation[];
}

export interface AdjudicationResult {
  compliant: boolean;
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
}

export interface AttackEntry {
  relation: string;
  effective: boolean;
  explanation: string;
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

export interface FormalProof {
  framework: string;
  semantics: string;
  decision: string;
  arguments: ArgumentEntry[];
  attacks: AttackEntry[];
  grounded_extension: GroundedExtension;
  reasoning_trace: Record<string, unknown>[];
  summary: ArgumentationSummary;
  conclusion?: {
    decision: string;
    reason: string;
    violated_rules: string[];
  };
}

export interface ProofBundle {
  artifact: ArtifactMetadata;
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

export interface SampleFile {
  name: string;
  path: string;
  description: string;
  violations: string[];
}
