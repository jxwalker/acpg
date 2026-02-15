import type { Violation, PolicyRule, EnforceResponse } from '../types';

export type TargetedFix = {
  ruleId: string;
  lines: number[];
  severity: string;
  hint: string;
  description: string;
  evidence?: string;
};

export type EnforceFailureExplanation = {
  title: string;
  detail: string;
  actions: string[];
  targetedActions?: string[];
  targetedFixes?: TargetedFix[];
  reasonCode?: string | null;
  rawError?: string | null;
};

const summarizeRemainingViolations = (violations: Violation[], limit = 3): string => {
  if (!violations.length) {
    return 'none reported';
  }
  const selected = violations.slice(0, limit).map((violation) => {
    if (violation.line != null) {
      return `${violation.rule_id} (L${violation.line})`;
    }
    return violation.rule_id;
  });
  const hidden = Math.max(0, violations.length - selected.length);
  if (hidden > 0) {
    return `${selected.join(', ')}, +${hidden} more`;
  }
  return selected.join(', ');
};

export const getRuleSpecificHint = (ruleId: string): string | null => {
  if (ruleId === 'SEC-003' || ruleId === 'JS-SEC-003') {
    return 'Replace `eval(...)` with `ast.literal_eval(...)` or `json.loads(...)`.';
  }
  if (ruleId === 'NIST-SC-13' || ruleId === 'CRYPTO-001') {
    return 'Replace `hashlib.md5(...)` with `hashlib.sha256(...)` — use AES-256-GCM for encryption.';
  }
  if (ruleId === 'SEC-001') {
    return 'Move hardcoded secrets to env vars: `os.environ[\'KEY\']` or a secrets manager.';
  }
  if (ruleId === 'SQL-001') {
    return 'Use parameterized queries: `cursor.execute(\'SELECT * FROM t WHERE id=?\', (id,))`.';
  }
  if (ruleId === 'SEC-002') {
    return 'Add input validation/sanitization before using user input in HTML/SQL/shell.';
  }
  if (ruleId === 'OWASP-A03') {
    return 'Sanitize user input — use allowlists, escape output, parameterize queries.';
  }
  if (ruleId === 'OWASP-A02') {
    return 'Use bcrypt/argon2 for password hashing, enforce TLS, avoid broken crypto.';
  }
  if (ruleId === 'NIST-AC-1') {
    return 'Implement least-privilege access controls and audit logging.';
  }
  if (ruleId === 'SEC-DESER') {
    return 'Avoid pickle/yaml.load on untrusted data — use `yaml.safe_load` or JSON.';
  }
  if (ruleId === 'CMD-INJ') {
    return 'Use subprocess with a list arg instead of `shell=True`, avoid `os.system()`.';
  }
  return null;
};

const buildTargetedRemediationActions = (
  violations: Violation[],
  policies: PolicyRule[],
  limit = 3,
): string[] => {
  if (!violations.length) {
    return [];
  }

  const grouped = new Map<string, { lines: number[]; count: number }>();
  for (const violation of violations) {
    const existing = grouped.get(violation.rule_id) || { lines: [], count: 0 };
    existing.count += 1;
    if (violation.line != null && !existing.lines.includes(violation.line)) {
      existing.lines.push(violation.line);
    }
    grouped.set(violation.rule_id, existing);
  }

  const prioritized = Array.from(grouped.entries())
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, limit);

  return prioritized.map(([ruleId, meta]) => {
    const policy = policies.find((item) => item.id === ruleId);
    const lines = meta.lines.sort((a, b) => a - b);
    const lineText = lines.length > 0
      ? `line${lines.length > 1 ? 's' : ''} ${lines.slice(0, 4).join(', ')}`
      : `${meta.count} occurrence${meta.count > 1 ? 's' : ''}`;
    const policySuggestion = policy?.fix_suggestion?.trim();
    const fallbackHint = getRuleSpecificHint(ruleId);
    const suggestion = policySuggestion || fallbackHint || 'Apply the policy-specific secure coding change and re-run analysis.';
    return `${ruleId} (${lineText}): ${suggestion}`;
  });
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const buildTargetedFixes = (
  violations: Violation[],
  policies: PolicyRule[],
  limit = 5,
): TargetedFix[] => {
  if (!violations.length) {
    return [];
  }

  const grouped = new Map<string, {
    lines: number[];
    count: number;
    severity: string;
    description: string;
    evidence?: string;
  }>();

  for (const violation of violations) {
    const existing = grouped.get(violation.rule_id);
    if (existing) {
      existing.count += 1;
      if (violation.line != null && !existing.lines.includes(violation.line)) {
        existing.lines.push(violation.line);
      }
      if (!existing.evidence && violation.evidence) {
        existing.evidence = violation.evidence;
      }
    } else {
      grouped.set(violation.rule_id, {
        lines: violation.line != null ? [violation.line] : [],
        count: 1,
        severity: violation.severity || 'medium',
        description: violation.description || '',
        evidence: violation.evidence,
      });
    }
  }

  return Array.from(grouped.entries())
    .sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[a[1].severity] ?? 9) - (SEVERITY_ORDER[b[1].severity] ?? 9);
      if (sevDiff !== 0) return sevDiff;
      return b[1].count - a[1].count;
    })
    .slice(0, limit)
    .map(([ruleId, meta]) => {
      const policy = policies.find((item) => item.id === ruleId);
      const policySuggestion = policy?.fix_suggestion?.trim();
      const fallbackHint = getRuleSpecificHint(ruleId);
      const hint = policySuggestion || fallbackHint || 'Apply the policy-specific secure coding change and re-run analysis.';
      return {
        ruleId,
        lines: meta.lines.sort((a, b) => a - b),
        severity: meta.severity,
        hint,
        description: meta.description,
        evidence: meta.evidence,
      };
    });
};

export const buildEnforceFailureExplanation = (
  result: EnforceResponse | null,
  violations: Violation[] = [],
  policies: PolicyRule[] = [],
): EnforceFailureExplanation | null => {
  if (!result || result.compliant) {
    return null;
  }

  const iterationMetrics = result.performance?.iterations ?? [];
  const reason = result.performance?.stopped_early_reason || null;
  const fixAttempts = iterationMetrics.filter((item) => item.fix_attempted).length;
  const unchangedFixIterations = iterationMetrics
    .filter((item) => item.fix_changed === false)
    .map((item) => item.iteration);
  const unresolvedSummary = summarizeRemainingViolations(violations);
  const targetedActions = buildTargetedRemediationActions(violations, policies);
  const targetedFixes = buildTargetedFixes(violations, policies);
  const latestFixError = (
    iterationMetrics
      ?.slice()
      .reverse()
      .find((item) => !!item.fix_error)
      ?.fix_error || null
  );

  if (reason === 'fix_error') {
    return {
      title: 'The model could not produce a valid fix.',
      detail: latestFixError || 'The fix request failed before compliant code could be generated.',
      actions: [
        'Validate provider availability and credentials in the Models tab.',
        'Retry with a faster or higher-quality coding model.',
        'Reduce scope by fixing one violation cluster at a time.',
      ],
      reasonCode: reason,
      rawError: latestFixError,
    };
  }

  if (reason === 'fix_returned_unchanged_code') {
    const unchangedIterationLabel = unchangedFixIterations.length > 0
      ? `Unchanged output on iteration${unchangedFixIterations.length > 1 ? 's' : ''} ${unchangedFixIterations.join(', ')}. `
      : '';
    return {
      title: 'Auto-fix stalled because the model kept returning unchanged code.',
      detail: `${unchangedIterationLabel}Fix attempts: ${fixAttempts || result.iterations}. Remaining violations: ${unresolvedSummary}.`,
      targetedActions,
      targetedFixes,
      actions: [
        'Apply the targeted rule fixes listed above, then run Auto-Fix again.',
        'If unchanged again, switch to another coding model/provider in Models.',
        'For large files, fix one rule family at a time (crypto first, then eval/exec, etc.).',
      ],
      reasonCode: reason,
    };
  }

  if (reason === 'fix_cycle_detected') {
    return {
      title: 'Auto-fix entered a repeating edit cycle.',
      detail: 'The system detected recurring code states and stopped to avoid infinite loops.',
      targetedActions,
      targetedFixes,
      actions: [
        'Switch to a different remediation model.',
        'Apply one manual edit to break cycle state, then retry.',
        'Lower iteration scope by addressing highest-severity findings first.',
      ],
      reasonCode: reason,
    };
  }

  if (reason === 'stagnation_no_violation_reduction') {
    return {
      title: 'Auto-fix stalled without reducing violations.',
      detail: `Across iterations, violation count/signature did not improve. Remaining violations: ${unresolvedSummary}.`,
      targetedActions,
      targetedFixes,
      actions: [
        'Apply the targeted rule fixes listed above.',
        'Try a model with stronger code-edit capability.',
        'Check whether some findings are non-autofixable and require design changes.',
      ],
      reasonCode: reason,
    };
  }

  if (reason === 'max_iterations_reached') {
    return {
      title: 'Auto-fix reached the configured iteration limit.',
      detail: `The app used ${result.iterations} iteration(s). Remaining violations: ${unresolvedSummary}.`,
      targetedActions,
      targetedFixes,
      actions: [
        'Increase max iterations only if each iteration shows real improvement.',
        'Apply the targeted rule fixes listed above, then re-run.',
        'Use a stronger/faster model for remediation passes.',
      ],
      reasonCode: reason,
    };
  }

  if (latestFixError) {
    return {
      title: 'Auto-fix could not complete.',
      detail: latestFixError,
      actions: [
        'Check provider diagnostics in the Models tab.',
        'Retry after confirming model endpoint health.',
      ],
      reasonCode: reason,
      rawError: latestFixError,
    };
  }

  return {
    title: 'Auto-fix finished but code remains non-compliant.',
    detail: `Some violations require manual remediation or a different model strategy. Remaining violations: ${unresolvedSummary}.`,
    targetedActions,
    targetedFixes,
    actions: [
      'Apply the targeted rule fixes listed above.',
      'Re-run Auto-Fix after adjusting provider/model settings.',
    ],
    reasonCode: reason,
  };
};
