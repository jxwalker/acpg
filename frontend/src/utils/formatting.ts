export const MODEL_TEST_TIMEOUT_SECONDS = 10;

export const formatMsSeconds = (ms: number): string => `${(ms / 1000).toFixed(2)}s`;

export const humanizeStopReason = (reason?: string | null): string => {
  switch (reason) {
    case 'stagnation_no_violation_reduction':
      return 'No violation reduction across iterations';
    case 'fix_returned_unchanged_code':
      return 'Model returned unchanged code';
    case 'fix_cycle_detected':
      return 'Fix cycle detected (repeating code state)';
    case 'fix_error':
      return 'Model fix request failed';
    case 'max_iterations_reached':
      return 'Reached max iteration limit';
    default:
      return reason || 'Unknown stop reason';
  }
};
