export const safeArray = <T,>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : []);

export const safeObject = (value: unknown): Record<string, any> => (
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, any>)
    : {}
);

export const safeText = (value: unknown, fallback = ''): string => {
  if (typeof value === 'string') {
    return value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (value == null) {
    return fallback;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return fallback;
  }
};

export type RuntimePolicyEvent = {
  tool: string;
  action: string;
  rule_id?: string | null;
  allowed?: boolean;
  message?: string | null;
};

export const parseJsonIfString = (value: unknown): unknown => {
  if (typeof value !== 'string') {
    return value;
  }
  const trimmed = value.trim();
  if (!(trimmed.startsWith('{') || trimmed.startsWith('['))) {
    return value;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
};

export const normalizeRuntimePolicyEvents = (value: unknown): RuntimePolicyEvent[] => {
  const parsed = parseJsonIfString(value);
  const asArray = Array.isArray(parsed) ? parsed : [parsed];
  const events: RuntimePolicyEvent[] = [];

  for (const item of asArray) {
    const obj = safeObject(item);
    const tool = safeText(obj.tool, '');
    const action = safeText(obj.action, '');
    if (!tool || !action) {
      continue;
    }
    events.push({
      tool,
      action,
      rule_id: obj.rule_id ? safeText(obj.rule_id) : null,
      allowed: typeof obj.allowed === 'boolean' ? obj.allowed : undefined,
      message: obj.message ? safeText(obj.message) : null,
    });
  }

  return events;
};

export const describeRuntimeAction = (action: string): string => {
  switch (action) {
    case 'allow_with_monitoring':
      return 'Allowed with monitoring';
    case 'require_approval':
      return 'Approval required';
    case 'deny':
      return 'Blocked';
    case 'allow':
      return 'Allowed';
    default:
      return action;
  }
};
