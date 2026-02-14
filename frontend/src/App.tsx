import { useState, useCallback, useEffect, useRef } from 'react';
import Editor, { DiffEditor } from '@monaco-editor/react';
import { 
  Shield, ShieldCheck, ShieldAlert,
  RefreshCw, FileCode, 
  AlertTriangle, CheckCircle2, XCircle, Info,
  ChevronDown, ChevronRight, Copy, Check,
  Bot, Search, Scale, FileCheck, Lock, Fingerprint,
  Sparkles, Terminal, Clock, Save, Upload, Download,
  FolderOpen, Trash2, Eye, GitBranch,
  List, Plus, Edit2, BookOpen, Settings, Link2, Power,
  Sun, Moon, Monitor,
  HardDrive, FileJson, FileText
} from 'lucide-react';

// Toast notification types
type ToastType = 'success' | 'error' | 'info' | 'warning';
interface Toast {
  id: string;
  message: string;
  type: ToastType;
  duration?: number;
}

// Toast Container Component
const ToastContainer = ({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: string) => void }) => {
  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`pointer-events-auto flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg animate-slide-up backdrop-blur-xl border ${
            toast.type === 'success' ? 'bg-emerald-500/20 border-emerald-500/30 text-emerald-300' :
            toast.type === 'error' ? 'bg-red-500/20 border-red-500/30 text-red-300' :
            toast.type === 'warning' ? 'bg-amber-500/20 border-amber-500/30 text-amber-300' :
            'bg-cyan-500/20 border-cyan-500/30 text-cyan-300'
          }`}
        >
          {toast.type === 'success' && <CheckCircle2 className="w-5 h-5 text-emerald-400" />}
          {toast.type === 'error' && <XCircle className="w-5 h-5 text-red-400" />}
          {toast.type === 'warning' && <AlertTriangle className="w-5 h-5 text-amber-400" />}
          {toast.type === 'info' && <Info className="w-5 h-5 text-cyan-400" />}
          <span className="text-sm font-medium">{toast.message}</span>
          <button 
            onClick={() => removeToast(toast.id)}
            className="ml-2 opacity-60 hover:opacity-100 transition-opacity"
          >
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      ))}
    </div>
  );
};
import { api } from './api';
import type { 
  PolicyRule, Violation, AnalysisResult, 
  AdjudicationResult, ProofBundle, EnforceResponse,
  PolicyHistoryEntry, PolicyDiffResponse
} from './types';

// Sample vulnerable code
const SAMPLE_CODE = `def login(username, password_input):
    """Login function with security vulnerabilities."""
    
    # Hardcoded credentials - will be fixed!
    password = "supersecret123"
    api_key = "sk-prod-abc123xyz"
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    
    # Dangerous eval usage
    result = eval(password_input)
    
    # Weak MD5 hashing
    import hashlib
    pw_hash = hashlib.md5(password.encode()).hexdigest()
    
    return authenticate(username, password)
`;

const CLEAN_SAMPLE = `import os
import hashlib
from typing import Optional

def login(username: str, password_input: str) -> Optional[dict]:
    """Secure login function following OWASP best practices."""
    
    # Credentials from environment - SEC-001 ✓
    stored_hash = os.environ.get("PASSWORD_HASH")
    api_key = os.environ.get("API_KEY")
    
    # Parameterized query - SQL-001 ✓
    query = "SELECT * FROM users WHERE name = ?"
    user = db.execute(query, (username,))
    
    # Safe password handling - SEC-003 ✓
    input_hash = hashlib.sha256(password_input.encode()).hexdigest()
    
    if input_hash == stored_hash:
        return {"status": "authenticated", "user": username}
    return None
`;

const MODEL_TEST_TIMEOUT_SECONDS = 10;

const formatMsSeconds = (ms: number): string => `${(ms / 1000).toFixed(2)}s`;

type EnforceFailureExplanation = {
  title: string;
  detail: string;
  actions: string[];
  targetedActions?: string[];
  reasonCode?: string | null;
  rawError?: string | null;
};

const humanizeStopReason = (reason?: string | null): string => {
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

const getRuleSpecificHint = (ruleId: string): string | null => {
  if (ruleId === 'SEC-003' || ruleId === 'JS-SEC-003') {
    return 'Replace eval/exec with a safe parser (Python: ast.literal_eval, JS: JSON.parse).';
  }
  if (ruleId === 'NIST-SC-13' || ruleId === 'CRYPTO-001') {
    return 'Replace weak crypto/hash algorithms (e.g., MD5/SHA1/DES/RC4) with SHA-256+ and approved ciphers.';
  }
  if (ruleId === 'SEC-001' || ruleId === 'NIST-AC-1') {
    return 'Move secrets to environment variables or a secrets manager.';
  }
  if (ruleId === 'SQL-001') {
    return 'Use parameterized queries instead of string concatenation.';
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

const buildEnforceFailureExplanation = (
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
    actions: [
      'Apply the targeted rule fixes listed above.',
      'Re-run Auto-Fix after adjusting provider/model settings.',
    ],
    reasonCode: reason,
  };
};

type WorkflowStep = 'idle' | 'prosecutor' | 'adjudicator' | 'generator' | 'proof' | 'complete';
type ViewMode = 'editor' | 'diff' | 'proof' | 'policies' | 'verify' | 'tools' | 'metrics' | 'models';
type CodeViewMode = 'current' | 'original' | 'fixed' | 'diff';
type SemanticsMode = 'auto' | 'grounded' | 'stable' | 'preferred';

interface ManagedTestCase {
  id: string;
  source: 'db' | 'file';
  name: string;
  description?: string;
  language: string;
  tags: string[];
  violations: string[];
  read_only: boolean;
  code?: string;
  created_at?: string | null;
  updated_at?: string | null;
}

interface TestCaseTagSummary {
  tag: string;
  count: number;
}

interface WorkflowState {
  step: WorkflowStep;
  iteration: number;
  maxIterations: number;
  violations: number;
}

interface SavedCode {
  id: string;
  name: string;
  code: string;
  language: string;
  savedAt: string;
  tags?: string[];
  favorite?: boolean;
  lastAnalysis?: {
    compliant: boolean;
    violations: number;
  };
}

type Theme = 'dark' | 'light' | 'system';

export default function App() {
  // Toast notifications
  const [toasts, setToasts] = useState<Toast[]>([]);
  
  const addToast = useCallback((message: string, type: ToastType = 'info', duration = 4000) => {
    const id = Math.random().toString(36).substr(2, 9);
    setToasts(prev => [...prev, { id, message, type, duration }]);
    if (duration > 0) {
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
    }
  }, []);
  
  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  // Theme state - persist to localStorage
  const [theme, setTheme] = useState<Theme>(() => {
    const saved = localStorage.getItem('acpg-theme');
    return (saved as Theme) || 'dark';
  });
  
  // Apply theme to document
  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.classList.toggle('light-theme', !prefersDark);
    } else {
      root.classList.toggle('light-theme', theme === 'light');
    }
    localStorage.setItem('acpg-theme', theme);
  }, [theme]);

  const [code, setCode] = useState(() => {
    const saved = localStorage.getItem('acpg-autosave-code');
    return saved || SAMPLE_CODE;
  });
  const [originalCode, setOriginalCode] = useState(SAMPLE_CODE);
  const [language] = useState('python');
  const [semantics, setSemantics] = useState<SemanticsMode>(() => {
    const saved = localStorage.getItem('acpg-semantics');
    if (saved === 'auto' || saved === 'grounded' || saved === 'stable' || saved === 'preferred') {
      return saved;
    }
    return 'auto';
  });
  const [autoSaveEnabled, setAutoSaveEnabled] = useState(true);
  const [workflow, setWorkflow] = useState<WorkflowState>({ 
    step: 'idle', 
    iteration: 0, 
    maxIterations: 3,
    violations: 0 
  });
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  
  // Real-time analysis
  const [realTimeEnabled, setRealTimeEnabled] = useState(false);
  const [realTimeLoading, setRealTimeLoading] = useState(false);
  const realTimeTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [adjudication, setAdjudication] = useState<AdjudicationResult | null>(null);
  const [enforceResult, setEnforceResult] = useState<EnforceResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [llmProvider, setLlmProvider] = useState<string>('Loading...');
  const [llmProviders, setLlmProviders] = useState<Array<{id: string; name: string; model: string; is_active: boolean}>>([]);
  const [showLlmSelector, setShowLlmSelector] = useState(false);
  const [showSemanticsSelector, setShowSemanticsSelector] = useState(false);
  const [llmSwitching, setLlmSwitching] = useState(false);
  const [llmProviderStatus, setLlmProviderStatus] = useState<Record<string, 'unknown' | 'testing' | 'success' | 'error'>>({});
  const [testingAllLlm, setTestingAllLlm] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('editor');
  const [codeViewMode, setCodeViewMode] = useState<CodeViewMode>('current');
  const [savedCodes, setSavedCodes] = useState<SavedCode[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveTags, setSaveTags] = useState('');
  const [bookmarkFilter, setBookmarkFilter] = useState<string | null>(null);
  const [complianceReport, setComplianceReport] = useState<any>(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [testCases, setTestCases] = useState<ManagedTestCase[]>([]);
  const [testCasesLoading, setTestCasesLoading] = useState(true);
  const [testCaseTags, setTestCaseTags] = useState<TestCaseTagSummary[]>([]);
  const [testCaseTagFilter, setTestCaseTagFilter] = useState<string | null>(null);
  const [showSampleMenu, setShowSampleMenu] = useState(false);
  const sampleMenuRef = useRef<HTMLDivElement | null>(null);
  const [enabledGroupsCount, setEnabledGroupsCount] = useState({ groups: 0, policies: 0 });
  const [policyCreationData, setPolicyCreationData] = useState<{toolName?: string; toolRuleId?: string; description?: string; severity?: string} | null>(null);
  const [showMinimap, setShowMinimap] = useState(() => {
    const saved = localStorage.getItem('acpg-minimap');
    return saved === 'true';
  });
  
  // Persist minimap preference
  useEffect(() => {
    localStorage.setItem('acpg-minimap', String(showMinimap));
  }, [showMinimap]);

  // Persist semantics preference
  useEffect(() => {
    localStorage.setItem('acpg-semantics', semantics);
  }, [semantics]);

  // Auto-save code to localStorage
  const autoSaveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [lastAutoSave, setLastAutoSave] = useState<Date | null>(null);
  
  useEffect(() => {
    if (!autoSaveEnabled) return;
    
    // Debounce auto-save by 1 second
    if (autoSaveTimeoutRef.current) {
      clearTimeout(autoSaveTimeoutRef.current);
    }
    
    autoSaveTimeoutRef.current = setTimeout(() => {
      localStorage.setItem('acpg-autosave-code', code);
      setLastAutoSave(new Date());
    }, 1000);
    
    return () => {
      if (autoSaveTimeoutRef.current) {
        clearTimeout(autoSaveTimeoutRef.current);
      }
    };
  }, [code, autoSaveEnabled]);
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const testCaseImportInputRef = useRef<HTMLInputElement>(null);
  const editorRef = useRef<any>(null);
  
  // Handle editor mount to get reference
  const handleEditorMount = (editor: any) => {
    editorRef.current = editor;
  };
  
  // Highlight a specific line in the editor
  const highlightLine = (lineNumber: number) => {
    if (editorRef.current) {
      // Scroll to and highlight the line
      editorRef.current.revealLineInCenter(lineNumber);
      editorRef.current.setPosition({ lineNumber, column: 1 });
      editorRef.current.focus();
      
      // Add a temporary decoration for visibility
      const decorations = editorRef.current.deltaDecorations([], [
        {
          range: { startLineNumber: lineNumber, startColumn: 1, endLineNumber: lineNumber, endColumn: 1 },
          options: {
            isWholeLine: true,
            className: 'highlighted-line',
            glyphMarginClassName: 'highlighted-glyph'
          }
        }
      ]);
      
      // Remove decoration after 2 seconds
      setTimeout(() => {
        editorRef.current?.deltaDecorations(decorations, []);
      }, 2000);
    }
  };
  
  // Analysis history
  interface HistoryEntry {
    id: string;
    timestamp: string;
    code_preview: string;
    language: string;
    compliant: boolean;
    violations_count: number;
    policies_passed: number;
    severity_breakdown: Record<string, number>;
    rule_breakdown?: Record<string, number>;
    dynamic_executed?: boolean;
    dynamic_runner?: string | null;
    dynamic_artifacts?: Array<{ suite_id?: string; violation_rule_id?: string | null }>;
  }
  interface HistoryTrends {
    window_days: number;
    total_runs: number;
    compliant_runs: number;
    non_compliant_runs: number;
    compliance_rate: number;
    avg_violations: number;
    avg_policies_passed: number;
    dynamic_runs: number;
    dynamic_issue_runs: number;
    dynamic_issue_rate: number;
    top_violated_rules: Array<{ rule_id: string; count: number }>;
    series: Array<{ date: string; runs: number; compliant: number; non_compliant: number; avg_violations: number }>;
  }
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyTrends, setHistoryTrends] = useState<HistoryTrends | null>(null);
  const [historyTrendDays, setHistoryTrendDays] = useState<number>(30);
  const [showHistory, setShowHistory] = useState(false);

  // Load saved codes from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('acpg_saved_codes');
    if (saved) {
      setSavedCodes(JSON.parse(saved));
    }
  }, []);

  // Real-time analysis with debouncing (500ms delay)
  useEffect(() => {
    if (!realTimeEnabled || workflow.step !== 'idle') return;
    
    // Clear any existing timeout
    if (realTimeTimeoutRef.current) {
      clearTimeout(realTimeTimeoutRef.current);
    }
    
    // Skip if code is too short
    if (code.trim().length < 10) {
      setAnalysis(null);
      setAdjudication(null);
      return;
    }
    
    // Set a new timeout for analysis
    realTimeTimeoutRef.current = setTimeout(async () => {
      setRealTimeLoading(true);
      try {
        const analysisResult = await api.analyze(code, language);
        setAnalysis(analysisResult);
        
        // Quick adjudication
        const adjResult = await api.adjudicate(analysisResult, semantics);
        setAdjudication(adjResult);
      } catch (e) {
        // Silently fail for real-time analysis
      } finally {
        setRealTimeLoading(false);
      }
    }, 500);
    
    return () => {
      if (realTimeTimeoutRef.current) {
        clearTimeout(realTimeTimeoutRef.current);
      }
    };
  }, [code, realTimeEnabled, workflow.step, language, semantics]);

  // Test a single LLM provider
  const testLlmProvider = async (id: string, showToast = false): Promise<boolean> => {
    const startedAtMs = Date.now();
    setLlmProviderStatus(prev => ({ ...prev, [id]: 'testing' }));
    const provider = llmProviders.find(p => p.id === id);
    const providerName = provider?.name || id;
    const providerModel = provider?.model || 'unknown-model';
    try {
      const res = await fetch('/api/v1/llm/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: id, timeout_seconds: MODEL_TEST_TIMEOUT_SECONDS }),
      });
      const result = await res.json();
      if (!res.ok) {
        throw new Error(result.detail || result.error || 'Failed to test provider');
      }
      const success = result.success;
      setLlmProviderStatus(prev => ({ ...prev, [id]: success ? 'success' : 'error' }));
      if (showToast) {
        const durationMs = Date.now() - startedAtMs;
        const summary = result.diagnostics?.summary || result.error || 'Connection failed';
        addToast(
          success
            ? `${providerName} (${providerModel}) online in ${formatMsSeconds(durationMs)}`
            : `${providerName} (${providerModel}) failed in ${formatMsSeconds(durationMs)}: ${summary}`,
          success ? 'success' : 'error'
        );
      }
      return success;
    } catch (err: any) {
      setLlmProviderStatus(prev => ({ ...prev, [id]: 'error' }));
      if (showToast) {
        const durationMs = Date.now() - startedAtMs;
        addToast(
          `${providerName} (${providerModel}) failed in ${formatMsSeconds(durationMs)}: ${err?.message || 'Connection failed'}`,
          'error',
        );
      }
      return false;
    }
  };

  // Load policies and LLM info on mount
  useEffect(() => {
    api.listPolicies()
      .then(data => setPolicies(data.policies))
      .catch(err => console.error('Failed to load policies:', err));
    
    // Load active LLM and available providers
    fetch('/api/v1/llm/active')
      .then(res => res.json())
      .then(data => setLlmProvider(data.name || 'Unknown'))
      .catch(() => setLlmProvider('GPT-4'));
    
    fetch('/api/v1/llm/providers')
      .then(res => res.json())
      .then((data) => {
        const providers = data || [];
        setLlmProviders(providers);
      })
      .catch(() => setLlmProviders([]));
  }, []);

  // Test all LLM providers
  const testAllLlmProviders = async () => {
    if (llmProviders.length === 0) return;
    setTestingAllLlm(true);
    
    let successCount = 0;
    for (const provider of llmProviders) {
      const success = await testLlmProvider(provider.id);
      if (success) successCount++;
    }

    setTestingAllLlm(false);
    addToast(
      `Tested ${llmProviders.length} providers: ${successCount} online, ${llmProviders.length - successCount} offline`,
      successCount === llmProviders.length ? 'success' : 'warning'
    );
  };

  const loadTestCases = useCallback(async () => {
    setTestCasesLoading(true);
    try {
      const query = new URLSearchParams();
      if (testCaseTagFilter) {
        query.set('tag', testCaseTagFilter);
      }
      const url = query.toString() ? `/api/v1/test-cases?${query.toString()}` : '/api/v1/test-cases';
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();
      setTestCases(data.cases || []);
    } catch (err) {
      console.error('Failed to load test cases:', err);
      setTestCases([]);
    } finally {
      setTestCasesLoading(false);
    }
  }, [testCaseTagFilter]);

  const loadTestCaseTags = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/test-cases/tags?source=db');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setTestCaseTags(Array.isArray(data.tags) ? data.tags : []);
    } catch (err) {
      console.error('Failed to load test case tags:', err);
      setTestCaseTags([]);
    }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/history?limit=20');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setHistory(Array.isArray(data.history) ? data.history : []);
    } catch (err) {
      console.error('Failed to load analysis history:', err);
      setHistory([]);
    }
  }, []);

  const loadHistoryTrends = useCallback(async () => {
    try {
      const response = await fetch(`/api/v1/history/trends?days=${historyTrendDays}`);
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const data = await response.json();
      setHistoryTrends(data || null);
    } catch (err) {
      console.error('Failed to load history trends:', err);
      setHistoryTrends(null);
    }
  }, [historyTrendDays]);

  useEffect(() => {
    void loadTestCases();
    void loadTestCaseTags();
    void loadHistory();
    void loadHistoryTrends();
    
    // Load enabled policy groups count
    fetch('/api/v1/policies/groups/')
      .then(res => res.json())
      .then(data => setEnabledGroupsCount({
        groups: data.enabled_groups || 0,
        policies: data.enabled_policies || 0
      }))
      .catch(() => {});
  }, [loadHistory, loadHistoryTrends, loadTestCases, loadTestCaseTags]);

  useEffect(() => {
    if (!showSampleMenu) {
      return;
    }
    const onPointerDown = (event: MouseEvent) => {
      if (!sampleMenuRef.current) {
        return;
      }
      const target = event.target as Node | null;
      if (target && !sampleMenuRef.current.contains(target)) {
        setShowSampleMenu(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [showSampleMenu]);

  useEffect(() => {
    if (!testCaseTagFilter) {
      return;
    }
    if (!testCaseTags.some(item => item.tag === testCaseTagFilter)) {
      setTestCaseTagFilter(null);
    }
  }, [testCaseTagFilter, testCaseTags]);

  const [analysisProgress, setAnalysisProgress] = useState<{
    phase: string;
    tool?: string;
    message?: string;
  } | null>(null);
  const [analysisStartedAtMs, setAnalysisStartedAtMs] = useState<number | null>(null);
  const [analysisElapsedMs, setAnalysisElapsedMs] = useState(0);

  useEffect(() => {
    if (!analysisProgress || analysisProgress.phase === 'complete' || analysisStartedAtMs == null) {
      return;
    }
    setAnalysisElapsedMs(Math.max(0, Date.now() - analysisStartedAtMs));
    const interval = window.setInterval(() => {
      setAnalysisElapsedMs(Math.max(0, Date.now() - analysisStartedAtMs));
    }, 250);
    return () => window.clearInterval(interval);
  }, [analysisProgress, analysisStartedAtMs]);

  useEffect(() => {
    if (!analysisProgress || analysisProgress.phase === 'complete') {
      setAnalysisStartedAtMs(null);
      setAnalysisElapsedMs(0);
    }
  }, [analysisProgress]);

  // Refresh history after analysis
  const refreshHistory = useCallback(() => {
    void loadHistory();
    void loadHistoryTrends();
  }, [loadHistory, loadHistoryTrends]);

  const handleAnalyze = useCallback(async () => {
    setError(null);
    setEnforceResult(null);
    setAnalysisStartedAtMs(Date.now());
    setAnalysisElapsedMs(0);
    setAnalysisProgress({ phase: 'starting', message: 'Initializing analysis...' });
    addToast('Starting analysis...', 'info', 2000);
    setWorkflow({ step: 'prosecutor', iteration: 0, maxIterations: 3, violations: 0 });
    
    try {
      // Show language detection
      setAnalysisProgress({ phase: 'detecting', message: 'Detecting language...' });
      await new Promise(r => setTimeout(r, 200));
      
      // Show tool execution
      setAnalysisProgress({ phase: 'tools', message: 'Running static analysis tools...' });
      const analysisResult = await api.analyze(code, language);
      
      // Show tool results
      if (analysisResult.tool_execution) {
        const tools = Object.keys(analysisResult.tool_execution);
        if (tools.length > 0) {
          setAnalysisProgress({ 
            phase: 'tools', 
            message: `Tools executed: ${tools.join(', ')}`,
            tool: tools[0]
          });
        }
      }
      
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 300));
      
      // Show policy checks
      setAnalysisProgress({ phase: 'policies', message: 'Running policy checks...' });
      await new Promise(r => setTimeout(r, 200));
      
      // Show adjudication
      setAnalysisProgress({ phase: 'adjudicating', message: 'Adjudicating compliance...' });
      setWorkflow(w => ({ ...w, step: 'adjudicator' }));
      const adjResult = await api.adjudicate(analysisResult, semantics);
      setAdjudication(adjResult);
      
      // Refresh history sidebar
      refreshHistory();
      
      await new Promise(r => setTimeout(r, 200));
      setAnalysisProgress({ phase: 'complete', message: 'Analysis complete' });
      setWorkflow(w => ({ ...w, step: 'complete' }));
      setTimeout(() => setAnalysisProgress(null), 2000);
      addToast('Analysis completed successfully', 'success');
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Analysis failed';
      setError(errorMsg);
      addToast(errorMsg, 'error');
      setAnalysisProgress(null);
      setAnalysisStartedAtMs(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language, semantics, addToast]);

  const handleEnforce = useCallback(async () => {
    setError(null);
    setOriginalCode(code); // Save original for diff
    setAnalysisStartedAtMs(Date.now());
    setAnalysisElapsedMs(0);
    setAnalysisProgress({ phase: 'starting', message: 'Starting enforcement...' });
    addToast('Starting auto-fix workflow...', 'info', 2500);
    setWorkflow({ step: 'prosecutor', iteration: 1, maxIterations: 3, violations: 0 });
    
    try {
      setAnalysisProgress({ phase: 'tools', message: 'Running static analysis tools...' });
      const analysisResult = await api.analyze(code, language);
      
      if (analysisResult.tool_execution) {
        const tools = Object.keys(analysisResult.tool_execution);
        if (tools.length > 0) {
          setAnalysisProgress({ 
            phase: 'tools', 
            message: `Tools executed: ${tools.join(', ')}`,
            tool: tools[0]
          });
        }
      }
      
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 300));
      setAnalysisProgress({ phase: 'adjudicating', message: 'Adjudicating compliance...' });
      setWorkflow(w => ({ ...w, step: 'adjudicator' }));
      
      await new Promise(r => setTimeout(r, 300));
      setAnalysisProgress({ 
        phase: 'generating', 
        message: `Applying iterative fixes with ${llmProvider} (up to 3 iterations)...` 
      });
      setWorkflow(w => ({ ...w, step: 'generator' }));
      
      const result = await api.enforce(code, language, 3, semantics);
      setEnforceResult(result);
      
      if (result.final_code !== code) {
        setCode(result.final_code);
        // Auto-switch to diff view
        setCodeViewMode('diff');
      }
      
      setWorkflow(w => ({ ...w, step: 'proof', iteration: result.iterations }));
      await new Promise(r => setTimeout(r, 300));
      
      setAnalysisProgress({ phase: 'tools', message: 'Re-analyzing fixed code...' });
      const finalAnalysis = await api.analyze(result.final_code, language);
      setAnalysis(finalAnalysis);
      
      setAnalysisProgress({ phase: 'adjudicating', message: 'Final adjudication...' });
      const adjResult = await api.adjudicate(finalAnalysis, semantics);
      setAdjudication(adjResult);
      
      setAnalysisProgress({ phase: 'complete', message: 'Enforcement complete' });
      setWorkflow(w => ({ ...w, step: 'complete', violations: finalAnalysis.violations.length }));
      setTimeout(() => setAnalysisProgress(null), 2000);
      if (result.compliant && adjResult.compliant) {
        addToast(`Auto-fix completed in ${result.iterations} iteration(s)`, 'success');
      } else {
        const explanation = buildEnforceFailureExplanation(result, finalAnalysis.violations, policies);
        if (explanation) {
          addToast(`Auto-fix incomplete: ${explanation.title}`, 'warning', 7000);
        } else {
          addToast('Auto-fix finished but code is still non-compliant', 'warning', 7000);
        }
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Enforcement failed';
      setError(errorMsg);
      addToast(errorMsg, 'error');
      setAnalysisProgress(null);
      setAnalysisStartedAtMs(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language, semantics, addToast, llmProvider, policies]);

  const handleGenerateReport = useCallback(async (format: 'json' | 'markdown' | 'html' = 'json') => {
    setReportLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/v1/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code,
          language,
          format,
          signed: true
        })
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate report');
      }
      
      if (format === 'json') {
        const report = await response.json();
        setComplianceReport(report);
        setShowReportModal(true);
      } else {
        // Download the file
        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `compliance_report.${format === 'markdown' ? 'md' : format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report generation failed');
    } finally {
      setReportLoading(false);
    }
  }, [code, language]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ctrl/Cmd + Enter = Analyze
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleAnalyze();
      }
      // Ctrl/Cmd + Shift + Enter = Auto-Fix
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'Enter') {
        e.preventDefault();
        handleEnforce();
      }
      // Escape = Close modals
      if (e.key === 'Escape') {
        setShowSaveDialog(false);
        setShowReportModal(false);
        setShowSampleMenu(false);
      }
    };
    
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleAnalyze, handleEnforce]);

  const handleLoadSample = (type: 'dirty' | 'clean') => {
    const newCode = type === 'dirty' ? SAMPLE_CODE : CLEAN_SAMPLE;
    setCode(newCode);
    setOriginalCode(newCode);
    setAnalysis(null);
    setAdjudication(null);
    setEnforceResult(null);
    setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    setViewMode('editor');
    setCodeViewMode('current');
  };

  const handleLoadTestCase = async (caseId: string) => {
    try {
      const response = await fetch(`/api/v1/test-cases/${encodeURIComponent(caseId)}`);
      if (!response.ok) throw new Error('Failed to load sample');
      const data = await response.json();
      setOriginalCode(data.code);
      setCode(data.code);
      setAnalysis(null);
      setAdjudication(null);
      setEnforceResult(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
      setViewMode('editor');
      setCodeViewMode('current');
      setShowSampleMenu(false);
      addToast(`Loaded test case: ${data.name}`, 'success');
    } catch (err) {
      const errorMsg = 'Failed to load test case';
      setError(errorMsg);
      addToast(errorMsg, 'error');
    }
  };

  const handleExportTestCases = useCallback(async () => {
    try {
      const response = await fetch('/api/v1/test-cases/export');
      if (!response.ok) {
        throw new Error('Failed to export test cases');
      }
      const payload = await response.json();
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      a.download = `acpg-test-cases-${timestamp}.json`;
      a.click();
      URL.revokeObjectURL(url);
      addToast(`Exported ${payload.count || 0} DB test cases`, 'success');
    } catch (err) {
      addToast('Failed to export test cases', 'error');
    }
  }, [addToast]);

  const handleImportTestCasesFile = useCallback(async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    try {
      const raw = await file.text();
      const parsed = JSON.parse(raw);
      const importedCases = Array.isArray(parsed?.cases) ? parsed.cases : Array.isArray(parsed) ? parsed : null;
      if (!importedCases || importedCases.length === 0) {
        throw new Error('No test cases found in import file');
      }

      const overwrite = window.confirm(
        'Overwrite existing test cases with matching name/language?\nSelect Cancel to keep existing records and skip duplicates.'
      );

      const response = await fetch('/api/v1/test-cases/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cases: importedCases,
          overwrite,
          match_by: 'name_language',
        }),
      });
      if (!response.ok) {
        throw new Error('Import request failed');
      }
      const result = await response.json();
      const summary = result.summary || {};
      addToast(
        `Import complete: ${summary.created || 0} created, ${summary.updated || 0} updated, ${summary.skipped || 0} skipped`,
        (summary.errors || 0) > 0 ? 'warning' : 'success',
        6000
      );
      await loadTestCaseTags();
      await loadTestCases();
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to import test cases', 'error');
    } finally {
      event.target.value = '';
    }
  }, [addToast, loadTestCaseTags, loadTestCases]);

  const handleCreateTestCase = useCallback(async () => {
    const name = window.prompt('Name for this test case?');
    if (!name || !name.trim()) {
      return;
    }
    const description = window.prompt('Optional description:', '') || '';
    const tagsRaw = window.prompt('Optional tags (comma-separated):', '') || '';
    const tags = tagsRaw
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    try {
      const response = await fetch('/api/v1/test-cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || null,
          language,
          code,
          tags,
        }),
      });
      if (!response.ok) {
        throw new Error('Failed to create test case');
      }
      await loadTestCaseTags();
      await loadTestCases();
      addToast(`Saved test case "${name.trim()}"`, 'success');
    } catch (err) {
      addToast('Failed to create test case', 'error');
    }
  }, [code, language, loadTestCaseTags, loadTestCases, addToast]);

  const handleUpdateTestCase = useCallback(async (testCase: ManagedTestCase) => {
    if (testCase.source !== 'db') {
      addToast('File-based test cases are read-only', 'warning');
      return;
    }
    const name = window.prompt('Update test case name:', testCase.name);
    if (!name || !name.trim()) {
      return;
    }
    const description = window.prompt('Update description:', testCase.description || '') || '';
    const tagsRaw = window.prompt('Update tags (comma-separated):', (testCase.tags || []).join(', ')) || '';
    const tags = tagsRaw
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);
    const updateCode = window.confirm('Update stored code with current editor content?');

    try {
      const payload: Record<string, unknown> = {
        name: name.trim(),
        description: description.trim() || null,
        tags,
      };
      if (updateCode) {
        payload.code = code;
        payload.language = language;
      }
      const response = await fetch(`/api/v1/test-cases/${encodeURIComponent(testCase.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        throw new Error('Failed to update test case');
      }
      await loadTestCaseTags();
      await loadTestCases();
      addToast(`Updated test case "${name.trim()}"`, 'success');
    } catch (err) {
      addToast('Failed to update test case', 'error');
    }
  }, [code, language, loadTestCaseTags, loadTestCases, addToast]);

  const handleDeleteTestCase = useCallback(async (testCase: ManagedTestCase) => {
    if (testCase.source !== 'db') {
      addToast('File-based test cases are read-only', 'warning');
      return;
    }
    if (!window.confirm(`Delete test case "${testCase.name}"?`)) {
      return;
    }
    try {
      const response = await fetch(`/api/v1/test-cases/${encodeURIComponent(testCase.id)}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        throw new Error('Failed to delete test case');
      }
      await loadTestCaseTags();
      await loadTestCases();
      addToast(`Deleted "${testCase.name}"`, 'success');
    } catch (err) {
      addToast('Failed to delete test case', 'error');
    }
  }, [loadTestCaseTags, loadTestCases, addToast]);

  const handleSaveCode = () => {
    if (!saveName.trim()) return;
    
    // Parse tags from comma-separated string
    const tags = saveTags
      .split(',')
      .map(t => t.trim().toLowerCase())
      .filter(t => t.length > 0);
    
    const newSave: SavedCode = {
      id: Date.now().toString(),
      name: saveName.trim(),
      code,
      language,
      savedAt: new Date().toISOString(),
      tags: tags.length > 0 ? tags : undefined,
      favorite: false,
      lastAnalysis: adjudication ? {
        compliant: adjudication.compliant,
        violations: analysis?.violations.length || 0
      } : undefined
    };
    
    const updated = [...savedCodes, newSave];
    setSavedCodes(updated);
    localStorage.setItem('acpg_saved_codes', JSON.stringify(updated));
    setShowSaveDialog(false);
    setSaveName('');
    setSaveTags('');
    addToast(`Code bookmark "${saveName.trim()}" saved`, 'success');
  };
  
  const toggleFavorite = (id: string) => {
    const updated = savedCodes.map(s => 
      s.id === id ? { ...s, favorite: !s.favorite } : s
    );
    setSavedCodes(updated);
    localStorage.setItem('acpg_saved_codes', JSON.stringify(updated));
  };
  
  // Get all unique tags from saved codes
  const allTags = Array.from(new Set(
    savedCodes.flatMap(s => s.tags || [])
  )).sort();
  
  // Filter saved codes
  const filteredSavedCodes = savedCodes.filter(s => {
    if (!bookmarkFilter) return true;
    if (bookmarkFilter === 'favorites') return s.favorite;
    return s.tags?.includes(bookmarkFilter);
  });

  const handleLoadCode = (saved: SavedCode) => {
    setCode(saved.code);
    setOriginalCode(saved.code);
    setAnalysis(null);
    setAdjudication(null);
    setEnforceResult(null);
    setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    setViewMode('editor');
    setCodeViewMode('current');
  };

  const handleDeleteSaved = (id: string) => {
    const updated = savedCodes.filter(s => s.id !== id);
    setSavedCodes(updated);
    localStorage.setItem('acpg_saved_codes', JSON.stringify(updated));
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setCode(content);
      setOriginalCode(content);
      setAnalysis(null);
      setAdjudication(null);
      setEnforceResult(null);
      setViewMode('editor');
      setCodeViewMode('current');
    };
    reader.readAsText(file);
  };

  const handleDownloadCode = () => {
    const blob = new Blob([code], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `code.${language === 'python' ? 'py' : 'js'}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadProof = async (format: string = 'json') => {
    if (!enforceResult?.proof_bundle) return;
    
    try {
      const response = await api.exportProof(enforceResult.proof_bundle, format);
      const content = response.content;
      
      // Determine file extension and MIME type
      let extension = 'json';
      let mimeType = 'application/json';
      if (format === 'markdown') {
        extension = 'md';
        mimeType = 'text/markdown';
      } else if (format === 'html') {
        extension = 'html';
        mimeType = 'text/html';
      } else if (format === 'summary') {
        extension = 'txt';
        mimeType = 'text/plain';
      }
      
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `proof_bundle.${extension}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
      // Fallback to client-side JSON export
      const blob = new Blob([JSON.stringify(enforceResult.proof_bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'proof_bundle.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const handleCopyProof = useCallback(() => {
    if (enforceResult?.proof_bundle) {
      navigator.clipboard.writeText(JSON.stringify(enforceResult.proof_bundle, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [enforceResult]);

  const isProcessing = workflow.step !== 'idle' && workflow.step !== 'complete';
  const isActivelyAnalyzing = isProcessing || (!!analysisProgress && analysisProgress.phase !== 'complete');

  return (
    <div className="min-h-screen bg-mesh grid-pattern">
      {/* Hidden file input */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileUpload} 
        accept=".py,.js,.ts,.jsx,.tsx"
        className="hidden"
      />
      <input
        type="file"
        ref={testCaseImportInputRef}
        onChange={handleImportTestCasesFile}
        accept=".json"
        className="hidden"
      />

      {/* Header */}
      <header className="glass border-b border-white/5 sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-8 py-4">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-5">
              <div className="relative">
                <div className="absolute inset-0 bg-emerald-500/30 blur-xl rounded-full" />
                <div className="relative p-3 rounded-2xl bg-gradient-to-br from-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/25">
                  <Shield className="w-7 h-7 text-white" />
                </div>
              </div>
              <div>
                <h1 className="text-2xl font-display font-bold tracking-tight gradient-text">ACPG</h1>
                <p className="text-sm text-slate-400 font-medium">Agentic Compliance & Policy Governor</p>
              </div>
            </div>
            
            {/* View Mode Tabs & Controls */}
            <div className="flex items-center gap-4">
              {/* View Mode Tabs */}
              <div className="flex items-center bg-slate-800/50 rounded-xl p-1">
                <button
                  onClick={() => { setViewMode('editor'); setCodeViewMode('current'); }}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'editor' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <FileCode className="w-4 h-4" />
                    Editor
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('proof')}
                  disabled={!enforceResult?.proof_bundle}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'proof' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Fingerprint className="w-4 h-4" />
                    Proof
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('policies')}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'policies' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <List className="w-4 h-4" />
                    Policies
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('tools')}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'tools' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Settings className="w-4 h-4" />
                    Tools
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('models')}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'models' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Bot className="w-4 h-4" />
                    Models
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('verify')}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'verify' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" />
                    Verify
                  </span>
                </button>
                <button
                  onClick={() => setViewMode('metrics')}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'metrics'
                      ? 'bg-slate-700 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <Terminal className="w-4 h-4" />
                    Demo Lab
                  </span>
                </button>
              </div>
              
              <div className="h-6 w-px bg-slate-700" />
              
              {/* LLM Selector */}
              <div className="relative">
                <button
                  onClick={() => setShowLlmSelector(!showLlmSelector)}
                  disabled={llmSwitching}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all ${
                    llmSwitching ? 'opacity-50 cursor-wait' : 'cursor-pointer'
                  }`}
                >
                  <Bot className={`w-4 h-4 text-cyan-400 ${llmSwitching ? 'animate-spin' : ''}`} />
                  <span className="text-sm text-slate-300">{llmProvider}</span>
                  <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${showLlmSelector ? 'rotate-180' : ''}`} />
                </button>
                
                {/* Backdrop */}
                {showLlmSelector && (
                  <div 
                    className="fixed inset-0 z-40" 
                    onClick={() => setShowLlmSelector(false)}
                  />
                )}
                
                {/* Dropdown */}
                {showLlmSelector && (
                  <div className="absolute top-full right-0 mt-2 w-80 glass rounded-xl border border-white/10 shadow-2xl z-50 overflow-hidden">
                    <div className="p-3 border-b border-white/10 flex items-center justify-between">
                      <span className="text-xs text-slate-500 uppercase tracking-wider">Select AI Model</span>
                      <button
                        onClick={(e) => { e.stopPropagation(); testAllLlmProviders(); }}
                        disabled={testingAllLlm}
                        className="text-xs px-2 py-1 bg-emerald-500/10 text-emerald-400 rounded hover:bg-emerald-500/20 transition-colors disabled:opacity-50 flex items-center gap-1"
                      >
                        {testingAllLlm ? (
                          <><RefreshCw className="w-3 h-3 animate-spin" /> Testing...</>
                        ) : (
                          <><CheckCircle2 className="w-3 h-3" /> Test All</>
                        )}
                      </button>
                    </div>
                    <div className="p-2 max-h-80 overflow-y-auto">
                      {llmProviders.length === 0 ? (
                        <div className="p-4 text-center text-slate-500 text-sm">
                          No providers configured
                        </div>
                      ) : (
                        llmProviders.map(provider => (
                          <button
                            key={provider.id}
                            onClick={async () => {
                              if (provider.is_active) {
                                setShowLlmSelector(false);
                                return;
                              }
                              setLlmSwitching(true);
                              try {
                                const res = await fetch('/api/v1/llm/switch', {
                                  method: 'POST',
                                  headers: { 'Content-Type': 'application/json' },
                                  body: JSON.stringify({ provider_id: provider.id })
                                });
                                if (res.ok) {
                                  const data = await res.json();
                                  setLlmProvider(data.provider?.name || provider.name);
                                  setLlmProviders(prev => prev.map(p => ({
                                    ...p,
                                    is_active: p.id === provider.id
                                  })));
                                } else {
                                  const err = await res.json();
                                  setError(err.detail || 'Failed to switch model');
                                }
                              } catch (err) {
                                setError('Failed to switch model');
                              } finally {
                                setLlmSwitching(false);
                                setShowLlmSelector(false);
                              }
                            }}
                            className={`w-full text-left p-3 rounded-lg transition-all ${
                              provider.is_active
                                ? 'bg-cyan-500/10 border border-cyan-500/30'
                                : 'hover:bg-white/5'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                {/* Status indicator */}
                                <div className="relative">
                                  <Bot className={`w-4 h-4 ${provider.is_active ? 'text-cyan-400' : 'text-slate-500'}`} />
                                  {llmProviderStatus[provider.id] && (
                                    <div className={`absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full border border-slate-800 ${
                                      llmProviderStatus[provider.id] === 'testing' ? 'bg-amber-500 animate-pulse' :
                                      llmProviderStatus[provider.id] === 'success' ? 'bg-emerald-500' :
                                      llmProviderStatus[provider.id] === 'error' ? 'bg-red-500' :
                                      'bg-slate-500'
                                    }`} />
                                  )}
                                </div>
                                <span className={`text-sm font-medium ${provider.is_active ? 'text-cyan-300' : 'text-slate-300'}`}>
                                  {provider.name}
                                </span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                {llmProviderStatus[provider.id] === 'success' && (
                                  <span className="text-[10px] bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded">
                                    Online
                                  </span>
                                )}
                                {llmProviderStatus[provider.id] === 'error' && (
                                  <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">
                                    Offline
                                  </span>
                                )}
                                {provider.is_active && (
                                  <span className="text-[10px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded">
                                    Active
                                  </span>
                                )}
                              </div>
                            </div>
                            <div className="mt-1 text-xs text-slate-500 font-mono truncate pl-6">
                              {provider.model}
                            </div>
                          </button>
                        ))
                      )}
                    </div>
                    <div className="p-2 border-t border-white/10 bg-slate-900/50">
                      <button
                        onClick={() => { setShowLlmSelector(false); setViewMode('models'); }}
                        className="w-full text-xs text-cyan-400 hover:text-cyan-300 py-1 flex items-center justify-center gap-1"
                      >
                        <Settings className="w-3 h-3" />
                        Configure Models
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Semantics Selector */}
              <div className="relative">
                <button
                  onClick={() => setShowSemanticsSelector(!showSemanticsSelector)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50 hover:border-violet-500/30 hover:bg-violet-500/5 transition-all cursor-pointer"
                >
                  <Scale className="w-4 h-4 text-violet-400" />
                  <span className="text-sm text-slate-300 capitalize">{semantics}</span>
                  <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${showSemanticsSelector ? 'rotate-180' : ''}`} />
                </button>

                {showSemanticsSelector && (
                  <div
                    className="fixed inset-0 z-40"
                    onClick={() => setShowSemanticsSelector(false)}
                  />
                )}

                {showSemanticsSelector && (
                  <div className="absolute top-full right-0 mt-2 w-72 glass rounded-xl border border-white/10 shadow-2xl z-50 overflow-hidden">
                    <div className="p-3 border-b border-white/10">
                      <div className="text-xs text-slate-500 uppercase tracking-wider">Semantics</div>
                      <div className="text-xs text-slate-400 mt-1">
                        AUTO decides with grounded semantics; stable/preferred use solver-backed skeptical decisioning.
                      </div>
                    </div>
                    <div className="p-2">
                      {[
                        { id: 'auto' as const, label: 'Auto (Recommended)', desc: 'Conservative decision + optional cross-checks' },
                        { id: 'grounded' as const, label: 'Grounded', desc: 'Conservative, deterministic' },
                        { id: 'stable' as const, label: 'Stable', desc: 'Solver-based; skeptical across stable extensions' },
                        { id: 'preferred' as const, label: 'Preferred', desc: 'Solver-based; skeptical across preferred extensions' },
                      ].map(opt => (
                        <button
                          key={opt.id}
                          onClick={() => {
                            setSemantics(opt.id);
                            setShowSemanticsSelector(false);
                            addToast(`Semantics set to ${opt.id}`, 'info', 2000);
                          }}
                          className={`w-full text-left p-3 rounded-lg transition-all ${
                            semantics === opt.id
                              ? 'bg-violet-500/20 border border-violet-500/30'
                              : 'hover:bg-slate-800/50 border border-transparent'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <div className="text-sm text-white">{opt.label}</div>
                            {semantics === opt.id && <CheckCircle2 className="w-4 h-4 text-violet-400" />}
                          </div>
                          <div className="text-xs text-slate-400 mt-1">{opt.desc}</div>
                        </button>
                      ))}

                      <div className="mt-2 p-3 rounded-lg border border-white/10 bg-slate-900/40">
                        <div className="text-xs text-slate-400">
                          If solver is unavailable or joint attacks are present, ACPG falls back to grounded and records why.
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              {/* Active Policies Badge */}
              <div 
                className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-emerald-500/30 cursor-pointer hover:bg-emerald-500/10 transition-all"
                onClick={() => setViewMode('policies')}
                title="Click to manage policy groups"
              >
                <Shield className="w-4 h-4 text-emerald-400" />
                <span className="text-sm text-slate-300">
                  {enabledGroupsCount.policies} policies
                </span>
                <span className="text-xs text-slate-500">
                  ({enabledGroupsCount.groups} groups)
                </span>
              </div>
              
              <div className="h-6 w-px bg-slate-700" />
              
              {/* History Button */}
              <button
                onClick={() => setShowHistory(!showHistory)}
                className={`px-4 py-2 text-sm font-medium rounded-xl transition-all flex items-center gap-2 ${
                  showHistory 
                    ? 'bg-violet-500/20 text-violet-300 border border-violet-500/30' 
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/50'
                }`}
              >
                <Clock className="w-4 h-4" />
                History
                {history.length > 0 && (
                  <span className="text-xs bg-violet-500/30 text-violet-300 px-1.5 py-0.5 rounded-full">
                    {history.length}
                  </span>
                )}
              </button>
              
              {/* Theme Toggle */}
              <div className="flex items-center bg-slate-800/50 rounded-xl p-1 border border-slate-700/50">
                <button
                  onClick={() => setTheme('light')}
                  className={`p-1.5 rounded-lg transition-all ${
                    theme === 'light' 
                      ? 'bg-amber-500/20 text-amber-400' 
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                  title="Light theme"
                >
                  <Sun className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setTheme('dark')}
                  className={`p-1.5 rounded-lg transition-all ${
                    theme === 'dark' 
                      ? 'bg-violet-500/20 text-violet-400' 
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                  title="Dark theme"
                >
                  <Moon className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setTheme('system')}
                  className={`p-1.5 rounded-lg transition-all ${
                    theme === 'system' 
                      ? 'bg-cyan-500/20 text-cyan-400' 
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                  title="System theme"
                >
                  <Monitor className="w-4 h-4" />
                </button>
              </div>
              
              {/* Test Code Dropdown */}
              <div className="relative" ref={sampleMenuRef}>
                <button
                  onClick={() => setShowSampleMenu(!showSampleMenu)}
                  className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all flex items-center gap-2"
                >
                  <FolderOpen className="w-4 h-4 text-amber-400" />
                  Test Code
                  <ChevronDown className={`w-4 h-4 transition-transform ${showSampleMenu ? 'rotate-180' : ''}`} />
                </button>

                {showSampleMenu && (
                  <div className="absolute top-full right-0 mt-2 w-96 glass rounded-xl border border-white/10 shadow-2xl z-50 overflow-hidden">
                    <div className="p-2 border-b border-white/10">
                      <span className="text-xs text-slate-500 uppercase tracking-wider px-2">Quick Samples</span>
                    </div>
                    <div className="p-1">
                      <button
                        onClick={() => { handleLoadSample('dirty'); setShowSampleMenu(false); }}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <div>
                          <div className="font-medium">Vulnerable Example</div>
                          <div className="text-xs text-slate-500">Built-in hardcoded secrets</div>
                        </div>
                      </button>
                      <button
                        onClick={() => { handleLoadSample('clean'); setShowSampleMenu(false); }}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <div>
                          <div className="font-medium">Clean Example</div>
                          <div className="text-xs text-slate-500">Compliant code sample</div>
                        </div>
                      </button>
                      <button
                        onClick={() => void handleCreateTestCase()}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <Plus className="w-4 h-4 text-cyan-400" />
                        <div>
                          <div className="font-medium">Save Current as Test Case</div>
                          <div className="text-xs text-slate-500">Store current editor code in DB</div>
                        </div>
                      </button>
                      <button
                        onClick={() => testCaseImportInputRef.current?.click()}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <FileJson className="w-4 h-4 text-violet-400" />
                        <div>
                          <div className="font-medium">Import Test Cases (JSON)</div>
                          <div className="text-xs text-slate-500">Bulk-import DB suites from export files</div>
                        </div>
                      </button>
                      <button
                        onClick={() => void handleExportTestCases()}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <Download className="w-4 h-4 text-emerald-400" />
                        <div>
                          <div className="font-medium">Export DB Test Cases</div>
                          <div className="text-xs text-slate-500">Download portable JSON for audit/CI</div>
                        </div>
                      </button>
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg flex items-center gap-3"
                      >
                        <Upload className="w-4 h-4 text-cyan-400" />
                        <div>
                          <div className="font-medium">Load Local File</div>
                          <div className="text-xs text-slate-500">Open .py/.js/.ts from disk</div>
                        </div>
                      </button>
                    </div>

                    {testCasesLoading ? (
                      <div className="p-4 text-center text-slate-400 text-sm">
                        Loading test cases...
                      </div>
                    ) : testCases.length > 0 ? (
                      <>
                        <div className="p-2 border-t border-white/10">
                          <span className="text-xs text-slate-500 uppercase tracking-wider px-2">
                            Stored Test Cases ({testCases.filter(tc => tc.source === 'db').length})
                          </span>
                          {testCaseTags.length > 0 && (
                            <div className="mt-2 px-2 flex flex-wrap gap-1.5">
                              <button
                                onClick={() => setTestCaseTagFilter(null)}
                                className={`px-2 py-1 rounded text-[10px] border transition-all ${
                                  testCaseTagFilter === null
                                    ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                                    : 'bg-slate-800/50 border-slate-700/60 text-slate-400 hover:text-slate-200'
                                }`}
                              >
                                all
                              </button>
                              {testCaseTags.map((item) => (
                                <button
                                  key={item.tag}
                                  onClick={() => setTestCaseTagFilter(item.tag)}
                                  className={`px-2 py-1 rounded text-[10px] border transition-all ${
                                    testCaseTagFilter === item.tag
                                      ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                                      : 'bg-slate-800/50 border-slate-700/60 text-slate-400 hover:text-slate-200'
                                  }`}
                                  title={`Filter by tag: ${item.tag}`}
                                >
                                  {item.tag} ({item.count})
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="p-1 max-h-56 overflow-y-auto">
                          {testCases.filter(tc => tc.source === 'db').length === 0 && (
                            <div className="px-3 py-2 text-xs text-slate-500">No DB test cases yet.</div>
                          )}
                          {testCases
                            .filter(tc => tc.source === 'db')
                            .map(testCase => (
                              <button
                                key={testCase.id}
                                onClick={() => handleLoadTestCase(testCase.id)}
                                className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                              >
                                <div className="flex items-start gap-3">
                                  <FileText className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                                  <div className="flex-1 min-w-0">
                                    <div className="font-medium text-xs truncate">{testCase.name}</div>
                                    <div className="text-xs text-slate-500 truncate">{testCase.description || 'No description'}</div>
                                    {testCase.tags?.length > 0 && (
                                      <div className="flex gap-1 mt-1 flex-wrap">
                                        {testCase.tags.slice(0, 3).map(tag => (
                                          <span key={tag} className="px-1.5 py-0.5 text-[10px] bg-cyan-500/20 text-cyan-300 rounded">
                                            {tag}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-1">
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        void handleUpdateTestCase(testCase);
                                      }}
                                      className="p-1 text-slate-400 hover:text-cyan-300"
                                      title="Edit test case"
                                    >
                                      <Edit2 className="w-3 h-3" />
                                    </button>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        void handleDeleteTestCase(testCase);
                                      }}
                                      className="p-1 text-slate-400 hover:text-red-300"
                                      title="Delete test case"
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </div>
                                </div>
                              </button>
                            ))}
                        </div>
                        <div className="p-2 border-t border-white/10">
                          <span className="text-xs text-slate-500 uppercase tracking-wider px-2">
                            File Samples ({testCases.filter(tc => tc.source === 'file').length})
                          </span>
                        </div>
                        <div className="p-1 max-h-56 overflow-y-auto">
                          {testCases.filter(tc => tc.source === 'file').map(testCase => (
                            <button
                              key={testCase.id}
                              onClick={() => handleLoadTestCase(testCase.id)}
                              className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                            >
                              <div className="flex items-center gap-3">
                                <FileCode className="w-4 h-4 text-violet-400 flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <div className="font-medium font-mono text-xs truncate">{testCase.name}</div>
                                  <div className="text-xs text-slate-500 truncate">{testCase.description}</div>
                                  {testCase.violations?.length > 0 && (
                                    <div className="flex gap-1 mt-1 flex-wrap">
                                      {testCase.violations.slice(0, 3).map(v => (
                                        <span key={v} className="px-1.5 py-0.5 text-[10px] bg-red-500/20 text-red-400 rounded">
                                          {v}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </button>
                          ))}
                        </div>
                      </>
                    ) : (
                      <div className="p-4 text-center text-slate-500 text-sm">
                        No test cases found
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>
      
      {/* History Sidebar */}
      {showHistory && (
        <div className="fixed right-0 top-0 bottom-0 w-96 glass border-l border-white/10 z-40 flex flex-col animate-slide-in-right">
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="w-5 h-5 text-violet-400" />
              <h3 className="font-semibold text-white">Analysis History</h3>
            </div>
            <div className="flex items-center gap-2">
              {history.length > 0 && (
                <button
                  onClick={() => {
                    fetch('/api/v1/history', { method: 'DELETE' })
                      .then(() => {
                        setHistory([]);
                        setHistoryTrends(null);
                        void loadHistoryTrends();
                      })
                      .catch(() => {});
                  }}
                  className="text-xs text-slate-400 hover:text-red-400 px-2 py-1"
                >
                  Clear All
                </button>
              )}
              <button
                onClick={() => setShowHistory(false)}
                className="text-slate-400 hover:text-white"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>
          </div>

          <div className="px-4 py-3 border-b border-white/10 bg-slate-900/30 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-wider text-slate-500">Trend Window</span>
              <select
                value={historyTrendDays}
                onChange={(e) => setHistoryTrendDays(Number(e.target.value))}
                className="bg-slate-800/70 border border-slate-700 rounded px-2 py-1 text-xs text-slate-300"
              >
                <option value={7}>7 days</option>
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
              </select>
            </div>
            {historyTrends ? (
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-2 py-2">
                  <div className="text-slate-500">Compliance Rate</div>
                  <div className="text-emerald-300 font-semibold">{historyTrends.compliance_rate.toFixed(1)}%</div>
                </div>
                <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-2 py-2">
                  <div className="text-slate-500">Runs</div>
                  <div className="text-cyan-300 font-semibold">{historyTrends.total_runs}</div>
                </div>
                <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-2 py-2">
                  <div className="text-slate-500">Avg Violations</div>
                  <div className="text-amber-300 font-semibold">{historyTrends.avg_violations.toFixed(2)}</div>
                </div>
                <div className="rounded-lg border border-violet-500/20 bg-violet-500/5 px-2 py-2">
                  <div className="text-slate-500">Dynamic Issue Runs</div>
                  <div className="text-violet-300 font-semibold">
                    {historyTrends.dynamic_issue_runs}/{historyTrends.dynamic_runs}
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-500">No trend data available for selected window.</div>
            )}
            {historyTrends && historyTrends.top_violated_rules.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {historyTrends.top_violated_rules.slice(0, 3).map((item) => (
                  <span
                    key={item.rule_id}
                    className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/15 text-red-300 border border-red-500/25"
                  >
                    {item.rule_id} ({item.count})
                  </span>
                ))}
              </div>
            )}
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {history.length === 0 ? (
              <div className="text-center py-12 text-slate-500">
                <Clock className="w-12 h-12 mx-auto mb-3 opacity-30" />
                <p>No analysis history yet</p>
                <p className="text-xs mt-1">Run an analysis to see it here</p>
              </div>
            ) : (
              history.map(entry => (
                <div
                  key={entry.id}
                  className={`p-3 rounded-xl border transition-all cursor-pointer hover:bg-slate-800/50 ${
                    entry.compliant 
                      ? 'bg-emerald-500/5 border-emerald-500/20' 
                      : 'bg-red-500/5 border-red-500/20'
                  }`}
                >
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {entry.compliant ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-red-400" />
                      )}
                      <span className={`text-xs font-semibold ${
                        entry.compliant ? 'text-emerald-400' : 'text-red-400'
                      }`}>
                        {entry.compliant ? 'PASS' : 'FAIL'}
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  
                  <p className="text-xs text-slate-400 font-mono line-clamp-2 mb-2">
                    {entry.code_preview}
                  </p>
                  
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-emerald-400">{entry.policies_passed} passed</span>
                    {entry.violations_count > 0 && (
                      <>
                        <span className="text-slate-600">•</span>
                        <span className="text-red-400">{entry.violations_count} failed</span>
                      </>
                    )}
                  </div>

                  {entry.dynamic_executed && (
                    <div className="flex items-center gap-1 mt-2">
                      <span className="px-1.5 py-0.5 text-[10px] bg-cyan-500/20 text-cyan-300 rounded">
                        dynamic {entry.dynamic_artifacts?.length || 0}
                      </span>
                      {entry.dynamic_artifacts?.some(item => !!item.violation_rule_id) && (
                        <span className="px-1.5 py-0.5 text-[10px] bg-amber-500/20 text-amber-300 rounded">
                          runtime issues
                        </span>
                      )}
                    </div>
                  )}
                  
                  {Object.keys(entry.severity_breakdown || {}).length > 0 && (
                    <div className="flex gap-1 mt-2">
                      {entry.severity_breakdown.critical > 0 && (
                        <span className="px-1.5 py-0.5 text-[10px] bg-red-500/20 text-red-400 rounded">
                          {entry.severity_breakdown.critical} critical
                        </span>
                      )}
                      {entry.severity_breakdown.high > 0 && (
                        <span className="px-1.5 py-0.5 text-[10px] bg-orange-500/20 text-orange-400 rounded">
                          {entry.severity_breakdown.high} high
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
          
          <div className="p-4 border-t border-white/10 text-center">
            <p className="text-xs text-slate-500">
              Showing last {history.length} analyses
            </p>
          </div>
        </div>
      )}

      {/* Workflow Pipeline */}
      <div className="max-w-[1920px] mx-auto px-8 py-6">
        <WorkflowPipeline workflow={workflow} />
      </div>

      {/* Main Content */}
      <main className="max-w-[1920px] mx-auto px-8 pb-12">
        {viewMode === 'verify' ? (
          <ProofVerifier />
        ) : viewMode === 'metrics' ? (
          <DemoLabView
            currentCode={code}
            semantics={semantics}
          />
        ) : viewMode === 'tools' ? (
          <ToolsConfigurationView 
            onCreatePolicy={(data) => {
              setPolicyCreationData(data);
              setViewMode('policies');
            }}
          />
        ) : viewMode === 'models' ? (
          <ModelsConfigurationView />
        ) : viewMode === 'policies' ? (
          <PoliciesView policies={policies} initialPolicyData={policyCreationData} onPolicyCreated={() => setPolicyCreationData(null)} />
        ) : viewMode === 'proof' && enforceResult?.proof_bundle ? (
          <ProofBundleView 
            proof={enforceResult.proof_bundle} 
            iterations={enforceResult.iterations}
            onCopy={handleCopyProof}
            onDownload={handleDownloadProof}
            copied={copied}
          />
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
            {/* Left Panel - Code Editor/Diff (3 cols) */}
            <div className="xl:col-span-3 space-y-5">
              <div className="glass rounded-2xl overflow-hidden border border-white/5">
                {/* Editor Header */}
                <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex gap-1.5">
                      <div className="w-3 h-3 rounded-full bg-red-500/80" />
                      <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                      <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                    </div>
                    <div className="h-4 w-px bg-slate-700" />
                    {codeViewMode === 'diff' ? (
                      <>
                        <GitBranch className="w-5 h-5 text-violet-400" />
                        <span className="font-medium text-slate-200">Code Diff</span>
                        <span className="px-2 py-0.5 text-xs font-mono font-medium bg-violet-500/20 text-violet-400 rounded-md">
                          original → fixed
                        </span>
                      </>
                    ) : codeViewMode === 'original' ? (
                      <>
                        <FileCode className="w-5 h-5 text-amber-400" />
                        <span className="font-medium text-slate-200">Original Code</span>
                        <span className="px-2 py-0.5 text-xs font-mono font-medium bg-amber-500/20 text-amber-400 rounded-md">
                          before fix
                        </span>
                      </>
                    ) : codeViewMode === 'fixed' ? (
                      <>
                        <FileCode className="w-5 h-5 text-emerald-400" />
                        <span className="font-medium text-slate-200">Fixed Code</span>
                        <span className="px-2 py-0.5 text-xs font-mono font-medium bg-emerald-500/20 text-emerald-400 rounded-md">
                          after fix
                        </span>
                      </>
                    ) : (
                      <>
                        <FileCode className="w-5 h-5 text-slate-400" />
                        <span className="font-medium text-slate-200">code.py</span>
                        <span className="px-2 py-0.5 text-xs font-mono font-medium bg-slate-800 rounded-md text-slate-400">
                          {language}
                        </span>
                      </>
                    )}
                  </div>
                  
                  {/* Code View Mode Toggle - only show when there's a fix */}
                  {enforceResult && originalCode !== code && (
                    <div className="flex items-center bg-slate-800/80 rounded-lg p-1">
                      <button
                        onClick={() => setCodeViewMode('original')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                          codeViewMode === 'original'
                            ? 'bg-amber-500/20 text-amber-400'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Original
                      </button>
                      <button
                        onClick={() => setCodeViewMode('fixed')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                          codeViewMode === 'fixed'
                            ? 'bg-emerald-500/20 text-emerald-400'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Fixed
                      </button>
                      <button
                        onClick={() => setCodeViewMode('diff')}
                        className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                          codeViewMode === 'diff'
                            ? 'bg-violet-500/20 text-violet-400'
                            : 'text-slate-400 hover:text-white'
                        }`}
                      >
                        Diff
                      </button>
                    </div>
                  )}
                  
                  {/* File Actions */}
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => fileInputRef.current?.click()}
                      className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-all"
                      title="Upload file"
                    >
                      <Upload className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={handleDownloadCode}
                      className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-all"
                      title="Download code"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button 
                      onClick={() => setShowSaveDialog(true)}
                      className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-all"
                      title="Save to library"
                    >
                      <Save className="w-4 h-4" />
                    </button>
                    <div className="h-4 w-px bg-slate-700" />
                    <button
                      onClick={() => setShowMinimap(!showMinimap)}
                      className={`p-2 rounded-lg transition-all ${
                        showMinimap 
                          ? 'text-cyan-400 bg-cyan-500/10' 
                          : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                      }`}
                      title={showMinimap ? "Hide minimap" : "Show minimap"}
                    >
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="14" y="3" width="7" height="18" rx="1" />
                        <rect x="3" y="3" width="8" height="18" rx="1" />
                      </svg>
                    </button>
                    <button
                      onClick={() => setAutoSaveEnabled(!autoSaveEnabled)}
                      className={`p-2 rounded-lg transition-all flex items-center gap-1.5 ${
                        autoSaveEnabled 
                          ? 'text-emerald-400 bg-emerald-500/10' 
                          : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                      }`}
                      title={autoSaveEnabled ? "Auto-save enabled" : "Auto-save disabled"}
                    >
                      <HardDrive className="w-4 h-4" />
                      {autoSaveEnabled && lastAutoSave && (
                        <span className="text-[10px] text-emerald-400/70">
                          saved
                        </span>
                      )}
                    </button>
                    <div className="h-4 w-px bg-slate-700" />
                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <Terminal className="w-4 h-4" />
                      <span>{(codeViewMode === 'original' ? originalCode : code).split('\n').length} lines</span>
                    </div>
                  </div>
                </div>
                
                {/* Editor Content */}
                <div className="h-[520px] bg-gray-950/50">
                  {codeViewMode === 'diff' ? (
                    <DiffEditor
                      height="100%"
                      language={language}
                      original={originalCode}
                      modified={code}
                      theme={theme === 'light' ? 'vs' : 'vs-dark'}
                      options={{
                        readOnly: true,
                        renderSideBySide: true,
                        minimap: { enabled: showMinimap },
                        fontSize: 14,
                        fontFamily: "'JetBrains Mono', monospace",
                        padding: { top: 20, bottom: 20 },
                      }}
                    />
                  ) : codeViewMode === 'original' ? (
                    <Editor
                      height="100%"
                      language={language}
                      value={originalCode}
                      theme={theme === 'light' ? 'vs' : 'vs-dark'}
                      options={{
                        readOnly: true,
                        minimap: { enabled: showMinimap },
                        fontSize: 14,
                        fontFamily: "'JetBrains Mono', monospace",
                        fontLigatures: true,
                        padding: { top: 20, bottom: 20 },
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        renderLineHighlight: 'line',
                      }}
                    />
                  ) : codeViewMode === 'fixed' ? (
                    <Editor
                      height="100%"
                      language={language}
                      value={code}
                      theme={theme === 'light' ? 'vs' : 'vs-dark'}
                      options={{
                        readOnly: true,
                        minimap: { enabled: showMinimap },
                        fontSize: 14,
                        fontFamily: "'JetBrains Mono', monospace",
                        fontLigatures: true,
                        padding: { top: 20, bottom: 20 },
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        renderLineHighlight: 'line',
                      }}
                    />
                  ) : (
                    <Editor
                      height="100%"
                      language={language}
                      value={code}
                      onChange={(value) => setCode(value || '')}
                      onMount={handleEditorMount}
                      theme={theme === 'light' ? 'vs' : 'vs-dark'}
                      options={{
                        minimap: { enabled: showMinimap },
                        fontSize: 14,
                        fontFamily: "'JetBrains Mono', monospace",
                        fontLigatures: true,
                        padding: { top: 20, bottom: 20 },
                        lineNumbers: 'on',
                        scrollBeyondLastLine: false,
                        renderLineHighlight: 'line',
                        cursorBlinking: 'smooth',
                        smoothScrolling: true,
                        bracketPairColorization: { enabled: true },
                        glyphMargin: true,
                      }}
                    />
                  )}
                </div>
              </div>

              {/* Saved Codes Library */}
              {savedCodes.length > 0 && (
                <div className="glass rounded-xl p-4 border border-white/5">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <BookOpen className="w-4 h-4 text-amber-400" />
                      <span className="text-sm font-medium text-slate-300">
                        Bookmarks ({filteredSavedCodes.length})
                      </span>
                    </div>
                    
                    {/* Filter buttons */}
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setBookmarkFilter(null)}
                        className={`px-2 py-1 text-xs rounded-lg transition-all ${
                          !bookmarkFilter ? 'bg-violet-500/20 text-violet-300' : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        All
                      </button>
                      <button
                        onClick={() => setBookmarkFilter('favorites')}
                        className={`px-2 py-1 text-xs rounded-lg transition-all ${
                          bookmarkFilter === 'favorites' ? 'bg-amber-500/20 text-amber-300' : 'text-slate-500 hover:text-slate-300'
                        }`}
                      >
                        ★
                      </button>
                      {allTags.slice(0, 3).map(tag => (
                        <button
                          key={tag}
                          onClick={() => setBookmarkFilter(tag === bookmarkFilter ? null : tag)}
                          className={`px-2 py-1 text-xs rounded-lg transition-all ${
                            bookmarkFilter === tag ? 'bg-violet-500/20 text-violet-300' : 'text-slate-500 hover:text-slate-300'
                          }`}
                        >
                          #{tag}
                        </button>
                      ))}
                    </div>
                  </div>
                  
                  <div className="flex flex-wrap gap-2">
                    {filteredSavedCodes.map(saved => (
                      <div 
                        key={saved.id} 
                        className={`group flex items-center gap-1 rounded-lg pl-2 pr-1 py-1 transition-all ${
                          saved.favorite 
                            ? 'bg-amber-500/10 border border-amber-500/20' 
                            : 'bg-slate-800/50 hover:bg-slate-800/80'
                        }`}
                      >
                        {/* Favorite star */}
                        <button
                          onClick={() => toggleFavorite(saved.id)}
                          className={`p-0.5 transition-all ${
                            saved.favorite ? 'text-amber-400' : 'text-slate-600 hover:text-amber-400 opacity-0 group-hover:opacity-100'
                          }`}
                        >
                          <span className="text-xs">{saved.favorite ? '★' : '☆'}</span>
                        </button>
                        
                        {/* Name + compliance indicator */}
                        <button
                          onClick={() => handleLoadCode(saved)}
                          className="flex items-center gap-1.5 text-sm text-slate-300 hover:text-white"
                        >
                          {saved.lastAnalysis && (
                            <span className={`w-1.5 h-1.5 rounded-full ${
                              saved.lastAnalysis.compliant ? 'bg-emerald-400' : 'bg-red-400'
                            }`} />
                          )}
                          {saved.name}
                        </button>
                        
                        {/* Tags */}
                        {saved.tags && saved.tags.length > 0 && (
                          <span className="text-[10px] text-violet-400 bg-violet-500/10 px-1.5 py-0.5 rounded-full">
                            {saved.tags[0]}
                          </span>
                        )}
                        
                        {/* Delete */}
                        <button
                          onClick={() => handleDeleteSaved(saved.id)}
                          className="p-1 text-slate-500 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Real-time Analysis Toggle */}
              <div className="flex items-center justify-between glass rounded-xl px-4 py-3 border border-white/5 mb-4">
                <div className="flex items-center gap-3">
                  <div className={`relative w-10 h-6 rounded-full transition-colors cursor-pointer ${
                    realTimeEnabled ? 'bg-cyan-500' : 'bg-slate-700'
                  }`} onClick={() => setRealTimeEnabled(!realTimeEnabled)}>
                    <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all shadow ${
                      realTimeEnabled ? 'left-5' : 'left-1'
                    }`} />
                  </div>
                  <div>
                    <span className="text-sm font-medium text-white">Real-time Analysis</span>
                    <span className="text-xs text-slate-500 ml-2">
                      {realTimeEnabled ? 'Analyzing as you type' : 'Disabled'}
                    </span>
                  </div>
                </div>
                {realTimeLoading && (
                  <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                )}
              </div>
              
              {/* Action Buttons */}
              <div className="flex gap-4">
                <button
                  onClick={handleAnalyze}
                  disabled={isProcessing}
                  className="flex-1 flex items-center justify-center gap-3 px-6 py-4 glass rounded-xl
                           text-white font-semibold transition-all duration-300
                           hover:bg-slate-800/80 disabled:opacity-50 disabled:cursor-not-allowed
                           border border-white/5 hover:border-white/10"
                >
                  {workflow.step === 'prosecutor' || workflow.step === 'adjudicator' ? (
                    <RefreshCw className="w-5 h-5 animate-spin" />
                  ) : (
                    <Search className="w-5 h-5 text-cyan-400" />
                  )}
                  <span>Analyze</span>
                  <kbd className="hidden sm:inline-block ml-2 px-1.5 py-0.5 text-[10px] bg-slate-700/50 text-slate-400 rounded">⌘↵</kbd>
                </button>
                <div className="relative group">
                  <button
                    onClick={() => handleGenerateReport('json')}
                    disabled={isProcessing || reportLoading}
                    className="flex items-center justify-center gap-3 px-6 py-4 glass rounded-xl
                             text-white font-semibold transition-all duration-300
                             hover:bg-amber-500/20 disabled:opacity-50 disabled:cursor-not-allowed
                             border border-amber-500/30 hover:border-amber-500/50"
                  >
                    {reportLoading ? (
                      <RefreshCw className="w-5 h-5 animate-spin text-amber-400" />
                    ) : (
                      <FileCheck className="w-5 h-5 text-amber-400" />
                    )}
                    <span className="text-amber-400">Report</span>
                  </button>
                  {/* Dropdown for format options */}
                  <div className="absolute top-full left-0 mt-2 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
                    <div className="glass rounded-xl border border-white/10 p-2 min-w-[160px] shadow-xl">
                      <button
                        onClick={() => handleGenerateReport('json')}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                      >
                        📊 View JSON Report
                      </button>
                      <button
                        onClick={() => handleGenerateReport('markdown')}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                      >
                        📝 Download Markdown
                      </button>
                      <button
                        onClick={() => handleGenerateReport('html')}
                        className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                      >
                        🌐 Download HTML
                      </button>
                    </div>
                  </div>
                </div>
                <button
                  onClick={handleEnforce}
                  disabled={isProcessing}
                  className="flex-[2] flex items-center justify-center gap-3 px-8 py-4 rounded-xl
                           font-semibold transition-all duration-300 btn-glow
                           bg-gradient-to-r from-emerald-600 via-emerald-500 to-cyan-500
                           hover:from-emerald-500 hover:via-emerald-400 hover:to-cyan-400
                           disabled:from-slate-700 disabled:to-slate-700 disabled:text-slate-400
                           text-white shadow-lg shadow-emerald-500/25"
                >
                  {workflow.step === 'generator' ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      <span>AI Fixing Code...</span>
                    </>
                  ) : workflow.step === 'proof' ? (
                    <>
                      <Lock className="w-5 h-5 animate-pulse" />
                      <span>Signing Proof...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-5 h-5" />
                      <span>Auto-Fix & Certify</span>
                      <kbd className="hidden sm:inline-block ml-2 px-1.5 py-0.5 text-[10px] bg-white/10 text-white/60 rounded">⇧⌘↵</kbd>
                    </>
                  )}
                </button>
              </div>

              {/* Error Display */}
              {error && (
                <div className="glass rounded-xl p-4 border border-red-500/30 bg-red-500/10 animate-slide-up">
                  <div className="flex items-center gap-3">
                    <XCircle className="w-5 h-5 text-red-400" />
                    <span className="text-red-300">{error}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Right Panel - Results (2 cols) */}
            <div className="xl:col-span-2 space-y-5">
              {/* Analysis Progress */}
              {analysisProgress && analysisProgress.phase !== 'complete' && (
                <div className="glass rounded-2xl p-4 border border-violet-500/30 bg-violet-500/5 animate-pulse">
                  <div className="flex items-center gap-3">
                    <RefreshCw className="w-5 h-5 text-violet-400 animate-spin" />
                    <div className="flex-1">
                      <div className="text-sm font-semibold text-violet-400">
                        {analysisProgress.phase === 'detecting' && 'Detecting Language'}
                        {analysisProgress.phase === 'tools' && 'Running Static Analysis Tools'}
                        {analysisProgress.phase === 'policies' && 'Running Policy Checks'}
                        {analysisProgress.phase === 'adjudicating' && 'Adjudicating Compliance'}
                        {analysisProgress.phase === 'starting' && 'Starting Analysis'}
                        {analysisProgress.phase === 'generating' && 'Auto-Fixing with Model'}
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        {analysisProgress.message}
                        {analysisProgress.tool && ` (${analysisProgress.tool})`}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-1 flex flex-wrap items-center gap-2">
                        <span>Elapsed: {formatMsSeconds(analysisElapsedMs)}</span>
                        {analysisProgress.phase === 'generating' && (
                          <>
                            <span>•</span>
                            <span>Waiting for model response and iteration checks</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Compliance Status */}
              <ComplianceStatus 
                adjudication={adjudication} 
                violations={analysis?.violations ?? []}
                enforceResult={enforceResult}
                isAnalyzing={isActivelyAnalyzing}
                analysis={analysis}
                policies={policies}
              />

              {/* Tool Execution Status */}
              {analysis && analysis.tool_execution && Object.keys(analysis.tool_execution).length > 0 && (
                <ToolExecutionStatus toolExecution={analysis.tool_execution} />
              )}

              {/* Unmapped Findings - Prominent Section */}
              {analysis && analysis.tool_execution && (() => {
                const allUnmapped: Array<{tool: string; finding: any}> = [];
                Object.entries(analysis.tool_execution).forEach(([toolName, info]: [string, any]) => {
                  if (info.success && info.findings) {
                    info.findings
                      .filter((f: any) => !f.mapped)
                      .forEach((finding: any) => {
                        allUnmapped.push({ tool: toolName, finding });
                      });
                  }
                });
                return allUnmapped.length > 0 ? (
                  <UnmappedFindingsSection 
                    unmappedFindings={allUnmapped}
                    onCreateMapping={(toolName: string, ruleId: string) => {
                      setViewMode('tools');
                      // Navigate to mappings tab and pre-fill form
                      // Use a longer timeout to ensure ToolsConfigurationView is mounted
                      setTimeout(() => {
                        const event = new CustomEvent('createMapping', { 
                          detail: { toolName, toolRuleId: ruleId } 
                        });
                        window.dispatchEvent(event);
                        // Re-dispatch after a short delay to ensure ToolMappingsView receives it
                        setTimeout(() => {
                          window.dispatchEvent(event);
                        }, 200);
                      }, 300);
                    }}
                  />
                ) : null;
              })()}

              {/* Violations List */}
              {analysis && analysis.violations.length > 0 && (
                <ViolationsList 
                  violations={analysis.violations} 
                  policies={policies} 
                  onLineClick={highlightLine}
                />
              )}

              {/* Proof Bundle Quick View */}
              {enforceResult?.proof_bundle && (
                <ProofBundleCard 
                  proof={enforceResult.proof_bundle} 
                  onCopy={handleCopyProof}
                  onViewFull={() => setViewMode('proof')}
                  copied={copied}
                />
              )}

              {/* Policy Reference (collapsed) */}
              <PolicyPanel policies={policies} />
            </div>
          </div>
        )}
      </main>

      {/* Save Dialog */}
      {showSaveDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="glass rounded-2xl p-6 w-[420px] border border-white/10">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-amber-400" />
              Save Code Bookmark
            </h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-2">Name</label>
                <input
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  placeholder="Enter a name..."
                  className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/50"
                  autoFocus
                />
              </div>
              
              <div>
                <label className="block text-sm text-slate-400 mb-2">Tags (comma-separated)</label>
                <input
                  type="text"
                  value={saveTags}
                  onChange={(e) => setSaveTags(e.target.value)}
                  placeholder="e.g., auth, api, security"
                  className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/50"
                />
                {allTags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    <span className="text-xs text-slate-500 mr-1">Existing:</span>
                    {allTags.slice(0, 5).map(tag => (
                      <button
                        key={tag}
                        onClick={() => setSaveTags(prev => prev ? `${prev}, ${tag}` : tag)}
                        className="px-2 py-0.5 text-xs bg-violet-500/10 text-violet-400 hover:bg-violet-500/20 rounded-full"
                      >
                        {tag}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              
              {adjudication && (
                <div className={`p-3 rounded-xl border text-sm ${
                  adjudication.compliant 
                    ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' 
                    : 'bg-red-500/10 border-red-500/20 text-red-400'
                }`}>
                  {adjudication.compliant ? '✓ Will save as compliant' : `⚠ Will save with ${analysis?.violations.length || 0} violations`}
                </div>
              )}
            </div>
            
            <div className="flex gap-3 mt-6">
              <button
                onClick={() => { setShowSaveDialog(false); setSaveName(''); setSaveTags(''); }}
                className="flex-1 px-4 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveCode}
                disabled={!saveName.trim()}
                className="flex-1 px-4 py-2 bg-emerald-500 text-white rounded-xl hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500"
              >
                Save Bookmark
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Compliance Report Modal */}
      {showReportModal && complianceReport && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
            {/* Header */}
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-xl ${
                  complianceReport.compliance_status?.compliant 
                    ? 'bg-emerald-500/20 border border-emerald-500/30' 
                    : 'bg-red-500/20 border border-red-500/30'
                }`}>
                  {complianceReport.compliance_status?.compliant ? (
                    <ShieldCheck className="w-8 h-8 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-8 h-8 text-red-400" />
                  )}
                </div>
                <div>
                  <h3 className="text-xl font-semibold text-white">Compliance Report</h3>
                  <p className={`text-sm ${complianceReport.compliance_status?.compliant ? 'text-emerald-400' : 'text-red-400'}`}>
                    {complianceReport.compliance_status?.status}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleGenerateReport('markdown')}
                  className="px-4 py-2 text-sm text-slate-300 hover:text-white border border-slate-700 rounded-xl flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Markdown
                </button>
                <button
                  onClick={() => handleGenerateReport('html')}
                  className="px-4 py-2 text-sm text-slate-300 hover:text-white border border-slate-700 rounded-xl flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  HTML
                </button>
                <button 
                  onClick={() => setShowReportModal(false)} 
                  className="p-2 text-slate-400 hover:text-white"
                >
                  <XCircle className="w-6 h-6" />
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Executive Summary */}
              <div className="glass rounded-xl p-6 border border-white/5">
                <h4 className="text-lg font-semibold text-white mb-3">Executive Summary</h4>
                <p className="text-slate-300 leading-relaxed">{complianceReport.executive_summary}</p>
              </div>

              {/* Summary Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="glass rounded-xl p-4 text-center border border-white/5">
                  <div className="text-3xl font-bold text-white">{complianceReport.summary?.total_violations ?? 0}</div>
                  <div className="text-sm text-slate-400">Total Violations</div>
                </div>
                <div className="glass rounded-xl p-4 text-center border border-red-500/20">
                  <div className="text-3xl font-bold text-red-400">{complianceReport.summary?.critical_count ?? 0}</div>
                  <div className="text-sm text-slate-400">Critical</div>
                </div>
                <div className="glass rounded-xl p-4 text-center border border-orange-500/20">
                  <div className="text-3xl font-bold text-orange-400">{complianceReport.summary?.high_count ?? 0}</div>
                  <div className="text-sm text-slate-400">High</div>
                </div>
                <div className="glass rounded-xl p-4 text-center border border-white/5">
                  <div className="text-3xl font-bold text-amber-400">{complianceReport.summary?.risk_score ?? 0}/100</div>
                  <div className="text-sm text-slate-400">Risk Score</div>
                </div>
              </div>

              {/* Violations */}
              {complianceReport.violations?.length > 0 && (
                <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Violations</h4>
                  <div className="space-y-3">
                    {complianceReport.violations.map((v: any, i: number) => (
                      <div key={i} className={`glass rounded-xl p-4 border-l-4 ${
                        v.severity === 'critical' ? 'border-l-red-500 bg-red-500/5' :
                        v.severity === 'high' ? 'border-l-orange-500 bg-orange-500/5' :
                        v.severity === 'medium' ? 'border-l-amber-500 bg-amber-500/5' :
                        'border-l-slate-500 bg-slate-500/5'
                      }`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-semibold text-violet-400">{v.id}</span>
                            <span className={`px-2 py-0.5 text-[10px] uppercase font-bold rounded ${
                              v.severity === 'critical' ? 'bg-red-500 text-white' :
                              v.severity === 'high' ? 'bg-orange-500 text-white' :
                              v.severity === 'medium' ? 'bg-amber-500 text-black' :
                              'bg-slate-600 text-white'
                            }`}>
                              {v.severity}
                            </span>
                          </div>
                          {v.location?.line && (
                            <span className="text-xs text-slate-500">Line {v.location.line}</span>
                          )}
                        </div>
                        <p className="text-sm text-slate-300 mb-2">{v.description}</p>
                        {v.location?.evidence && (
                          <div className="bg-slate-900/50 rounded-lg p-3 font-mono text-xs text-slate-300 mb-2 overflow-x-auto">
                            {v.location.evidence}
                          </div>
                        )}
                        {v.fix_suggestion && (
                          <div className="flex items-start gap-2 text-sm">
                            <span className="text-cyan-400">💡</span>
                            <span className="text-cyan-300">{v.fix_suggestion}</span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {complianceReport.recommendations?.length > 0 && (
                <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Recommendations</h4>
                  <div className="space-y-3">
                    {complianceReport.recommendations.map((rec: any, i: number) => (
                      <div key={i} className="glass rounded-xl p-4 border border-white/5">
                        <div className="flex items-start gap-4">
                          <div className="flex-shrink-0 w-8 h-8 bg-violet-500/20 rounded-full flex items-center justify-center text-violet-400 font-bold">
                            {rec.priority}
                          </div>
                          <div className="flex-1">
                            <h5 className="text-white font-medium mb-1">{rec.title}</h5>
                            <div className="flex flex-wrap gap-3 text-xs text-slate-400 mb-2">
                              <span>Severity: <span className={
                                rec.severity === 'critical' ? 'text-red-400' :
                                rec.severity === 'high' ? 'text-orange-400' :
                                rec.severity === 'medium' ? 'text-amber-400' :
                                'text-slate-400'
                              }>{rec.severity}</span></span>
                              <span>Occurrences: {rec.occurrences}</span>
                              <span>Effort: {rec.effort}</span>
                            </div>
                            <p className="text-sm text-slate-300">{rec.action}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Signature */}
              {complianceReport.signature && (
                <div className="glass rounded-xl p-4 border border-emerald-500/20 bg-emerald-500/5">
                  <div className="flex items-center gap-3 mb-2">
                    <Lock className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-semibold text-emerald-400">Cryptographically Signed</span>
                  </div>
                  <div className="font-mono text-xs text-slate-500 break-all">
                    {complianceReport.signature.value?.slice(0, 64)}...
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    Fingerprint: {complianceReport.signature.public_key_fingerprint}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Toast Notifications */}
      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}

// Workflow Pipeline Component
function WorkflowPipeline({ workflow }: { workflow: WorkflowState }) {
  const steps = [
    { id: 'prosecutor', label: 'Prosecutor', icon: Search, description: 'Static Analysis' },
    { id: 'adjudicator', label: 'Adjudicator', icon: Scale, description: 'Formal Logic' },
    { id: 'generator', label: 'Generator', icon: Bot, description: 'AI Code Fix' },
    { id: 'proof', label: 'Proof', icon: Fingerprint, description: 'ECDSA Signing' },
  ];

  const getStepStatus = (stepId: string) => {
    const stepOrder = ['prosecutor', 'adjudicator', 'generator', 'proof', 'complete'];
    const currentIndex = stepOrder.indexOf(workflow.step);
    const stepIndex = stepOrder.indexOf(stepId);
    
    if (workflow.step === 'idle') return 'idle';
    if (stepIndex < currentIndex) return 'complete';
    if (stepIndex === currentIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="glass rounded-2xl p-6 border border-white/5">
      <div className="flex items-center justify-between">
        {steps.map((step, index) => {
          const status = getStepStatus(step.id);
          const Icon = step.icon;
          
          return (
            <div key={step.id} className="flex items-center flex-1">
              <div className="flex flex-col items-center flex-1">
                <div className={`
                  relative w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-500
                  ${status === 'complete' ? 'bg-emerald-500/20 border-2 border-emerald-500/50' : 
                    status === 'active' ? 'bg-cyan-500/20 border-2 border-cyan-500/50 animate-pulse-ring' : 
                    'bg-slate-800/50 border-2 border-slate-700/50'}
                `}>
                  {status === 'complete' ? (
                    <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                  ) : (
                    <Icon className={`w-6 h-6 ${status === 'active' ? 'text-cyan-400' : 'text-slate-500'}`} />
                  )}
                  {status === 'active' && (
                    <div className="absolute inset-0 rounded-2xl border-2 border-cyan-400/30 animate-ping" />
                  )}
                </div>
                <div className="mt-3 text-center">
                  <div className={`font-semibold text-sm ${
                    status === 'complete' ? 'text-emerald-400' : 
                    status === 'active' ? 'text-cyan-400' : 'text-slate-500'
                  }`}>
                    {step.label}
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5">{step.description}</div>
                </div>
              </div>
              {index < steps.length - 1 && (
                <div className="flex-shrink-0 w-16 h-0.5 mx-2 mb-8">
                  <div className={`h-full rounded transition-all duration-500 ${
                    getStepStatus(steps[index + 1].id) === 'complete' || getStepStatus(steps[index + 1].id) === 'active'
                      ? 'bg-gradient-to-r from-emerald-500 to-cyan-500' 
                      : 'bg-slate-700/50'
                  }`} />
                </div>
              )}
            </div>
          );
        })}
        
        {/* Final Status */}
        <div className="flex flex-col items-center ml-4">
          <div className={`
            w-14 h-14 rounded-2xl flex items-center justify-center transition-all duration-500
            ${workflow.step === 'complete' && workflow.violations === 0
              ? 'bg-emerald-500/20 border-2 border-emerald-500/50 glow-emerald' 
              : workflow.step === 'complete'
              ? 'bg-amber-500/20 border-2 border-amber-500/50'
              : 'bg-slate-800/50 border-2 border-slate-700/50'}
          `}>
            {workflow.step === 'complete' ? (
              workflow.violations === 0 ? (
                <ShieldCheck className="w-6 h-6 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-6 h-6 text-amber-400" />
              )
            ) : (
              <Shield className="w-6 h-6 text-slate-500" />
            )}
          </div>
          <div className="mt-3 text-center">
            <div className={`font-semibold text-sm ${
              workflow.step === 'complete' && workflow.violations === 0 ? 'text-emerald-400' :
              workflow.step === 'complete' ? 'text-amber-400' : 'text-slate-500'
            }`}>
              Status
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {workflow.step === 'complete' ? (workflow.violations === 0 ? 'Certified' : 'Partial') : 'Pending'}
            </div>
          </div>
        </div>
      </div>
      
      {workflow.iteration > 0 && (
        <div className="mt-4 pt-4 border-t border-white/5 flex items-center justify-center gap-3">
          <Clock className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-400">
            Iteration <span className="text-cyan-400 font-semibold">{workflow.iteration}</span> of {workflow.maxIterations}
          </span>
          {workflow.violations > 0 && (
            <>
              <span className="text-slate-600">•</span>
              <span className="text-sm text-slate-400">
                <span className="text-amber-400 font-semibold">{workflow.violations}</span> violations remaining
              </span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// Compliance Status Component with enhanced animations
function ComplianceStatus({ 
  adjudication, 
  violations,
  enforceResult,
  isAnalyzing,
  analysis,
  policies,
}: { 
  adjudication: AdjudicationResult | null;
  violations: Violation[];
  enforceResult: EnforceResponse | null;
  isAnalyzing: boolean;
  analysis: AnalysisResult | null;
  policies: PolicyRule[];
}) {
  // Count violations by severity
  const severityCounts = violations.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const violationCount = violations.length;

  if (!adjudication && isAnalyzing) {
    return (
      <div className="glass rounded-2xl p-6 border border-violet-500/20 bg-violet-500/5 animate-fade-in">
        <div className="flex items-center gap-4">
          <div className="p-4 rounded-2xl bg-violet-500/15 border border-violet-500/20">
            <RefreshCw className="w-10 h-10 text-violet-400 animate-spin" />
          </div>
          <div>
            <h3 className="text-xl font-display font-semibold text-violet-300">Analyzing…</h3>
            <p className="text-sm text-slate-400 mt-1">Running tools, policy checks, and adjudication</p>
          </div>
        </div>
      </div>
    );
  }

  if (!adjudication) {
    return (
      <div className="glass rounded-2xl p-6 border border-white/5 animate-fade-in">
        <div className="flex items-center gap-4">
          <div className="p-4 rounded-2xl bg-slate-800/50 animate-float">
            <Shield className="w-10 h-10 text-slate-500" />
          </div>
          <div>
            <h3 className="text-xl font-display font-semibold text-slate-300">Ready to Analyze</h3>
            <p className="text-sm text-slate-500 mt-1">Submit code to check compliance with security policies</p>
          </div>
        </div>
      </div>
    );
  }

  const isCompliant = adjudication.compliant;
  const totalPolicies = adjudication.satisfied_rules.length + violationCount;
  const passRate = totalPolicies > 0 ? (adjudication.satisfied_rules.length / totalPolicies) * 100 : 0;
  const enforceFailure = buildEnforceFailureExplanation(enforceResult, violations, policies);
  const iterationDiagnostics = enforceResult?.performance?.iterations ?? [];
  const fixIterationDiagnostics = iterationDiagnostics.filter((item) => item.fix_attempted);
  const avgFixSeconds = fixIterationDiagnostics.length > 0
    ? fixIterationDiagnostics.reduce((sum, item) => sum + (item.fix_seconds ?? 0), 0) / fixIterationDiagnostics.length
    : null;

  return (
    <div className={`relative glass rounded-2xl p-6 border overflow-hidden ${
      isCompliant 
        ? 'border-emerald-500/30 animate-success-celebration animate-success-glow' 
        : 'border-red-500/30 animate-warning-shake animate-warning-glow'
    }`}>
      {/* Background gradient effect */}
      <div className={`absolute inset-0 opacity-10 ${
        isCompliant 
          ? 'bg-gradient-to-br from-emerald-500 via-transparent to-cyan-500' 
          : 'bg-gradient-to-br from-red-500 via-transparent to-orange-500'
      }`} />
      
      {/* Animated particles for compliant state */}
      {isCompliant && (
        <div className="particles">
          {[...Array(6)].map((_, i) => (
            <div 
              key={i}
              className="particle bg-emerald-400"
              style={{
                left: `${20 + i * 12}%`,
                bottom: '20%',
                animationDelay: `${i * 0.15}s`
              }}
            />
          ))}
        </div>
      )}
      
      <div className="relative flex items-start gap-4">
        {/* Animated icon with ring */}
        <div className="relative">
          <div className={`absolute inset-0 rounded-2xl animate-pulse-ring ${
            isCompliant ? 'bg-emerald-500/20' : 'bg-red-500/20'
          }`} />
          <div className={`relative p-4 rounded-2xl ${
            isCompliant ? 'bg-emerald-500/10' : 'bg-red-500/10'
          }`}>
            {isCompliant ? (
              <ShieldCheck className="w-10 h-10 text-emerald-400 animate-bounce-in" />
            ) : (
              <ShieldAlert className="w-10 h-10 text-red-400 animate-bounce-in" />
            )}
          </div>
        </div>
        
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h3 className={`text-xl font-display font-bold ${
              isCompliant ? 'text-emerald-400' : 'text-red-400'
            }`}>
              {isCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
            </h3>
            {isCompliant && (
              <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/20 text-emerald-400 rounded-full animate-badge-pulse border border-emerald-500/30">
                ✓ CERTIFIED
              </span>
            )}
            {!isCompliant && (
              <span className="px-2 py-0.5 text-xs font-semibold bg-red-500/20 text-red-400 rounded-full animate-badge-pulse border border-red-500/30">
                ⚠ ACTION REQUIRED
              </span>
            )}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            {isCompliant 
              ? `All ${adjudication.satisfied_rules.length} security policies satisfied`
              : `${violationCount} violation${violationCount !== 1 ? 's' : ''} require attention`
            }
          </p>
          
          {/* Progress bar */}
          <div className="mt-3 mb-2">
            <div className="flex justify-between text-xs mb-1">
              <span className="text-slate-500">Compliance Progress</span>
              <span className={isCompliant ? 'text-emerald-400' : 'text-slate-400'}>
                {passRate.toFixed(0)}%
              </span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className={`h-full rounded-full transition-all duration-1000 ease-out ${
                  isCompliant 
                    ? 'bg-gradient-to-r from-emerald-500 to-cyan-500' 
                    : 'bg-gradient-to-r from-red-500 to-orange-500'
                }`}
                style={{ width: `${passRate}%` }}
              />
            </div>
          </div>
          
          {/* Severity breakdown for non-compliant */}
          {!isCompliant && violationCount > 0 && (
            <div className="flex items-center gap-2 mt-3 flex-wrap">
              {severityCounts.critical > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-red-500/20 text-red-400 rounded border border-red-500/30 animate-pulse">
                  {severityCounts.critical} critical
                </span>
              )}
              {severityCounts.high > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-orange-500/20 text-orange-400 rounded border border-orange-500/30">
                  {severityCounts.high} high
                </span>
              )}
              {severityCounts.medium > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-amber-500/20 text-amber-400 rounded border border-amber-500/30">
                  {severityCounts.medium} medium
                </span>
              )}
              {severityCounts.low > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-slate-500/20 text-slate-400 rounded border border-slate-500/30">
                  {severityCounts.low} low
                </span>
              )}
            </div>
          )}

          {!isCompliant && enforceFailure && (
            <div className="mt-4 p-3 rounded-xl border border-amber-500/30 bg-amber-500/10">
              <div className="text-sm font-semibold text-amber-200">{enforceFailure.title}</div>
              <p className="text-xs text-slate-300 mt-1">{enforceFailure.detail}</p>
              {enforceFailure.reasonCode && (
                <p className="text-[11px] text-slate-500 mt-1 font-mono">
                  reason: {enforceFailure.reasonCode}
                </p>
              )}
              {enforceFailure.targetedActions && enforceFailure.targetedActions.length > 0 && (
                <div className="mt-2 text-xs text-cyan-200">
                  <p className="text-[11px] uppercase tracking-wide text-cyan-300/80 mb-1">Targeted next fixes</p>
                  {enforceFailure.targetedActions.map((action, idx) => (
                    <p key={idx}>• {action}</p>
                  ))}
                </div>
              )}
              {enforceFailure.actions.length > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  {enforceFailure.actions.map((action, idx) => (
                    <p key={idx}>• {action}</p>
                  ))}
                </div>
              )}
            </div>
          )}
          
          {enforceResult && (
            <div className="flex items-center gap-4 mt-4 pt-4 border-t border-white/5">
              <div className="text-center">
                <div className="text-2xl font-bold text-white">{enforceResult.iterations}</div>
                <div className="text-xs text-slate-500">Iterations</div>
              </div>
              <div className="h-8 w-px bg-slate-700" />
              <div className="text-center">
                <div className="text-2xl font-bold text-emerald-400 animate-bounce-in" style={{ animationDelay: '0.2s' }}>
                  {adjudication.satisfied_rules.length}
                </div>
                <div className="text-xs text-slate-500">Passed</div>
              </div>
              {!isCompliant && (
                <>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-400 animate-bounce-in" style={{ animationDelay: '0.3s' }}>
                      {violationCount}
                    </div>
                    <div className="text-xs text-slate-500">Failed</div>
                  </div>
                </>
              )}
              <div className="h-8 w-px bg-slate-700" />
              <div className="text-center">
                <div className="text-2xl font-bold text-slate-300">{totalPolicies}</div>
                <div className="text-xs text-slate-500">Total</div>
              </div>
              {analysis?.performance && (
                <>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-lg font-bold text-violet-300">
                      {analysis.performance.total_seconds.toFixed(2)}s
                    </div>
                    <div className="text-xs text-slate-500">Analyze Time</div>
                  </div>
                </>
              )}
              {enforceResult.llm_usage && (
                <>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-lg font-bold text-cyan-300">
                      {enforceResult.llm_usage.estimated_cost_usd != null
                        ? `$${enforceResult.llm_usage.estimated_cost_usd.toFixed(6)}`
                        : 'n/a'}
                    </div>
                    <div className="text-xs text-slate-500">Run Cost</div>
                  </div>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-lg font-bold text-slate-300">
                      {enforceResult.llm_usage.total_tokens?.toLocaleString() ?? 0}
                    </div>
                    <div className="text-xs text-slate-500">LLM Tokens</div>
                  </div>
                </>
              )}
              {enforceResult?.performance && (
                <>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-lg font-bold text-violet-300">
                      {enforceResult.performance.total_seconds.toFixed(2)}s
                    </div>
                    <div className="text-xs text-slate-500">Enforce Time</div>
                  </div>
                </>
              )}
            </div>
          )}
          {analysis?.performance && (
            <div className="mt-3 pt-3 border-t border-white/5 text-xs text-slate-400 flex flex-wrap gap-3">
              <span>Tools: {analysis.performance.static_tools_seconds.toFixed(2)}s</span>
              <span>Policies: {analysis.performance.policy_checks_seconds.toFixed(2)}s</span>
              {analysis.performance.dynamic_analysis_seconds != null && (
                <span>Dynamic: {analysis.performance.dynamic_analysis_seconds.toFixed(2)}s</span>
              )}
              {adjudication.timing_seconds != null && (
                <span>Adjudication: {adjudication.timing_seconds.toFixed(2)}s</span>
              )}
            </div>
          )}
          {enforceResult?.llm_usage && (
            <div className="mt-2 text-xs text-slate-500">
              Endpoint usage: {Object.entries(enforceResult.llm_usage.endpoint_breakdown || {})
                .map(([endpoint, count]) => `${endpoint} (${count})`)
                .join(', ') || 'n/a'}
            </div>
          )}
          {enforceResult?.performance && (
            <div className="mt-2 text-xs text-slate-500 flex flex-wrap gap-3">
              <span>Analyze: {enforceResult.performance.analysis_seconds.toFixed(2)}s</span>
              <span>Adjudicate: {enforceResult.performance.adjudication_seconds.toFixed(2)}s</span>
              <span>Fix: {enforceResult.performance.fix_seconds.toFixed(2)}s</span>
              <span>Proof: {enforceResult.performance.proof_seconds.toFixed(2)}s</span>
              {enforceResult.performance.stopped_early_reason && (
                <span className="text-amber-300">
                  Stop reason: {humanizeStopReason(enforceResult.performance.stopped_early_reason)}
                </span>
              )}
            </div>
          )}
          {iterationDiagnostics.length > 0 && (
            <div className="mt-3 p-3 rounded-xl border border-white/10 bg-slate-900/40">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-300">Iteration diagnostics</div>
                <div className="text-[11px] text-slate-500">
                  Fix attempts: {fixIterationDiagnostics.length}
                  {avgFixSeconds != null && ` • Avg fix latency ${avgFixSeconds.toFixed(2)}s`}
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full text-[11px] text-left text-slate-300">
                  <thead className="text-slate-500">
                    <tr>
                      <th className="py-1 pr-4 font-medium">Iter</th>
                      <th className="py-1 pr-4 font-medium">Violations</th>
                      <th className="py-1 pr-4 font-medium">Analyze</th>
                      <th className="py-1 pr-4 font-medium">Adjudicate</th>
                      <th className="py-1 pr-4 font-medium">Fix</th>
                      <th className="py-1 pr-0 font-medium">Outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iterationDiagnostics.map((item) => {
                      let outcome = 'No fix step';
                      let outcomeClass = 'text-slate-500';
                      if (item.fix_error) {
                        outcome = 'Fix error';
                        outcomeClass = 'text-red-300';
                      } else if (item.fix_attempted && item.fix_changed === false) {
                        outcome = 'Unchanged';
                        outcomeClass = 'text-amber-300';
                      } else if (item.fix_attempted && item.fix_changed === true) {
                        outcome = 'Code changed';
                        outcomeClass = 'text-emerald-300';
                      } else if (item.compliant) {
                        outcome = 'Compliant';
                        outcomeClass = 'text-emerald-300';
                      }

                      return (
                        <tr key={item.iteration} className="border-t border-white/5">
                          <td className="py-1 pr-4 font-mono text-slate-400">{item.iteration}</td>
                          <td className="py-1 pr-4 font-mono">{item.violation_count}</td>
                          <td className="py-1 pr-4 font-mono">{item.analysis_seconds.toFixed(2)}s</td>
                          <td className="py-1 pr-4 font-mono">{item.adjudication_seconds.toFixed(2)}s</td>
                          <td className="py-1 pr-4 font-mono">{item.fix_seconds != null ? `${item.fix_seconds.toFixed(2)}s` : 'n/a'}</td>
                          <td className={`py-1 pr-0 ${outcomeClass}`}>{outcome}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Unmapped Findings Section - Prominent display of all unmapped findings
function UnmappedFindingsSection({ 
  unmappedFindings,
  onCreateMapping
}: { 
  unmappedFindings: Array<{tool: string; finding: any}>;
  onCreateMapping: (toolName: string, ruleId: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="glass rounded-2xl overflow-hidden border border-amber-500/20 animate-slide-up">
      <div className="px-5 py-4 border-b border-amber-500/20 bg-amber-500/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-amber-500/10">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <span className="font-semibold text-slate-200">Unmapped Findings</span>
              <p className="text-xs text-slate-400 mt-0.5">
                {unmappedFindings.length} finding{unmappedFindings.length !== 1 ? 's' : ''} from tools that aren't mapped to policies
              </p>
            </div>
          </div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="px-3 py-1.5 text-sm bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 rounded-lg transition-colors flex items-center gap-2"
          >
            {expanded ? (
              <>
                <ChevronDown className="w-4 h-4" />
                Hide
              </>
            ) : (
              <>
                <ChevronRight className="w-4 h-4" />
                Show All
              </>
            )}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="max-h-[400px] overflow-y-auto p-5 space-y-3 animate-fade-in">
          {unmappedFindings.map((item, i) => (
            <div 
              key={i} 
              className="p-4 bg-amber-500/5 rounded-xl border border-amber-500/20 hover:border-amber-500/40 transition-colors"
            >
              <div className="flex items-start justify-between gap-3 mb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="px-2 py-1 bg-violet-500/20 text-violet-400 text-xs font-mono rounded">
                    {item.tool}
                  </span>
                  <span className="px-2 py-1 bg-amber-500/20 text-amber-400 text-xs font-mono rounded">
                    {item.finding.rule_id}
                  </span>
                  {item.finding.line && (
                    <span className="text-xs text-slate-400">Line {item.finding.line}</span>
                  )}
                  {item.finding.severity && (
                    <span className={`px-2 py-1 text-xs rounded ${
                      item.finding.severity === 'high' || item.finding.severity === 'critical' 
                        ? 'bg-red-500/20 text-red-400' 
                        : item.finding.severity === 'medium'
                        ? 'bg-amber-500/20 text-amber-400'
                        : 'bg-slate-500/20 text-slate-400'
                    }`}>
                      {item.finding.severity}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => onCreateMapping(item.tool, item.finding.rule_id)}
                  className="px-3 py-1.5 text-xs bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
                >
                  <Link2 className="w-3 h-3" />
                  Map Rule
                </button>
              </div>
              <p className="text-sm text-slate-300">{item.finding.message}</p>
            </div>
          ))}
          <div className="mt-4 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <p className="text-xs text-slate-400">
              💡 <strong>Tip:</strong> Click "Map Rule" to create a mapping from this tool rule to an ACPG policy. 
              This will make future findings from this rule appear as violations.
            </p>
          </div>
        </div>
      )}
      {!expanded && unmappedFindings.length > 0 && (
        <div className="px-5 py-3 border-t border-amber-500/20">
          <div className="flex items-center justify-between">
            <div className="text-sm text-slate-400">
              {unmappedFindings.slice(0, 3).map((item, i) => (
                <span key={i} className="mr-3">
                  <span className="font-mono text-amber-400">{item.tool}:{item.finding.rule_id}</span>
                  {item.finding.line && <span className="text-slate-500"> (L{item.finding.line})</span>}
                </span>
              ))}
              {unmappedFindings.length > 3 && (
                <span className="text-slate-500">+ {unmappedFindings.length - 3} more</span>
              )}
            </div>
            <button
              onClick={() => setExpanded(true)}
              className="text-xs text-amber-400 hover:text-amber-300"
            >
              View all →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Tool Execution Status Component
function ToolExecutionStatus({ 
  toolExecution 
}: { 
  toolExecution: Record<string, any>;
}) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showUnmapped, setShowUnmapped] = useState<Record<string, boolean>>({});

  const toggleExpand = (toolName: string) => {
    setExpanded(prev => ({ ...prev, [toolName]: !prev[toolName] }));
  };

  const toggleUnmapped = (toolName: string) => {
    setShowUnmapped(prev => ({ ...prev, [toolName]: !prev[toolName] }));
  };

  const tools = Object.entries(toolExecution);
  const successfulTools = tools.filter(([_, info]) => info.success);
  const failedTools = tools.filter(([_, info]) => !info.success);
  const totalFindings = tools.reduce((sum, [_, info]) => sum + (info.findings_count || 0), 0);
  const totalMapped = tools.reduce((sum, [_, info]) => sum + (info.mapped_findings || 0), 0);
  const totalUnmapped = tools.reduce((sum, [_, info]) => sum + (info.unmapped_findings || 0), 0);

  return (
    <div className="glass rounded-2xl overflow-hidden border border-white/5 animate-slide-up">
      <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-violet-500/10">
            <Terminal className="w-5 h-5 text-violet-400" />
          </div>
          <span className="font-semibold text-slate-200">Tool Execution</span>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-slate-400">
            {successfulTools.length}/{tools.length} tools ran
          </span>
          {totalFindings > 0 && (
            <span className="text-slate-400">
              {totalFindings} findings ({totalMapped} mapped, {totalUnmapped} unmapped)
            </span>
          )}
        </div>
      </div>
      <div className="max-h-[300px] overflow-y-auto">
        {/* Successful Tools */}
        {successfulTools.map(([toolName, info]: [string, any]) => {
          const isExpanded = expanded[toolName];
          const showUnmappedFindings = showUnmapped[toolName];
          
          return (
            <div key={toolName} className="border-b border-white/5 last:border-b-0">
              <button
                onClick={() => toggleExpand(toolName)}
                className="w-full px-5 py-3 flex items-center gap-3 hover:bg-white/[0.02] transition-colors text-left"
              >
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span className="px-2 py-1 text-xs font-mono font-semibold rounded-lg bg-violet-500/20 text-violet-400">
                  {toolName}
                  {info.tool_version && (
                    <span className="ml-1 text-violet-300/70">v{info.tool_version}</span>
                  )}
                </span>
                <span className="flex-1 text-sm text-slate-300">
                  {info.findings_count || 0} findings
                </span>
                <div className="flex items-center gap-2 text-xs">
                  {info.mapped_findings > 0 && (
                    <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 rounded">
                      {info.mapped_findings} mapped
                    </span>
                  )}
                  {info.unmapped_findings > 0 && (
                    <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 rounded">
                      {info.unmapped_findings} unmapped
                    </span>
                  )}
                  {info.execution_time && (
                    <span className="text-slate-500">
                      {(info.execution_time * 1000).toFixed(0)}ms
                    </span>
                  )}
                </div>
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-slate-500" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                )}
              </button>
              {isExpanded && (
                <div className="px-5 pb-3 pl-12 space-y-2 animate-fade-in">
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div className="p-2 bg-slate-800/50 rounded">
                      <div className="text-slate-500">Total Findings</div>
                      <div className="text-white font-semibold">{info.findings_count || 0}</div>
                    </div>
                    <div className="p-2 bg-emerald-500/10 rounded">
                      <div className="text-slate-500">Mapped</div>
                      <div className="text-emerald-400 font-semibold">{info.mapped_findings || 0}</div>
                    </div>
                    <div className="p-2 bg-amber-500/10 rounded">
                      <div className="text-slate-500">Unmapped</div>
                      <div className="text-amber-400 font-semibold">{info.unmapped_findings || 0}</div>
                    </div>
                  </div>
                  {info.unmapped_findings > 0 && (
                    <div>
                      <button
                        onClick={() => toggleUnmapped(toolName)}
                        className="text-xs text-amber-400 hover:text-amber-300 flex items-center gap-1"
                      >
                        {showUnmappedFindings ? (
                          <ChevronDown className="w-3 h-3" />
                        ) : (
                          <ChevronRight className="w-3 h-3" />
                        )}
                        Show {info.unmapped_findings} unmapped finding{info.unmapped_findings !== 1 ? 's' : ''}
                      </button>
                      {showUnmappedFindings && info.findings && (
                        <div className="mt-2 space-y-1 max-h-40 overflow-y-auto">
                          {info.findings
                            .filter((f: any) => !f.mapped)
                            .map((finding: any, i: number) => (
                            <div key={i} className="p-2 bg-amber-500/5 rounded border border-amber-500/20 text-xs">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="px-1.5 py-0.5 bg-amber-500/20 text-amber-400 font-mono rounded">
                                  {finding.rule_id}
                                </span>
                                {finding.line && (
                                  <span className="text-slate-500">Line {finding.line}</span>
                                )}
                                <span className="px-1.5 py-0.5 bg-amber-500/20 text-amber-400 rounded text-[10px]">
                                  Unmapped
                                </span>
                              </div>
                              <div className="text-slate-300">{finding.message}</div>
                            </div>
                          ))}
                          {info.findings.filter((f: any) => f.mapped).length > 0 && (
                            <div className="mt-2 pt-2 border-t border-slate-700">
                              <div className="text-xs text-slate-500 mb-1">Mapped findings:</div>
                              {info.findings
                                .filter((f: any) => f.mapped)
                                .map((finding: any, i: number) => (
                                <div key={i} className="p-2 bg-emerald-500/5 rounded border border-emerald-500/20 text-xs mb-1">
                                  <div className="flex items-center gap-2 mb-1">
                                    <span className="px-1.5 py-0.5 bg-amber-500/20 text-amber-400 font-mono rounded">
                                      {finding.rule_id}
                                    </span>
                                    <span className="text-slate-400">→</span>
                                    <span className="px-1.5 py-0.5 bg-emerald-500/20 text-emerald-400 font-mono rounded">
                                      {finding.policy_id}
                                    </span>
                                    {finding.line && (
                                      <span className="text-slate-500">Line {finding.line}</span>
                                    )}
                                  </div>
                                  <div className="text-slate-300">{finding.message}</div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
        
        {/* Failed Tools */}
        {failedTools.map(([toolName, info]: [string, any]) => (
          <div key={toolName} className="border-b border-white/5 last:border-b-0">
            <div className="px-5 py-3 flex items-center gap-3">
              <XCircle className="w-4 h-4 text-red-400" />
              <span className="px-2 py-1 text-xs font-mono font-semibold rounded-lg bg-violet-500/20 text-violet-400">
                {toolName}
              </span>
              <span className="flex-1 text-sm text-red-400">
                Failed: {info.error || 'Unknown error'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Violations List Component
function ViolationsList({ 
  violations, 
  policies,
  onLineClick
}: { 
  violations: Violation[];
  policies: PolicyRule[];
  onLineClick?: (line: number) => void;
}) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const toggleExpand = (index: number) => {
    setExpanded(prev => ({ ...prev, [index]: !prev[index] }));
  };
  
  const handleLineClick = (line: number | undefined, e: React.MouseEvent) => {
    e.stopPropagation();
    if (line && onLineClick) {
      onLineClick(line);
    }
  };
  
  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'critical': return { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' };
      case 'high': return { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' };
      case 'medium': return { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' };
      default: return { color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/30' };
    }
  };

  // Get violations with available fixes
  const [showQuickFixes, setShowQuickFixes] = useState(true);
  const fixableViolations = violations.filter(v => {
    const policy = policies.find(p => p.id === v.rule_id);
    return policy?.fix_suggestion;
  });

  const [showExportMenu, setShowExportMenu] = useState(false);

  const exportViolations = (format: 'json' | 'csv') => {
    let content: string;
    let filename: string;
    let mimeType: string;

    if (format === 'json') {
      content = JSON.stringify(violations, null, 2);
      filename = `violations-${new Date().toISOString().split('T')[0]}.json`;
      mimeType = 'application/json';
    } else {
      // CSV format
      const headers = ['Rule ID', 'Severity', 'Message', 'Line', 'Category', 'Source'];
      const rows = violations.map(v => [
        v.rule_id,
        v.severity,
        `"${(v.description || '').replace(/"/g, '""')}"`,
        v.line || '',
        '',
        v.detector || ''
      ]);
      content = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      filename = `violations-${new Date().toISOString().split('T')[0]}.csv`;
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    setShowExportMenu(false);
  };

  return (
    <div className="glass rounded-2xl overflow-hidden border border-white/5 animate-slide-up stagger-1">
      <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-500/10">
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <span className="font-semibold text-slate-200">Policy Violations</span>
        </div>
        <div className="flex items-center gap-2">
          {/* Export Button */}
          <div className="relative">
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-all"
              title="Export violations"
            >
              <Download className="w-4 h-4" />
            </button>
            {showExportMenu && (
              <>
                <div className="fixed inset-0 z-40" onClick={() => setShowExportMenu(false)} />
                <div className="absolute right-0 top-full mt-1 w-32 glass rounded-lg border border-white/10 shadow-xl z-50 overflow-hidden">
                  <button
                    onClick={() => exportViolations('json')}
                    className="w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
                  >
                    <FileJson className="w-4 h-4" /> JSON
                  </button>
                  <button
                    onClick={() => exportViolations('csv')}
                    className="w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-white/5 flex items-center gap-2"
                  >
                    <FileText className="w-4 h-4" /> CSV
                  </button>
                </div>
              </>
            )}
          </div>
          <span className="px-3 py-1 text-sm font-semibold bg-red-500/10 text-red-400 rounded-full">
            {violations.length} found
          </span>
        </div>
      </div>
      
      {/* Quick Fixes Summary Panel */}
      {fixableViolations.length > 0 && (
        <div className="border-b border-white/5">
          <button
            onClick={() => setShowQuickFixes(!showQuickFixes)}
            className="w-full px-5 py-3 flex items-center justify-between hover:bg-cyan-500/5 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-medium text-cyan-400">
                Quick Fixes Available ({fixableViolations.length})
              </span>
            </div>
            <ChevronDown className={`w-4 h-4 text-cyan-400 transition-transform ${showQuickFixes ? 'rotate-180' : ''}`} />
          </button>
          
          {showQuickFixes && (
            <div className="px-5 pb-4 space-y-2 animate-fade-in">
              {fixableViolations.slice(0, 5).map((violation, idx) => {
                const policy = policies.find(p => p.id === violation.rule_id);
                return (
                  <div 
                    key={idx}
                    className="flex items-start gap-3 p-3 bg-gradient-to-r from-cyan-500/5 to-transparent rounded-lg border border-cyan-500/10"
                  >
                    <div className="flex-shrink-0 mt-0.5">
                      <div className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center">
                        <span className="text-xs font-bold text-cyan-400">{idx + 1}</span>
                      </div>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-semibold text-violet-400">{violation.rule_id}</span>
                        {violation.line && (
                          <span className="text-xs text-slate-500">Line {violation.line}</span>
                        )}
                      </div>
                      <p className="text-sm text-slate-300">{policy?.fix_suggestion}</p>
                    </div>
                  </div>
                );
              })}
              {fixableViolations.length > 5 && (
                <p className="text-xs text-slate-500 text-center pt-2">
                  +{fixableViolations.length - 5} more fixes available
                </p>
              )}
            </div>
          )}
        </div>
      )}
      
      <div className="max-h-[280px] overflow-y-auto">
        {violations.map((violation, index) => {
          const severity = getSeverityConfig(violation.severity);
          const isExpanded = expanded[index];
          const policy = policies.find(p => p.id === violation.rule_id);
          
          return (
            <div key={index} className="border-b border-white/5 last:border-b-0">
              <button
                onClick={() => toggleExpand(index)}
                className="w-full px-5 py-4 flex items-center gap-4 hover:bg-white/[0.02] transition-colors text-left"
              >
                <div className={`w-1 h-8 rounded-full ${severity.bg}`} />
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-slate-500" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-500" />
                )}
                <span className={`px-2.5 py-1 text-xs font-mono font-semibold rounded-lg ${severity.bg} ${severity.color}`}>
                  {violation.rule_id}
                </span>
                {violation.detector && violation.detector !== 'regex' && violation.detector !== 'ast' && (
                  <span className="px-2 py-1 text-xs font-medium rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20" title={`Found by ${violation.detector}`}>
                    {violation.detector}
                  </span>
                )}
                <span className="flex-1 text-sm text-slate-300 truncate">
                  {violation.description}
                </span>
                {violation.line && (
                  <button
                    onClick={(e) => handleLineClick(violation.line, e)}
                    className="text-xs text-cyan-400 font-mono bg-cyan-500/10 hover:bg-cyan-500/20 px-2 py-1 rounded border border-cyan-500/20 transition-all"
                    title="Click to jump to line"
                  >
                    ↗ L{violation.line}
                  </button>
                )}
              </button>
              {isExpanded && (
                <div className="px-5 pb-4 pl-16 space-y-3 animate-fade-in">
                  {violation.evidence && (
                    <div className="p-3 bg-slate-900/50 rounded-lg font-mono text-xs text-slate-300 border border-white/5">
                      <code>{violation.evidence}</code>
                    </div>
                  )}
                  {policy?.fix_suggestion && (
                    <div className="flex items-start gap-3 p-3 bg-cyan-500/5 rounded-lg border border-cyan-500/20">
                      <Info className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" />
                      <div className="text-sm text-slate-400">
                        <span className="text-cyan-400 font-semibold">Suggested Fix: </span>
                        {policy.fix_suggestion}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Proof Bundle Card (Compact)
const safeArray = <T,>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : []);

const safeObject = (value: unknown): Record<string, any> => (
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, any>)
    : {}
);

const safeText = (value: unknown, fallback = ''): string => {
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

type RuntimePolicyEvent = {
  tool: string;
  action: string;
  rule_id?: string | null;
  allowed?: boolean;
  message?: string | null;
};

const parseJsonIfString = (value: unknown): unknown => {
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

const normalizeRuntimePolicyEvents = (value: unknown): RuntimePolicyEvent[] => {
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

const describeRuntimeAction = (action: string): string => {
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

function ProofBundleCard({ 
  proof, 
  onCopy, 
  onViewFull,
  copied
}: { 
  proof: ProofBundle;
  onCopy: () => void;
  onViewFull: () => void;
  copied: boolean;
}) {
  const artifact = safeObject(proof?.artifact);
  const artifactHash = typeof artifact.hash === 'string' ? artifact.hash : 'n/a';
  return (
    <div className="gradient-border rounded-2xl overflow-hidden animate-scale-in stagger-2">
      <div className="p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30">
              <Fingerprint className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h3 className="font-display font-bold text-white">Proof Bundle</h3>
              <p className="text-xs text-slate-400">Cryptographically Signed</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={onViewFull}
              className="flex items-center gap-2 px-3 py-2 text-sm font-medium
                       bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white
                       rounded-lg transition-all border border-white/10"
            >
              <Eye className="w-4 h-4" />
              View Full
            </button>
            <button
              onClick={onCopy}
              className="p-2 bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white
                       rounded-lg transition-all border border-white/10"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>
        
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Hash</div>
            <div className="font-mono text-sm text-slate-300 truncate">
              {artifactHash !== 'n/a' ? `${artifactHash.slice(0, 16)}...` : 'n/a'}
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Status</div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-semibold text-emerald-400">{proof.decision}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Full Proof Bundle View
function ProofBundleView({ 
  proof, 
  iterations,
  onCopy,
  onDownload,
  copied
}: { 
  proof: ProofBundle;
  iterations: number;
  onCopy: () => void;
  onDownload: (format: string) => void;
  copied: boolean;
}) {
  const [activeTab, setActiveTab] = useState<'overview' | 'formal' | 'json'>('overview');
  const [exportFormat, setExportFormat] = useState<string>('json');
  const [showExportMenu, setShowExportMenu] = useState(false);
  const artifact = safeObject(proof?.artifact);
  const signed = safeObject(proof?.signed);
  const policies = safeArray<any>(proof?.policies);
  
  const exportFormats = [
    { value: 'json', label: 'JSON', icon: '{}' },
    { value: 'markdown', label: 'Markdown', icon: '📝' },
    { value: 'html', label: 'HTML', icon: '🌐' },
    { value: 'summary', label: 'Summary', icon: '📄' },
  ];
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30">
              <Fingerprint className="w-10 h-10 text-emerald-400" />
            </div>
            <div>
              <h2 className="text-2xl font-display font-bold text-white">Proof Bundle</h2>
              <p className="text-slate-400">Cryptographically Signed Compliance Certificate</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={onCopy}
              className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 text-slate-300 rounded-xl border border-white/10"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copied!' : 'Copy JSON'}
            </button>
            <div className="relative">
              <button
                onClick={() => setShowExportMenu(!showExportMenu)}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl"
              >
                <Download className="w-4 h-4" />
                Download
                <ChevronDown className="w-4 h-4" />
              </button>
              {showExportMenu && (
                <div className="absolute right-0 mt-2 w-48 bg-slate-800 border border-white/10 rounded-xl shadow-xl z-10 overflow-hidden">
                  {exportFormats.map((fmt) => (
                    <button
                      key={fmt.value}
                      onClick={() => {
                        setExportFormat(fmt.value);
                        onDownload(fmt.value);
                        setShowExportMenu(false);
                      }}
                      className={`w-full text-left px-4 py-3 hover:bg-slate-700 transition-colors flex items-center gap-3 ${
                        exportFormat === fmt.value ? 'bg-emerald-500/20 text-emerald-400' : 'text-slate-300'
                      }`}
                    >
                      <span>{fmt.icon}</span>
                      <span>{fmt.label}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
        
        {/* Tabs */}
        <div className="flex gap-2">
          {(['overview', 'formal', 'json'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                activeTab === tab
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              {tab === 'overview' ? 'Overview' : tab === 'formal' ? 'Formal Proof' : 'Raw JSON'}
            </button>
          ))}
        </div>
      </div>
      
      {/* Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-2 gap-6">
          {/* Artifact Info */}
          <div className="glass rounded-2xl p-6 border border-white/5">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <FileCode className="w-5 h-5 text-cyan-400" />
              Artifact
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-white/5">
                  <span className="text-slate-400">Hash (SHA-256)</span>
                  <span className="font-mono text-sm text-slate-200">
                    {typeof artifact.hash === 'string' ? `${artifact.hash.slice(0, 24)}...` : 'n/a'}
                  </span>
                </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Language</span>
                <span className="text-slate-200">{artifact.language || 'unknown'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Generator</span>
                <span className="text-slate-200">{artifact.generator || 'unknown'}</span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-400">Timestamp</span>
                <span className="text-slate-200">
                  {artifact.timestamp ? new Date(artifact.timestamp).toLocaleString() : 'n/a'}
                </span>
              </div>
            </div>
          </div>
          
          {/* Signature Info */}
          <div className="glass rounded-2xl p-6 border border-white/5">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <Lock className="w-5 h-5 text-violet-400" />
              Digital Signature
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Algorithm</span>
                <span className="text-slate-200">{signed.algorithm || 'unknown'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Signer</span>
                <span className="text-slate-200">{signed.signer || 'unknown'}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Decision</span>
                <span className={`font-semibold ${proof.decision === 'Compliant' ? 'text-emerald-400' : 'text-red-400'}`}>
                  {proof.decision}
                </span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-400">Iterations</span>
                <span className="text-slate-200">{iterations}</span>
              </div>
            </div>
          </div>
          
          {/* Policies */}
          <div className="glass rounded-2xl p-6 border border-white/5 col-span-2">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-emerald-400" />
              Verified Policies ({policies.length})
            </h3>
            <div className="grid grid-cols-4 gap-3">
              {policies.map((p, i) => (
                <div
                  key={i}
                  className={`p-3 rounded-xl border ${
                    p.result === 'satisfied'
                      ? 'bg-emerald-500/10 border-emerald-500/30'
                      : 'bg-red-500/10 border-red-500/30'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    {p.result === 'satisfied' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400" />
                    )}
                    <span className={`font-mono text-sm font-semibold ${
                      p.result === 'satisfied' ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {p.id}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 truncate">{p.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
      
      {activeTab === 'formal' && (
        <FormalProofView proof={proof} />
      )}
      
      {activeTab === 'json' && (
        <div className="glass rounded-2xl p-6 border border-white/5">
          <pre className="text-sm text-slate-300 font-mono overflow-auto max-h-[600px] p-4 bg-slate-900/50 rounded-xl">
            {JSON.stringify(proof, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// Visual Argumentation Graph Component
function ArgumentationGraphVisual({ proof }: { proof: ProofBundle }) {
  const argumentation = safeObject(proof?.argumentation);
  const args = safeArray<any>(argumentation.arguments);
  
  // Group arguments by rule
  const violationArgs = args.filter(a => a.type === 'violation');
  const complianceArgs = args.filter(a => a.type === 'compliance');
  const exceptionArgs = args.filter(a => a.type === 'exception');
  
  // Get unique violated rules
  const violatedRules = [...new Set(violationArgs.map(a => a.rule_id))];
  const satisfiedRules = complianceArgs
    .filter(a => a.status === 'accepted' && !violatedRules.includes(a.rule_id))
    .map(a => a.rule_id);

  if (args.length === 0) {
    return null;
  }

  return (
    <div className="glass rounded-2xl p-6 border border-white/5">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <GitBranch className="w-5 h-5 text-violet-400" />
        Argumentation Graph
      </h3>
      
      {/* Legend */}
      <div className="flex gap-6 mb-6 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-emerald-500"></div>
          <span className="text-slate-400">Accepted (claim holds)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <span className="text-slate-400">Rejected (claim defeated)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-orange-500"></div>
          <span className="text-orange-400">→</span>
          <span className="text-slate-400">attacks</span>
        </div>
      </div>

      {/* Violation chains */}
      {violatedRules.length > 0 && (
        <div className="space-y-4 mb-6">
          <h4 className="text-sm font-semibold text-red-400 uppercase tracking-wider">
            Violated Policies ({violatedRules.length})
          </h4>
          {violatedRules.map(ruleId => {
            const violation = violationArgs.find(a => a.rule_id === ruleId);
            const compliance = complianceArgs.find(a => a.rule_id === ruleId);
            const exception = exceptionArgs.find(a => a.rule_id === ruleId);
            
            return (
              <div key={ruleId} className="flex items-center gap-3 p-4 bg-slate-800/50 rounded-xl">
                {/* Exception (if any) */}
                {exception && (
                  <>
                    <div className={`flex-shrink-0 p-3 rounded-lg border-2 ${
                      exception.status === 'accepted' 
                        ? 'bg-emerald-500/10 border-emerald-500/50' 
                        : 'bg-slate-700/50 border-slate-600/50'
                    }`}>
                      <div className="text-xs font-mono font-bold text-amber-400">E_{ruleId}</div>
                      <div className={`text-xs mt-1 ${
                        exception.status === 'accepted' ? 'text-emerald-400' : 'text-slate-500'
                      }`}>
                        {exception.status === 'accepted' ? '✓ ACCEPTED' : '✗ REJECTED'}
                      </div>
                      <div className="text-xs text-slate-500 mt-1">Exception</div>
                    </div>
                    <div className="flex items-center text-orange-400">
                      <div className="w-8 h-0.5 bg-orange-500"></div>
                      <span className="text-xs mx-1">attacks</span>
                      <div className="w-0 h-0 border-t-4 border-b-4 border-l-6 border-transparent border-l-orange-500"></div>
                    </div>
                  </>
                )}
                
                {/* Violation */}
                <div className={`flex-shrink-0 p-3 rounded-lg border-2 ${
                  violation?.status === 'accepted' 
                    ? 'bg-red-500/10 border-red-500/50' 
                    : 'bg-slate-700/50 border-slate-600/50'
                }`}>
                  <div className="text-xs font-mono font-bold text-red-400">V_{ruleId}</div>
                  <div className={`text-xs mt-1 ${
                    violation?.status === 'accepted' ? 'text-red-400' : 'text-slate-500'
                  }`}>
                    {violation?.status === 'accepted' ? '✓ ACCEPTED' : '✗ REJECTED'}
                  </div>
                  {violation?.evidence && (
                    <div className="text-xs text-slate-500 mt-1 max-w-32 truncate" title={safeText(violation.evidence, 'n/a')}>
                      {safeText(violation.evidence, 'n/a')}
                    </div>
                  )}
                </div>
                
                {/* Attack arrow */}
                <div className="flex items-center text-orange-400">
                  <div className="w-8 h-0.5 bg-orange-500"></div>
                  <span className="text-xs mx-1">attacks</span>
                  <div className="w-0 h-0 border-t-4 border-b-4 border-l-6 border-transparent border-l-orange-500"></div>
                </div>
                
                {/* Compliance */}
                <div className={`flex-shrink-0 p-3 rounded-lg border-2 ${
                  compliance?.status === 'accepted' 
                    ? 'bg-emerald-500/10 border-emerald-500/50' 
                    : 'bg-red-500/10 border-red-500/50'
                }`}>
                  <div className={`text-xs font-mono font-bold ${
                    compliance?.status === 'accepted' ? 'text-emerald-400' : 'text-red-400'
                  }`}>C_{ruleId}</div>
                  <div className={`text-xs mt-1 ${
                    compliance?.status === 'accepted' ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {compliance?.status === 'accepted' ? '✓ ACCEPTED' : '✗ REJECTED'}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">Compliance</div>
                </div>
                
                {/* Result explanation */}
                <div className="flex-1 pl-4 border-l border-slate-700">
                  <div className="text-sm text-red-400 font-semibold">Policy Violated</div>
                  <div className="text-xs text-slate-400 mt-1">
                    {violation?.status === 'accepted' 
                      ? `Violation V_${ruleId} was accepted (undefeated), so C_${ruleId} was rejected.`
                      : `Violation was defeated by exception.`
                    }
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
      
      {/* Satisfied policies summary */}
      {satisfiedRules.length > 0 && (
        <div className="p-4 bg-emerald-500/5 rounded-xl border border-emerald-500/20">
          <h4 className="text-sm font-semibold text-emerald-400 mb-2">
            Satisfied Policies ({satisfiedRules.length})
          </h4>
          <p className="text-xs text-slate-400 mb-3">
            No violations found - compliance arguments accepted in grounded extension
          </p>
          <div className="flex flex-wrap gap-2">
            {satisfiedRules.slice(0, 10).map(ruleId => (
              <span key={ruleId} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                C_{ruleId} ✓
              </span>
            ))}
            {satisfiedRules.length > 10 && (
              <span className="px-2 py-1 bg-slate-700 text-slate-400 text-xs rounded">
                +{satisfiedRules.length - 10} more
              </span>
            )}
          </div>
        </div>
      )}
      
      {/* Grounded Extension Summary */}
      <div className="mt-6 p-4 bg-violet-500/5 rounded-xl border border-violet-500/20">
        <h4 className="text-sm font-semibold text-violet-400 mb-2">Grounded Extension Result</h4>
        <div className="grid grid-cols-2 gap-4 text-xs">
          <div>
            <div className="text-slate-400 mb-1">Accepted Arguments:</div>
            <div className="text-emerald-400 font-mono">
              {proof.argumentation?.grounded_extension?.accepted?.length || 0} arguments
            </div>
          </div>
          <div>
            <div className="text-slate-400 mb-1">Rejected Arguments:</div>
            <div className="text-slate-500 font-mono">
              {proof.argumentation?.grounded_extension?.rejected?.length || 0} arguments
            </div>
          </div>
        </div>
        <div className="mt-3 pt-3 border-t border-violet-500/20">
          <div className={`text-sm font-bold ${
            proof.decision === 'Compliant' ? 'text-emerald-400' : 'text-red-400'
          }`}>
            Decision: {proof.decision}
          </div>
          <div className="text-xs text-slate-400 mt-1">
            {proof.decision === 'Compliant' 
              ? 'All compliance arguments accepted, no violations in grounded extension.'
              : 'Violation arguments accepted in grounded extension indicate policy failures.'
            }
          </div>
        </div>
      </div>
    </div>
  );
}

// Formal Proof View - Step-by-step logical reasoning
function FormalProofView({ proof }: { proof: ProofBundle }) {
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({ 1: true, 5: true });
  const argumentation = safeObject(proof?.argumentation);
  
  const toggleStep = (step: number) => {
    setExpandedSteps(prev => ({ ...prev, [step]: !prev[step] }));
  };
  
  // Extract reasoning steps from the proof
  const reasoningTrace = safeArray<any>(argumentation.reasoning_trace);
  const reasoningSteps = reasoningTrace.filter((item: any) => item && item.step !== undefined);
  
  // Extract legacy format data
  const proofArguments = safeArray<any>(argumentation.arguments);
  const proofAttacks = safeArray<any>(argumentation.attacks);
  const groundedExtension = safeObject(argumentation.grounded_extension);
  const summary = safeObject(argumentation.summary);
  const groundedAccepted = safeArray<string>(groundedExtension.accepted);
  const groundedRejected = safeArray<string>(groundedExtension.rejected);
  const totalArguments = (
    typeof summary.total_arguments === 'number'
      ? summary.total_arguments
      : proofArguments.length
  );
  const hasFormalPayload = (
    reasoningSteps.length > 0
    || proofArguments.length > 0
    || proofAttacks.length > 0
    || groundedAccepted.length > 0
    || groundedRejected.length > 0
  );
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center gap-4 mb-4">
          <div className="p-4 rounded-2xl bg-violet-500/20 border border-violet-500/30">
            <Scale className="w-10 h-10 text-violet-400" />
          </div>
          <div>
            <h2 className="text-2xl font-display font-bold text-white">Formal Argumentation Proof</h2>
            <p className="text-slate-400">Step-by-step logical reasoning using Dung's Abstract Argumentation Framework</p>
          </div>
        </div>
        
        {/* Framework Summary */}
        <div className="grid grid-cols-4 gap-4 mt-6">
          <div className="p-4 bg-violet-500/10 rounded-xl border border-violet-500/30 text-center">
            <div className="text-xs text-violet-300 uppercase tracking-wider mb-1">Framework</div>
            <div className="text-white font-semibold">Dung's AAF</div>
          </div>
          <div className="p-4 bg-violet-500/10 rounded-xl border border-violet-500/30 text-center">
            <div className="text-xs text-violet-300 uppercase tracking-wider mb-1">Semantics</div>
            <div className="text-white font-semibold">Grounded Extension</div>
          </div>
          <div className="p-4 bg-violet-500/10 rounded-xl border border-violet-500/30 text-center">
            <div className="text-xs text-violet-300 uppercase tracking-wider mb-1">Arguments</div>
            <div className="text-white font-semibold">{totalArguments}</div>
          </div>
          <div className={`p-4 rounded-xl border text-center ${
            proof.decision === 'Compliant' 
              ? 'bg-emerald-500/10 border-emerald-500/30' 
              : 'bg-red-500/10 border-red-500/30'
          }`}>
            <div className={`text-xs uppercase tracking-wider mb-1 ${
              proof.decision === 'Compliant' ? 'text-emerald-300' : 'text-red-300'
            }`}>Decision</div>
            <div className={`font-bold ${
              proof.decision === 'Compliant' ? 'text-emerald-400' : 'text-red-400'
            }`}>{proof.decision}</div>
          </div>
        </div>
      </div>

      {!hasFormalPayload && (
        <div className="glass rounded-2xl p-6 border border-amber-500/30 bg-amber-500/10">
          <div className="text-amber-300 font-semibold">Formal proof data is unavailable for this bundle.</div>
          <p className="text-sm text-slate-300 mt-2">
            The proof bundle is valid, but argumentation details were missing or in a legacy format.
          </p>
        </div>
      )}
      
      {/* Plain English Explanation */}
      {argumentation.explanation && (
        <div className="glass rounded-2xl p-6 border border-white/5">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-cyan-400" />
            What This Means
          </h3>
          
          {/* Summary */}
          <div className={`p-4 rounded-xl border mb-4 ${
            proof.decision === 'Compliant' 
              ? 'bg-emerald-500/10 border-emerald-500/30' 
              : 'bg-red-500/10 border-red-500/30'
          }`}>
            <p className="text-slate-200">
              {safeText(safeObject(argumentation.explanation).summary, 'No summary available.')}
            </p>
          </div>
          
          {/* What happened for each violation */}
          {safeArray<any>(safeObject(argumentation.explanation).what_happened).length > 0 && (
            <div className="space-y-3 mb-4">
              <h4 className="text-sm font-semibold text-slate-300">Policy And Runtime Evidence Explained:</h4>
              {safeArray<any>(safeObject(argumentation.explanation).what_happened).map((item: any, i: number) => (
                (() => {
                  const policyId = safeText(item.policy, 'unknown-policy');
                  const resultLabel = safeText(item.result, 'UNKNOWN');
                  const isRuntimePolicy = policyId === 'RUNTIME-POLICY';
                  const runtimeEvents = isRuntimePolicy ? normalizeRuntimePolicyEvents(item.evidence) : [];
                  const cardClass = isRuntimePolicy
                    ? 'p-4 bg-cyan-500/5 rounded-xl border border-cyan-500/20'
                    : 'p-4 bg-red-500/5 rounded-xl border border-red-500/20';
                  const badgeClass = isRuntimePolicy
                    ? 'px-2 py-1 bg-cyan-500/20 text-cyan-300 text-xs font-mono rounded'
                    : 'px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded';
                  const resultClass = isRuntimePolicy ? 'text-cyan-300 font-semibold' : 'text-red-400 font-semibold';

                  return (
                <div key={i} className={cardClass}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={badgeClass}>
                      {policyId}
                    </span>
                    <span className={resultClass}>{resultLabel}</span>
                  </div>
                  <p className="text-sm text-slate-300 mb-2">{safeText(item.explanation, 'No explanation provided.')}</p>

                  {isRuntimePolicy && (
                    <div className="mb-2 p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 text-xs text-slate-300">
                      <p>This is runtime governance evidence, not a direct static-code violation.</p>
                      <p className="mt-1">
                        It records policy decisions about tool execution (allow, deny, monitoring, approval) and is included in the proof for audit traceability.
                      </p>
                    </div>
                  )}

                  {isRuntimePolicy && runtimeEvents.length > 0 ? (
                    <div className="space-y-2">
                      {runtimeEvents.map((event, idx) => (
                        <div key={`${event.tool}-${event.action}-${idx}`} className="text-xs text-slate-300 bg-slate-900/50 px-3 py-2 rounded border border-cyan-500/20">
                          <div className="flex flex-wrap gap-2">
                            <span className="font-mono text-cyan-300">{event.tool}</span>
                            <span className="text-slate-500">•</span>
                            <span>{describeRuntimeAction(event.action)}</span>
                            {event.allowed !== undefined && (
                              <>
                                <span className="text-slate-500">•</span>
                                <span>{event.allowed ? 'execution permitted' : 'execution blocked'}</span>
                              </>
                            )}
                          </div>
                          {event.rule_id && (
                            <p className="mt-1 text-slate-400">Rule: <span className="font-mono">{event.rule_id}</span></p>
                          )}
                          {event.message && (
                            <p className="mt-1 text-slate-400">{event.message}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : item.evidence ? (
                    <div className="text-xs text-slate-400 font-mono bg-slate-900/50 px-3 py-2 rounded">
                      Evidence: {safeText(item.evidence, 'n/a')}
                    </div>
                  ) : null}
                </div>
                  );
                })()
              ))}
            </div>
          )}
          
          {/* Terminology */}
          <details className="group">
            <summary className="cursor-pointer text-sm font-semibold text-slate-400 hover:text-slate-300 flex items-center gap-2">
              <ChevronRight className="w-4 h-4 group-open:rotate-90 transition-transform" />
              Terminology Reference
            </summary>
            <div className="mt-3 grid grid-cols-2 gap-2">
              {Object.entries(safeObject(safeObject(argumentation.explanation).terminology)).map(([term, def]: [string, any]) => (
                <div key={term} className="p-2 bg-slate-800/50 rounded-lg">
                  <span className="font-mono text-cyan-400 text-sm">{term}</span>
                  <p className="text-xs text-slate-400 mt-1">{safeText(def, 'n/a')}</p>
                </div>
              ))}
            </div>
          </details>
        </div>
      )}
      
      {/* Visual Argumentation Graph */}
      <ArgumentationGraphVisual proof={proof} />
      
      {/* Step-by-step Reasoning */}
      {reasoningSteps.length > 0 ? (
        <div className="space-y-4">
          {reasoningSteps.map((step: any) => (
            <div key={step.step} className="glass rounded-2xl border border-white/5 overflow-hidden">
              <button
                onClick={() => toggleStep(step.step)}
                className="w-full p-5 flex items-center gap-4 hover:bg-white/[0.02] transition-colors text-left"
              >
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-bold ${
                  step.phase === 'decision' 
                    ? proof.decision === 'Compliant' 
                      ? 'bg-emerald-500/20 text-emerald-400' 
                      : 'bg-red-500/20 text-red-400'
                    : 'bg-violet-500/20 text-violet-400'
                }`}>
                  {step.step}
                </div>
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-white">{safeText(step.title, `Step ${step.step}`)}</h3>
                  <p className="text-sm text-slate-400">{safeText(step.description, '')}</p>
                </div>
                {expandedSteps[step.step] ? (
                  <ChevronDown className="w-5 h-5 text-slate-400" />
                ) : (
                  <ChevronRight className="w-5 h-5 text-slate-400" />
                )}
              </button>
              
              {expandedSteps[step.step] && (
                <div className="px-5 pb-5 border-t border-white/5 animate-fade-in">
                  {/* Logic Rules */}
                  {step.logic && (
                    <div className="mt-4 p-4 bg-slate-900/50 rounded-xl border border-white/5">
                      <div className="text-xs text-cyan-400 uppercase tracking-wider mb-2">Formal Logic</div>
                      <div className="space-y-1 font-mono text-sm">
                        {safeArray<string>(step.logic).map((rule: string, i: number) => (
                          <div key={i} className="text-slate-300 flex items-start gap-2">
                            <span className="text-cyan-500">→</span>
                            <span>{rule}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Algorithm */}
                  {step.algorithm && (
                    <div className="mt-4 p-4 bg-slate-900/50 rounded-xl border border-white/5">
                      <div className="text-xs text-amber-400 uppercase tracking-wider mb-2">Algorithm</div>
                      <div className="space-y-1 font-mono text-sm">
                        {safeArray<string>(step.algorithm).map((line: string, i: number) => (
                          <div key={i} className="text-slate-300">{line}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Arguments by type */}
                  {step.arguments && (
                    <div className="mt-4 grid grid-cols-2 gap-4">
                      {safeArray<any>(safeObject(step.arguments).compliance).length > 0 && (
                        <div className="p-4 bg-emerald-500/5 rounded-xl border border-emerald-500/20">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Compliance Arguments ({safeArray<any>(safeObject(step.arguments).compliance).length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {safeArray<any>(safeObject(step.arguments).compliance).map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-emerald-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-emerald-400' : 'text-slate-500'
                                }`}>{safeText(arg.id, 'unknown')}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-emerald-300' : 'text-slate-500'
                                }`}>({safeText(arg.status, 'unknown')})</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {safeArray<any>(safeObject(step.arguments).violation).length > 0 && (
                        <div className="p-4 bg-red-500/5 rounded-xl border border-red-500/20">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violation Arguments ({safeArray<any>(safeObject(step.arguments).violation).length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {safeArray<any>(safeObject(step.arguments).violation).map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-red-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-red-400' : 'text-slate-500'
                                }`}>{safeText(arg.id, 'unknown')}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-red-300' : 'text-slate-500'
                                }`}>({safeText(arg.status, 'unknown')})</span>
                                {arg.evidence && (
                                  <div className="mt-1 text-slate-400 truncate">Evidence: {safeText(arg.evidence, 'n/a')}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Attacks */}
                  {safeArray<any>(step.attacks).length > 0 && (
                    <div className="mt-4 p-4 bg-orange-500/5 rounded-xl border border-orange-500/20">
                      <div className="text-xs text-orange-400 uppercase tracking-wider mb-2">
                        Attack Relations ({safeArray<any>(step.attacks).length})
                      </div>
                      <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                        {safeArray<any>(step.attacks).map((attack: any, i: number) => (
                          <div key={i} className={`p-2 rounded-lg text-xs flex items-center gap-2 ${
                            attack.effective ? 'bg-orange-500/10' : 'bg-slate-800/50'
                          }`}>
                            <span className="font-mono text-slate-300">{safeText(attack.attacker, '?')}</span>
                            <span className={attack.effective ? 'text-orange-400' : 'text-slate-500'}>→</span>
                            <span className="font-mono text-slate-300">{safeText(attack.target, '?')}</span>
                            <span className={`ml-auto ${attack.effective ? 'text-orange-400' : 'text-slate-500'}`}>
                              {attack.effective ? '✓' : '✗'}
                            </span>
                          </div>
                        ))}
                      </div>
                      {safeArray<any>(step.attacks).some((a: any) => a.reason) && (
                        <div className="mt-3 pt-3 border-t border-orange-500/20">
                          {safeArray<any>(step.attacks).filter((a: any) => a.reason).slice(0, 3).map((attack: any, i: number) => (
                            <div key={i} className="text-xs text-slate-400 mb-1">
                              <span className="text-orange-400">
                                {safeText(attack.attacker, '?')} → {safeText(attack.target, '?')}:
                              </span>{' '}
                              {safeText(attack.reason, '')}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Grounded Extension Result */}
                  {step.result && (
                    <div className="mt-4 grid grid-cols-2 gap-4">
                      <div className="p-4 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                        <div className="text-xs text-emerald-300 uppercase tracking-wider mb-2">
                          Accepted ({step.result.accepted_count})
                        </div>
                        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                          {safeArray<string>(safeObject(step.result).accepted).map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                              {safeText(id, '?')}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                        <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                          Rejected ({step.result.rejected_count})
                        </div>
                        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                          {safeArray<string>(safeObject(step.result).rejected).map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                              {safeText(id, '?')}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  {/* Decision */}
                  {step.phase === 'decision' && (
                    <div className={`mt-4 p-4 rounded-xl border ${
                      step.decision === 'COMPLIANT' 
                        ? 'bg-emerald-500/10 border-emerald-500/30' 
                        : 'bg-red-500/10 border-red-500/30'
                    }`}>
                      <div className="flex items-center gap-3 mb-3">
                        {step.decision === 'COMPLIANT' ? (
                          <ShieldCheck className="w-8 h-8 text-emerald-400" />
                        ) : (
                          <ShieldAlert className="w-8 h-8 text-red-400" />
                        )}
                        <div className={`text-2xl font-bold ${
                          step.decision === 'COMPLIANT' ? 'text-emerald-400' : 'text-red-400'
                        }`}>
                          {safeText(step.decision, 'UNKNOWN')}
                        </div>
                      </div>
                      <p className="text-sm text-slate-300">{safeText(step.reasoning, '')}</p>
                      
                      {safeArray<string>(step.satisfied_policies).length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Satisfied Policies ({safeArray<string>(step.satisfied_policies).length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {safeArray<string>(step.satisfied_policies).map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                                {safeText(id, '?')}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {safeArray<string>(step.violated_policies).length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violated Policies ({safeArray<string>(step.violated_policies).length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {safeArray<string>(step.violated_policies).map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded">
                                {safeText(id, '?')}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Details for framework definition */}
                  {step.details && (
                    <div className="mt-4 grid grid-cols-3 gap-4">
                      <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                        <div className="text-2xl font-bold text-white">{step.details.total_arguments}</div>
                        <div className="text-xs text-slate-400">Total Arguments</div>
                      </div>
                      <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                        <div className="text-2xl font-bold text-white">{step.details.total_attacks}</div>
                        <div className="text-xs text-slate-400">Attack Relations</div>
                      </div>
                      <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                        <div className="text-2xl font-bold text-violet-400">
                          {step.details.argument_types?.compliance || 0}C / {step.details.argument_types?.violation || 0}V
                        </div>
                        <div className="text-xs text-slate-400">Compliance / Violation</div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      ) : (
        /* Fallback to simple view if no step-by-step reasoning */
        <div className="glass rounded-2xl p-6 border border-white/5">
          {/* Arguments */}
          {proofArguments.length > 0 && (
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-slate-300 mb-3">Arguments</h4>
              <div className="grid grid-cols-2 gap-2 max-h-60 overflow-y-auto">
                {proofArguments.map((arg: any, i: number) => (
                  <div
                    key={i}
                    className={`p-3 rounded-lg border ${
                      arg.status === 'accepted'
                        ? 'bg-emerald-500/10 border-emerald-500/30'
                        : 'bg-slate-800/50 border-slate-700/50'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`font-mono text-sm ${
                        arg.status === 'accepted' ? 'text-emerald-400' : 'text-slate-400'
                      }`}>
                        {safeText(arg.id, 'unknown')}
                      </span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        arg.type === 'compliance' ? 'bg-emerald-500/20 text-emerald-400' :
                        arg.type === 'violation' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {safeText(arg.type, 'unknown')}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{safeText(arg.details, '')}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Attacks */}
          {proofAttacks.length > 0 && (
            <div className="mb-6">
              <h4 className="text-sm font-semibold text-slate-300 mb-3">Attack Relations</h4>
              <div className="grid grid-cols-3 gap-2">
                {proofAttacks.map((attack: any, i: number) => (
                  <div
                    key={i}
                    className={`p-2 rounded-lg border text-xs ${
                      attack.effective
                        ? 'bg-orange-500/10 border-orange-500/30'
                        : 'bg-slate-800/50 border-slate-700/50'
                    }`}
                  >
                    <span className="font-mono text-slate-300">{safeText(attack.relation, '?')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Grounded Extension */}
          {(groundedAccepted.length > 0 || groundedRejected.length > 0) && (
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                <div className="text-xs text-emerald-300 uppercase tracking-wider mb-2">Accepted</div>
                <div className="flex flex-wrap gap-1">
                  {groundedAccepted.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                      {safeText(id, '?')}
                    </span>
                  ))}
                </div>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">Rejected</div>
                <div className="flex flex-wrap gap-1">
                  {groundedRejected.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                      {safeText(id, '?')}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Policy Group interface
interface PolicyGroupPolicyDetail {
  id: string;
  description: string;
  severity: string;
}

interface PolicyGroup {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  policies: string[];
  policy_count?: number;
  policy_details?: PolicyGroupPolicyDetail[];
}

// Tools Configuration View
function ToolsConfigurationView({ 
  onCreatePolicy 
}: { 
  onCreatePolicy?: (data: {toolName: string; toolRuleId: string; description?: string; severity?: string}) => void;
}) {
  const [activeTab, setActiveTab] = useState<'tools' | 'mappings' | 'rules'>('tools');
  
  // Listen for createMapping events to switch to mappings tab
  useEffect(() => {
    const handleCreateMapping = (event: CustomEvent) => {
      setActiveTab('mappings');
      // Re-dispatch the event after tab switch so ToolMappingsView can handle it
      setTimeout(() => {
        window.dispatchEvent(event);
      }, 100);
    };
    
    window.addEventListener('createMapping', handleCreateMapping as EventListener);
    return () => {
      window.removeEventListener('createMapping', handleCreateMapping as EventListener);
    };
  }, []);
  const [tools, setTools] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toggling, setToggling] = useState<Set<string>>(new Set());

  const loadTools = useCallback(() => {
    setLoading(true);
    fetch('/api/v1/static-analysis/tools')
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        setTools(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    loadTools();
  }, [loadTools]);

  const toggleTool = async (language: string, toolName: string, currentEnabled: boolean) => {
    const key = `${language}:${toolName}`;
    setToggling(prev => new Set(prev).add(key));
    
    try {
      const response = await fetch(
        `/api/v1/static-analysis/tools/${language}/${toolName}?enabled=${!currentEnabled}`,
        { method: 'PATCH' }
      );
      
      if (!response.ok) {
        throw new Error(`Failed to toggle tool: ${response.statusText}`);
      }
      
      // Reload tools to get updated state
      await loadTools();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle tool');
    } finally {
      setToggling(prev => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
    }
  };

  if (loading && !tools) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading tools configuration...</p>
      </div>
    );
  }

  if (error && !tools) {
    return (
      <div className="glass rounded-2xl p-12 border border-red-500/20 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-4" />
        <p className="text-red-400">Error loading tools: {error}</p>
        <button
          onClick={() => { setError(null); loadTools(); }}
          className="mt-4 px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Tabs */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center gap-4 mb-4">
          <div className="p-4 rounded-2xl bg-violet-500/20 border border-violet-500/30">
            <Settings className="w-10 h-10 text-violet-400" />
          </div>
          <div className="flex-1">
            <h2 className="text-2xl font-display font-bold text-white">Static Analysis Configuration</h2>
            <p className="text-slate-400">Configure tools and policy mappings</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => setActiveTab('tools')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'tools'
                ? 'bg-violet-500/20 text-violet-400 border border-violet-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2">
              <Power className="w-4 h-4" />
              Tools
            </div>
          </button>
          <button
            onClick={() => setActiveTab('rules')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'rules'
                ? 'bg-violet-500/20 text-violet-400 border border-violet-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2">
              <List className="w-4 h-4" />
              Browse Rules
            </div>
          </button>
          <button
            onClick={() => setActiveTab('mappings')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeTab === 'mappings'
                ? 'bg-violet-500/20 text-violet-400 border border-violet-500/30'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2">
              <Link2 className="w-4 h-4" />
              Mappings
            </div>
          </button>
        </div>

        {/* Cache Stats */}
        {tools?.cache_stats && (
          <div className="mt-4 p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-slate-300">Cache Statistics</span>
            </div>
            <div className="grid grid-cols-3 gap-4 text-sm">
              <div>
                <span className="text-slate-500">Entries:</span>
                <span className="ml-2 text-slate-300 font-mono">{tools.cache_stats.total_entries}</span>
              </div>
              <div>
                <span className="text-slate-500">Size:</span>
                <span className="ml-2 text-slate-300 font-mono">
                  {(tools.cache_stats.total_size_bytes / 1024).toFixed(1)} KB
                </span>
              </div>
              <div>
                <span className="text-slate-500">TTL:</span>
                <span className="ml-2 text-slate-300 font-mono">{tools.cache_stats.ttl_seconds}s</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Content based on active tab */}
      {activeTab === 'rules' ? (
        <ToolRulesBrowser onCreatePolicy={onCreatePolicy} />
      ) : activeTab === 'tools' ? (
        tools?.tools_by_language ? (
          Object.entries(tools.tools_by_language).map(([language, langTools]: [string, any]) => (
            <div key={language} className="glass rounded-2xl p-6 border border-white/5">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <FileCode className="w-5 h-5 text-violet-400" />
                {language.charAt(0).toUpperCase() + language.slice(1)}
              </h3>
              
              <div className="space-y-3">
                {langTools.map((tool: any) => {
                  const toggleKey = `${language}:${tool.name}`;
                  const isToggling = toggling.has(toggleKey);
                  
                  return (
                    <div
                      key={tool.name}
                      className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50 flex items-center justify-between"
                    >
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="px-3 py-1 bg-violet-500/20 text-violet-400 text-sm font-mono font-semibold rounded-lg">
                            {tool.name}
                          </span>
                        </div>
                        <div className="grid grid-cols-3 gap-4 text-xs text-slate-400">
                          <div>
                            <span className="text-slate-500">Timeout:</span> {tool.timeout}s
                          </div>
                          <div>
                            <span className="text-slate-500">Format:</span> {tool.output_format}
                          </div>
                          {tool.requires_config && (
                            <div>
                              <span className="text-slate-500">Config:</span> {tool.requires_config}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="ml-4 flex items-center gap-3">
                        <button
                          onClick={() => toggleTool(language, tool.name, tool.enabled)}
                          disabled={isToggling}
                          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                            tool.enabled
                              ? 'bg-emerald-500'
                              : 'bg-slate-600'
                          } ${isToggling ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
                        >
                          <span
                            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                              tool.enabled ? 'translate-x-6' : 'translate-x-1'
                            }`}
                          />
                        </button>
                        {isToggling && (
                          <RefreshCw className="w-4 h-4 text-slate-400 animate-spin" />
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        ) : (
          <div className="glass rounded-2xl p-12 border border-white/5 text-center">
            <p className="text-slate-400">No tools configured</p>
          </div>
        )
      ) : (
        <ToolMappingsView onCreatePolicy={onCreatePolicy} />
      )}
    </div>
  );
}

// Tool Rules Browser - Browse available rules from tools
function ToolRulesBrowser({ 
  onCreatePolicy 
}: { 
  onCreatePolicy?: (data: {toolName: string; toolRuleId: string; description?: string; severity?: string}) => void;
}) {
  const [allRules, setAllRules] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'mapped' | 'unmapped'>('all');
  const [showMappingForm, setShowMappingForm] = useState(false);
  const [mappingRule, setMappingRule] = useState<{toolName: string; ruleId: string; rule: any} | null>(null);
  const [newMapping, setNewMapping] = useState({
    policyId: '',
    confidence: 'medium',
    severity: 'medium',
    description: ''
  });

  useEffect(() => {
    fetch('/api/v1/static-analysis/tools/rules')
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        setAllRules(data);
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  const loadRules = () => {
    fetch('/api/v1/static-analysis/tools/rules')
      .then(res => res.json())
      .then(data => setAllRules(data))
      .catch(err => setError(err.message));
  };

  const handleCreateMapping = (toolName: string, ruleId: string, rule: any) => {
    setMappingRule({ toolName, ruleId, rule });
    setNewMapping({
      policyId: '',
      confidence: rule.severity === 'critical' || rule.severity === 'high' ? 'high' : 'medium',
      severity: rule.severity || 'medium',
      description: rule.description || ''
    });
    setShowMappingForm(true);
  };

  const handleSaveMapping = async () => {
    if (!mappingRule || !newMapping.policyId) {
      alert('Please enter a policy ID');
      return;
    }

    try {
      const response = await fetch(
        `/api/v1/static-analysis/mappings/${mappingRule.toolName}/${mappingRule.ruleId}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            policy_id: newMapping.policyId,
            confidence: newMapping.confidence,
            severity: newMapping.severity,
            description: newMapping.description || mappingRule.rule.description
          })
        }
      );
      
      if (response.ok) {
        loadRules();
        setShowMappingForm(false);
        setMappingRule(null);
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to save mapping');
      }
    } catch (err) {
      alert('Failed to save mapping');
    }
  };

  if (loading) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading tool rules...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass rounded-2xl p-12 border border-red-500/20 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-4" />
        <p className="text-red-400">Error loading rules: {error}</p>
        <button
          onClick={() => { setError(null); loadRules(); }}
          className="mt-4 px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!allRules || Object.keys(allRules).length === 0) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <p className="text-slate-400">No tool rules available</p>
      </div>
    );
  }

  const tools = Object.keys(allRules);
  const currentTool = selectedTool || tools[0];
  const toolData = allRules[currentTool];
  const rules = Object.entries(toolData.rules || {}).filter(([_, rule]: [string, any]) => {
    if (filter === 'mapped') return rule.mapped;
    if (filter === 'unmapped') return !rule.mapped;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Pipeline Visualization */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <h3 className="text-lg font-semibold text-white mb-4">How Tools Work in the Pipeline</h3>
        <div className="space-y-3 text-sm">
          <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-violet-500/20 flex items-center justify-center text-violet-400 font-bold">1</div>
            <div className="flex-1">
              <div className="font-semibold text-white">Code Analysis</div>
              <div className="text-slate-400">When you analyze code, enabled tools run automatically</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-violet-500/20 flex items-center justify-center text-violet-400 font-bold">2</div>
            <div className="flex-1">
              <div className="font-semibold text-white">Tool Execution</div>
              <div className="text-slate-400">Tools (Bandit, ESLint, etc.) scan code and find issues</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-violet-500/20 flex items-center justify-center text-violet-400 font-bold">3</div>
            <div className="flex-1">
              <div className="font-semibold text-white">Rule Mapping</div>
              <div className="text-slate-400">Tool findings are mapped to ACPG policies (only mapped rules create violations)</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg">
            <div className="w-8 h-8 rounded-full bg-violet-500/20 flex items-center justify-center text-violet-400 font-bold">4</div>
            <div className="flex-1">
              <div className="font-semibold text-white">Violation Creation</div>
              <div className="text-slate-400">Mapped findings become violations in the compliance report</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tool Selection and Filter */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Browse Tool Rules</h3>
            <p className="text-sm text-slate-400 mt-1">
              View available rules from static analysis tools and create mappings
            </p>
          </div>
        </div>

        <div className="flex gap-4 mb-4">
          <div className="flex-1">
            <label className="block text-sm text-slate-400 mb-2">Select Tool</label>
            <select
              value={currentTool}
              onChange={(e) => setSelectedTool(e.target.value)}
              className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
            >
              {tools.map(tool => (
                <option key={tool} value={tool}>{tool}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-sm text-slate-400 mb-2">Filter</label>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value as 'all' | 'mapped' | 'unmapped')}
              className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
            >
              <option value="all">All Rules</option>
              <option value="mapped">Mapped Only</option>
              <option value="unmapped">Unmapped Only</option>
            </select>
          </div>
        </div>

        {toolData && (
          <div className="p-4 bg-slate-800/30 rounded-lg">
            <div className="flex gap-6 text-sm">
              <div>
                <span className="text-slate-500">Total Rules:</span>{' '}
                <span className="text-white font-semibold">{toolData.total_rules}</span>
              </div>
              <div>
                <span className="text-slate-500">Mapped:</span>{' '}
                <span className="text-emerald-400 font-semibold">{toolData.mapped_rules}</span>
              </div>
              <div>
                <span className="text-slate-500">Unmapped:</span>{' '}
                <span className="text-amber-400 font-semibold">{toolData.unmapped_rules}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Mapping Form Modal */}
      {showMappingForm && mappingRule && (
        <div className="glass rounded-2xl p-6 border border-white/5">
          <h4 className="text-md font-semibold text-white mb-4">
            Create Mapping: {mappingRule.toolName}:{mappingRule.ruleId}
          </h4>
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Tool Rule</label>
              <div className="p-3 bg-slate-800/50 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <span className="px-2 py-1 bg-amber-500/20 text-amber-400 text-xs font-mono rounded">
                    {mappingRule.ruleId}
                  </span>
                  <span className="text-sm text-slate-300">{mappingRule.rule.description}</span>
                </div>
                <div className="text-xs text-slate-500">
                  Severity: {mappingRule.rule.severity || 'medium'}
                </div>
              </div>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Policy ID *</label>
              <input
                type="text"
                value={newMapping.policyId}
                onChange={(e) => setNewMapping({...newMapping, policyId: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="e.g., SQL-001"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Confidence</label>
                <select
                  value={newMapping.confidence}
                  onChange={(e) => setNewMapping({...newMapping, confidence: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Severity</label>
                <select
                  value={newMapping.severity}
                  onChange={(e) => setNewMapping({...newMapping, severity: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Description</label>
              <textarea
                value={newMapping.description}
                onChange={(e) => setNewMapping({...newMapping, description: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                rows={2}
                placeholder="Description of the mapping"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSaveMapping}
                className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/30 transition-colors"
              >
                Create Mapping
              </button>
              <button
                onClick={() => {
                  setShowMappingForm(false);
                  setMappingRule(null);
                }}
                className="px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
              >
                Cancel
              </button>
              {onCreatePolicy && (
                <button
                  onClick={() => {
                    onCreatePolicy({
                      toolName: mappingRule.toolName,
                      toolRuleId: mappingRule.ruleId,
                      description: newMapping.description || mappingRule.rule.description,
                      severity: newMapping.severity
                    });
                    setShowMappingForm(false);
                  }}
                  className="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors"
                >
                  Create Policy First
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Rules List */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <h4 className="text-md font-semibold text-white mb-4">
          {currentTool.charAt(0).toUpperCase() + currentTool.slice(1)} Rules ({rules.length})
        </h4>
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {rules.map(([ruleId, rule]: [string, any]) => (
            <div
              key={ruleId}
              className={`p-4 rounded-xl border ${
                rule.mapped 
                  ? 'bg-emerald-500/5 border-emerald-500/20' 
                  : 'bg-slate-800/50 border-slate-700/50'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-amber-500/20 text-amber-400 text-xs font-mono rounded">
                      {ruleId}
                    </span>
                    {rule.mapped ? (
                      <>
                        <span className="text-slate-400">→</span>
                        <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                          {rule.mapped_to_policy}
                        </span>
                        <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs rounded">
                          Mapped
                        </span>
                      </>
                    ) : (
                      <span className="px-2 py-1 bg-slate-700 text-slate-500 text-xs rounded">
                        Unmapped
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-slate-300 mb-2">{rule.description}</p>
                  <div className="flex gap-4 text-xs text-slate-400">
                    <div>
                      <span className="text-slate-500">Severity:</span>{' '}
                      <span className={`font-semibold ${
                        rule.severity === 'critical' ? 'text-red-400' :
                        rule.severity === 'high' ? 'text-orange-400' :
                        rule.severity === 'medium' ? 'text-amber-400' :
                        'text-slate-400'
                      }`}>
                        {rule.severity || 'medium'}
                      </span>
                    </div>
                    {rule.category && (
                      <div>
                        <span className="text-slate-500">Category:</span>{' '}
                        <span className="text-slate-300">{rule.category}</span>
                      </div>
                    )}
                  </div>
                </div>
                {!rule.mapped && (
                  <div className="ml-4 flex gap-2">
                    <button
                      onClick={() => handleCreateMapping(currentTool, ruleId, rule)}
                      className="px-3 py-1.5 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors text-xs flex items-center gap-1"
                    >
                      <Link2 className="w-3 h-3" />
                      Map
                    </button>
                    {onCreatePolicy && (
                      <button
                        onClick={() => {
                          onCreatePolicy({
                            toolName: currentTool,
                            toolRuleId: ruleId,
                            description: rule.description,
                            severity: rule.severity || 'medium'
                          });
                        }}
                        className="px-3 py-1.5 bg-amber-500/20 text-amber-400 rounded-lg hover:bg-amber-500/30 transition-colors text-xs flex items-center gap-1"
                      >
                        <Plus className="w-3 h-3" />
                        Policy
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Tool Mappings View
function ToolMappingsView({ 
  onCreatePolicy 
}: { 
  onCreatePolicy?: (data: {toolName: string; toolRuleId: string; description?: string; severity?: string}) => void;
}) {
  const [mappings, setMappings] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingMapping, setEditingMapping] = useState<{toolName: string; ruleId: string; mapping: any} | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showBulkForm, setShowBulkForm] = useState(false);
  const [bulkMappings, setBulkMappings] = useState<Array<{toolName: string; toolRuleId: string; policyId: string; confidence: string; severity: string; description: string}>>([]);
  const [bulkProcessing, setBulkProcessing] = useState(false);
  const [bulkResults, setBulkResults] = useState<{succeeded: number; failed: number; results: any} | null>(null);
  const [newMapping, setNewMapping] = useState({
    toolName: '',
    toolRuleId: '',
    policyId: '',
    confidence: 'medium',
    severity: 'medium',
    description: ''
  });
  const [ruleDetails, setRuleDetails] = useState<any>(null);
  
  // Listen for createMapping events from unmapped findings
  useEffect(() => {
    const handleCreateMapping = async (event: Event) => {
      const { toolName, toolRuleId } = (event as CustomEvent).detail;
      
      // Fetch rule details from the API to auto-populate the form
      try {
        const response = await fetch(`/api/v1/static-analysis/tools/${toolName}/rules/${toolRuleId}`);
        if (response.ok) {
          const ruleDetails = await response.json();
          setNewMapping({
            toolName,
            toolRuleId,
            policyId: '',
            confidence: ruleDetails.severity === 'critical' || ruleDetails.severity === 'high' ? 'high' : 'medium',
            severity: ruleDetails.severity || 'medium',
            description: ruleDetails.description || ''
          });
          // Store rule details for display
          setRuleDetails(ruleDetails);
        } else {
          // Fallback if rule not found
          setNewMapping({
            toolName,
            toolRuleId,
            policyId: '',
            confidence: 'medium',
            severity: 'medium',
            description: ''
          });
          setRuleDetails(null);
        }
      } catch (err) {
        // Fallback on error
        setNewMapping({
          toolName,
          toolRuleId,
          policyId: '',
          confidence: 'medium',
          severity: 'medium',
          description: ''
        });
        setRuleDetails(null);
      }
      setShowAddForm(true);
    };
    
    window.addEventListener('createMapping', handleCreateMapping);
    return () => {
      window.removeEventListener('createMapping', handleCreateMapping);
    };
  }, []);

  const loadMappings = useCallback(() => {
    setLoading(true);
    fetch('/api/v1/static-analysis/mappings')
      .then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then(data => {
        setMappings(data.mappings || {});
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    loadMappings();
  }, [loadMappings]);

  if (loading) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading tool mappings...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass rounded-2xl p-12 border border-red-500/20 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-4" />
        <p className="text-red-400">Error loading mappings: {error}</p>
      </div>
    );
  }

  if (!mappings || Object.keys(mappings).length === 0) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <p className="text-slate-400">No tool mappings configured</p>
        <p className="text-slate-500 text-sm mt-2">Mappings are defined in policies/tool_mappings.json</p>
      </div>
    );
  }

  const handleEdit = (toolName: string, ruleId: string, mapping: any) => {
    setEditingMapping({ toolName, ruleId, mapping });
    setNewMapping({
      toolName,
      toolRuleId: ruleId,
      policyId: mapping.policy_id,
      confidence: mapping.confidence || 'medium',
      severity: mapping.severity || 'medium',
      description: mapping.description || ''
    });
    setShowAddForm(true);
  };

  const handleDelete = async (toolName: string, ruleId: string) => {
    if (!confirm(`Delete mapping for ${toolName}:${ruleId}?`)) return;
    
    try {
      const response = await fetch(`/api/v1/static-analysis/mappings/${toolName}/${ruleId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        loadMappings();
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to delete mapping');
      }
    } catch (err) {
      alert('Failed to delete mapping');
    }
  };

  const handleSaveMapping = async () => {
    try {
      const response = await fetch(
        `/api/v1/static-analysis/mappings/${newMapping.toolName}/${newMapping.toolRuleId}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            policy_id: newMapping.policyId,
            confidence: newMapping.confidence,
            severity: newMapping.severity,
            description: newMapping.description
          })
        }
      );
      
      if (response.ok) {
        loadMappings();
        setShowAddForm(false);
        setEditingMapping(null);
        setNewMapping({
          toolName: '',
          toolRuleId: '',
          policyId: '',
          confidence: 'medium',
          severity: 'medium',
          description: ''
        });
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to save mapping');
      }
    } catch (err) {
      alert('Failed to save mapping');
    }
  };

  const handleCreatePolicy = (toolName: string, ruleId: string, mapping: any) => {
    if (onCreatePolicy) {
      onCreatePolicy({
        toolName,
        toolRuleId: ruleId,
        description: mapping.description || `${toolName} rule ${ruleId}`,
        severity: mapping.severity || 'medium'
      });
    }
  };

  const handleBulkAdd = () => {
    setBulkMappings([...bulkMappings, {
      toolName: '',
      toolRuleId: '',
      policyId: '',
      confidence: 'medium',
      severity: 'medium',
      description: ''
    }]);
  };

  const handleBulkRemove = (index: number) => {
    setBulkMappings(bulkMappings.filter((_, i) => i !== index));
  };

  const handleBulkUpdate = (index: number, field: string, value: string) => {
    const updated = [...bulkMappings];
    updated[index] = { ...updated[index], [field]: value };
    setBulkMappings(updated);
  };

  const handleBulkSave = async () => {
    // Validate all mappings have required fields
    const invalid = bulkMappings.filter(m => !m.toolName || !m.toolRuleId || !m.policyId);
    if (invalid.length > 0) {
      alert(`Please fill in all required fields for ${invalid.length} mapping(s)`);
      return;
    }

    setBulkProcessing(true);
    setBulkResults(null);

    try {
      const response = await fetch('/api/v1/static-analysis/mappings/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mappings: bulkMappings })
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const result = await response.json();
      setBulkResults(result);
      
      if (result.failed === 0) {
        // All succeeded, reload mappings and close form
        loadMappings();
        setTimeout(() => {
          setShowBulkForm(false);
          setBulkMappings([]);
          setBulkResults(null);
        }, 2000);
      }
    } catch (err: any) {
      alert(`Failed to save bulk mappings: ${err.message}`);
    } finally {
      setBulkProcessing(false);
    }
  };

  if (loading) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading tool mappings...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass rounded-2xl p-12 border border-red-500/20 text-center">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-4" />
        <p className="text-red-400">Error loading mappings: {error}</p>
        <button
          onClick={() => { setError(null); loadMappings(); }}
          className="mt-4 px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  if (!mappings || Object.keys(mappings).length === 0) {
    return (
      <div className="space-y-6">
        <div className="glass rounded-2xl p-6 border border-white/5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-lg font-semibold text-white">Tool-to-Policy Mappings</h3>
              <p className="text-sm text-slate-400 mt-1">
                Map static analysis tool rules to ACPG policies
              </p>
            </div>
            <button
              onClick={() => setShowAddForm(true)}
              className="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Mapping
            </button>
          </div>
        </div>
        {showAddForm && (
          <div className="glass rounded-2xl p-6 border border-white/5">
            <h4 className="text-md font-semibold text-white mb-4">
              {editingMapping ? 'Edit Mapping' : 'Add New Mapping'}
            </h4>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Tool Name</label>
                <input
                  type="text"
                  value={newMapping.toolName}
                  onChange={(e) => setNewMapping({...newMapping, toolName: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  placeholder="e.g., bandit"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Tool Rule ID</label>
                <input
                  type="text"
                  value={newMapping.toolRuleId}
                  onChange={(e) => setNewMapping({...newMapping, toolRuleId: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  placeholder="e.g., B608"
                />
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Policy ID</label>
                <input
                  type="text"
                  value={newMapping.policyId}
                  onChange={(e) => setNewMapping({...newMapping, policyId: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  placeholder="e.g., SQL-001"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Confidence</label>
                  <select
                    value={newMapping.confidence}
                    onChange={(e) => setNewMapping({...newMapping, confidence: e.target.value})}
                    className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Severity</label>
                  <select
                    value={newMapping.severity}
                    onChange={(e) => setNewMapping({...newMapping, severity: e.target.value})}
                    className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Description</label>
                <textarea
                  value={newMapping.description}
                  onChange={(e) => setNewMapping({...newMapping, description: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  rows={2}
                  placeholder="Description of the mapping"
                />
              </div>
              <div className="flex gap-2">
                <button
                  onClick={handleSaveMapping}
                  className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/30 transition-colors"
                >
                  Save
                </button>
                <button
                  onClick={() => {
                    setShowAddForm(false);
                    setEditingMapping(null);
                    setNewMapping({
                      toolName: '',
                      toolRuleId: '',
                      policyId: '',
                      confidence: 'medium',
                      severity: 'medium',
                      description: ''
                    });
                  }}
                  className="px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="glass rounded-2xl p-12 border border-white/5 text-center">
          <p className="text-slate-400">No tool mappings configured</p>
          <p className="text-slate-500 text-sm mt-2">Click "Add Mapping" to create your first mapping</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold text-white">Tool-to-Policy Mappings</h3>
            <p className="text-sm text-slate-400 mt-1">
              Map static analysis tool rules to ACPG policies
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => {
                setShowBulkForm(true);
                setBulkMappings([]);
                setBulkResults(null);
              }}
              className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors flex items-center gap-2"
            >
              <List className="w-4 h-4" />
              Bulk Mapping
            </button>
            <button
              onClick={() => {
                setShowAddForm(true);
                setEditingMapping(null);
                setNewMapping({
                  toolName: '',
                  toolRuleId: '',
                  policyId: '',
                  confidence: 'medium',
                  severity: 'medium',
                  description: ''
                });
              }}
              className="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Mapping
            </button>
          </div>
        </div>
      </div>

      {showBulkForm && (
        <div className="glass rounded-2xl p-6 border border-white/5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-md font-semibold text-white">Bulk Mapping</h4>
              <p className="text-sm text-slate-400 mt-1">
                Create multiple mappings at once
              </p>
            </div>
            <button
              onClick={() => {
                setShowBulkForm(false);
                setBulkMappings([]);
                setBulkResults(null);
              }}
              className="px-3 py-1.5 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors text-sm"
            >
              Close
            </button>
          </div>

          {bulkResults && (
            <div className={`mb-4 p-4 rounded-lg border ${
              bulkResults.failed === 0 
                ? 'bg-emerald-500/10 border-emerald-500/30' 
                : 'bg-amber-500/10 border-amber-500/30'
            }`}>
              <div className="flex items-center gap-2 mb-2">
                {bulkResults.failed === 0 ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                )}
                <span className={`font-semibold ${
                  bulkResults.failed === 0 ? 'text-emerald-400' : 'text-amber-400'
                }`}>
                  {bulkResults.succeeded} succeeded, {bulkResults.failed} failed
                </span>
              </div>
              {bulkResults.results.failed.length > 0 && (
                <div className="mt-2 space-y-1">
                  {bulkResults.results.failed.slice(0, 5).map((f: any, i: number) => (
                    <div key={i} className="text-xs text-red-400">
                      {f.mapping.toolName}:{f.mapping.toolRuleId} - {f.error}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="space-y-3 max-h-96 overflow-y-auto mb-4">
            {bulkMappings.length === 0 ? (
              <div className="text-center py-8 text-slate-400">
                <p>No mappings added yet</p>
                <p className="text-sm mt-1">Click "Add Row" to start</p>
              </div>
            ) : (
              bulkMappings.map((mapping, index) => (
                <div key={index} className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <div className="flex items-start gap-2 mb-3">
                    <span className="px-2 py-1 bg-violet-500/20 text-violet-400 text-xs font-mono rounded">
                      #{index + 1}
                    </span>
                    <button
                      onClick={() => handleBulkRemove(index)}
                      className="ml-auto px-2 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition-colors text-xs"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mb-2">
                    <input
                      type="text"
                      placeholder="Tool (e.g., bandit)"
                      value={mapping.toolName}
                      onChange={(e) => handleBulkUpdate(index, 'toolName', e.target.value)}
                      className="px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-white text-sm"
                    />
                    <input
                      type="text"
                      placeholder="Rule ID (e.g., B608)"
                      value={mapping.toolRuleId}
                      onChange={(e) => handleBulkUpdate(index, 'toolRuleId', e.target.value)}
                      className="px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-white text-sm"
                    />
                    <input
                      type="text"
                      placeholder="Policy ID (e.g., SQL-001)"
                      value={mapping.policyId}
                      onChange={(e) => handleBulkUpdate(index, 'policyId', e.target.value)}
                      className="px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-white text-sm"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={mapping.confidence}
                      onChange={(e) => handleBulkUpdate(index, 'confidence', e.target.value)}
                      className="px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-white text-sm"
                    >
                      <option value="low">Low Confidence</option>
                      <option value="medium">Medium Confidence</option>
                      <option value="high">High Confidence</option>
                    </select>
                    <select
                      value={mapping.severity}
                      onChange={(e) => handleBulkUpdate(index, 'severity', e.target.value)}
                      className="px-2 py-1.5 bg-slate-900/50 border border-slate-700 rounded text-white text-sm"
                    >
                      <option value="low">Low Severity</option>
                      <option value="medium">Medium Severity</option>
                      <option value="high">High Severity</option>
                      <option value="critical">Critical</option>
                    </select>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="flex gap-2">
            <button
              onClick={handleBulkAdd}
              className="px-4 py-2 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Row
            </button>
            <button
              onClick={handleBulkSave}
              disabled={bulkMappings.length === 0 || bulkProcessing}
              className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/30 transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {bulkProcessing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  Save All ({bulkMappings.length})
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {showAddForm && (
        <div className="glass rounded-2xl p-6 border border-white/5">
          <h4 className="text-md font-semibold text-white mb-4">
            {editingMapping ? 'Edit Mapping' : 'Add New Mapping'}
          </h4>
          
          {/* Rule Details Panel - shown when mapping an unmapped rule */}
          {ruleDetails && !editingMapping && (
            <div className="mb-6 p-4 bg-violet-500/10 rounded-xl border border-violet-500/20">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded-lg bg-violet-500/20">
                  <Info className="w-5 h-5 text-violet-400" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-0.5 bg-slate-700 text-slate-300 text-xs font-mono rounded">
                      {ruleDetails.tool_name}:{ruleDetails.rule_id}
                    </span>
                    {ruleDetails.severity && (
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        ruleDetails.severity === 'high' || ruleDetails.severity === 'critical'
                          ? 'bg-red-500/20 text-red-400'
                          : ruleDetails.severity === 'medium'
                          ? 'bg-amber-500/20 text-amber-400'
                          : 'bg-slate-500/20 text-slate-400'
                      }`}>
                        {ruleDetails.severity}
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-slate-300 mb-2">{ruleDetails.description}</p>
                  {ruleDetails.cwe && (
                    <div className="text-xs text-slate-400">
                      <span className="font-medium">CWE:</span> {Array.isArray(ruleDetails.cwe) ? ruleDetails.cwe.join(', ') : ruleDetails.cwe}
                    </div>
                  )}
                  {ruleDetails.category && (
                    <div className="text-xs text-slate-400 mt-1">
                      <span className="font-medium">Category:</span> {ruleDetails.category}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Tool Name</label>
              <input
                type="text"
                value={newMapping.toolName}
                onChange={(e) => setNewMapping({...newMapping, toolName: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="e.g., bandit"
                disabled={!!editingMapping || !!ruleDetails}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Tool Rule ID</label>
              <input
                type="text"
                value={newMapping.toolRuleId}
                onChange={(e) => setNewMapping({...newMapping, toolRuleId: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="e.g., B608"
                disabled={!!editingMapping || !!ruleDetails}
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Policy ID</label>
              <input
                type="text"
                value={newMapping.policyId}
                onChange={(e) => setNewMapping({...newMapping, policyId: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="e.g., SQL-001"
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm text-slate-400 mb-1">Confidence</label>
                <select
                  value={newMapping.confidence}
                  onChange={(e) => setNewMapping({...newMapping, confidence: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div>
                <label className="block text-sm text-slate-400 mb-1">Severity</label>
                <select
                  value={newMapping.severity}
                  onChange={(e) => setNewMapping({...newMapping, severity: e.target.value})}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Description</label>
              <textarea
                value={newMapping.description}
                onChange={(e) => setNewMapping({...newMapping, description: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                rows={2}
                placeholder="Description of the mapping"
              />
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleSaveMapping}
                className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-lg hover:bg-emerald-500/30 transition-colors"
              >
                Save
              </button>
              <button
                onClick={() => {
                  setShowAddForm(false);
                  setEditingMapping(null);
                  setRuleDetails(null);
                  setNewMapping({
                    toolName: '',
                    toolRuleId: '',
                    policyId: '',
                    confidence: 'medium',
                    severity: 'medium',
                    description: ''
                  });
                }}
                className="px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {Object.entries(mappings).map(([toolName, toolMappings]: [string, any]) => (
        <div key={toolName} className="glass rounded-2xl p-6 border border-white/5">
          <h4 className="text-md font-semibold text-white mb-4 flex items-center gap-2">
            <span className="px-3 py-1 bg-violet-500/20 text-violet-400 text-sm font-mono rounded-lg">
              {toolName}
            </span>
            <span className="text-slate-400 text-sm">
              {Object.keys(toolMappings).length} mapping{Object.keys(toolMappings).length !== 1 ? 's' : ''}
            </span>
          </h4>
          
          <div className="space-y-2">
            {Object.entries(toolMappings).map(([ruleId, mapping]: [string, any]) => (
              <div
                key={ruleId}
                className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="px-2 py-1 bg-amber-500/20 text-amber-400 text-xs font-mono rounded">
                        {ruleId}
                      </span>
                      <span className="text-slate-400">→</span>
                      <span className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                        {mapping.policy_id}
                      </span>
                    </div>
                    {mapping.description && (
                      <p className="text-sm text-slate-300 mb-2">{mapping.description}</p>
                    )}
                    <div className="flex gap-4 text-xs text-slate-400">
                      <div>
                        <span className="text-slate-500">Confidence:</span>{' '}
                        <span className={`font-semibold ${
                          mapping.confidence === 'high' ? 'text-emerald-400' :
                          mapping.confidence === 'medium' ? 'text-amber-400' :
                          'text-slate-400'
                        }`}>
                          {mapping.confidence || 'medium'}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500">Severity:</span>{' '}
                        <span className={`font-semibold ${
                          mapping.severity === 'critical' ? 'text-red-400' :
                          mapping.severity === 'high' ? 'text-orange-400' :
                          mapping.severity === 'medium' ? 'text-amber-400' :
                          'text-slate-400'
                        }`}>
                          {mapping.severity || 'medium'}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex gap-2 ml-4">
                    <button
                      onClick={() => handleCreatePolicy(toolName, ruleId, mapping)}
                      className="px-3 py-1.5 bg-violet-500/20 text-violet-400 rounded-lg hover:bg-violet-500/30 transition-colors text-xs flex items-center gap-1"
                      title="Create Policy from this mapping"
                    >
                      <Plus className="w-3 h-3" />
                      Policy
                    </button>
                    <button
                      onClick={() => handleEdit(toolName, ruleId, mapping)}
                      className="px-3 py-1.5 bg-amber-500/20 text-amber-400 rounded-lg hover:bg-amber-500/30 transition-colors text-xs flex items-center gap-1"
                      title="Edit mapping"
                    >
                      <Edit2 className="w-3 h-3" />
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(toolName, ruleId)}
                      className="px-3 py-1.5 bg-red-500/20 text-red-400 rounded-lg hover:bg-red-500/30 transition-colors text-xs flex items-center gap-1"
                      title="Delete mapping"
                    >
                      <Trash2 className="w-3 h-3" />
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

// Proof Bundle Verifier - Check for tampering
function ProofVerifier() {
  const [proofJson, setProofJson] = useState('');
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleVerify = async () => {
    setLoading(true);
    setError(null);
    setVerificationResult(null);

    try {
      const proofBundle = JSON.parse(proofJson);
      
      const response = await fetch('/api/v1/proof/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ proof_bundle: proofBundle })
      });

      const result = await response.json();
      setVerificationResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON or verification failed');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setProofJson(event.target?.result as string);
        setVerificationResult(null);
      };
      reader.readAsText(file);
    }
  };

  const handleTamperDemo = () => {
    if (!proofJson) return;
    try {
      const proof = JSON.parse(proofJson);
      // Tamper with the decision field
      if (proof.decision === 'Compliant') {
        proof.decision = 'Non-compliant';
      } else {
        proof.decision = 'Compliant';
      }
      setProofJson(JSON.stringify(proof, null, 2));
      setVerificationResult(null);
    } catch {
      setError('Cannot tamper - invalid JSON');
    }
  };

  const handleTamperArtifact = () => {
    if (!proofJson) return;
    try {
      const proof = JSON.parse(proofJson);
      if (proof.artifact?.hash) {
        proof.artifact.hash = 'TAMPERED_' + proof.artifact.hash.slice(9);
      }
      setProofJson(JSON.stringify(proof, null, 2));
      setVerificationResult(null);
    } catch {
      setError('Cannot tamper - invalid JSON');
    }
  };

  const handleExportProof = async (format: string = 'json') => {
    if (!proofJson) return;
    try {
      const proofBundle = JSON.parse(proofJson);
      const response = await api.exportProof(proofBundle, format);
      const content = response.content;
      
      // Determine file extension and MIME type
      let extension = 'json';
      let mimeType = 'application/json';
      if (format === 'markdown') {
        extension = 'md';
        mimeType = 'text/markdown';
      } else if (format === 'html') {
        extension = 'html';
        mimeType = 'text/html';
      } else if (format === 'summary') {
        extension = 'txt';
        mimeType = 'text/plain';
      }
      
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `proof_bundle.${extension}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
      setError('Export failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center gap-4 mb-4">
          <div className="p-4 rounded-2xl bg-cyan-500/20 border border-cyan-500/30">
            <ShieldCheck className="w-10 h-10 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-2xl font-display font-bold text-white">Proof Bundle Verifier</h2>
            <p className="text-slate-400">Verify cryptographic integrity of compliance proof bundles</p>
          </div>
        </div>
        
        <div className="p-4 bg-slate-800/50 rounded-xl border border-white/5 mt-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-2">How it works:</h3>
          <ul className="text-sm text-slate-400 space-y-1">
            <li>• Proof bundles are signed with <span className="text-cyan-400 font-mono">ECDSA-SHA256</span></li>
            <li>• Any modification to the bundle will invalidate the signature</li>
            <li>• The verifier checks the cryptographic signature against the public key</li>
            <li>• Try the "Tamper" buttons to see what happens when data is modified</li>
          </ul>
        </div>
      </div>

      {/* Input Section */}
      <div className="grid grid-cols-2 gap-6">
        <div className="glass rounded-2xl p-6 border border-white/5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <FileCode className="w-5 h-5 text-violet-400" />
              Proof Bundle JSON
            </h3>
            <div className="flex gap-2">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileUpload}
                accept=".json"
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-3 py-1.5 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg flex items-center gap-2"
              >
                <Upload className="w-4 h-4" />
                Load File
              </button>
            </div>
          </div>
          
          <textarea
            value={proofJson}
            onChange={(e) => { setProofJson(e.target.value); setVerificationResult(null); }}
            placeholder="Paste a proof bundle JSON here, or load from file..."
            className="w-full h-80 bg-slate-900/50 border border-white/10 rounded-xl p-4 text-sm font-mono text-slate-300 placeholder-slate-500 resize-none"
          />
          
          <div className="flex gap-3 mt-4">
            <button
              onClick={handleVerify}
              disabled={!proofJson || loading}
              className="flex-1 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-400 hover:to-blue-400 disabled:from-slate-600 disabled:to-slate-600 text-white font-semibold rounded-xl flex items-center justify-center gap-2 transition-all"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  Verifying...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-5 h-5" />
                  Verify Signature
                </>
              )}
            </button>
          </div>
          
          {/* Tamper Demo Buttons */}
          <div className="mt-4 p-4 bg-red-500/10 rounded-xl border border-red-500/20">
            <h4 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Tamper Demo (for testing)
            </h4>
            <p className="text-xs text-slate-400 mb-3">
              Click these buttons to modify the proof bundle and see how verification detects tampering:
            </p>
            <div className="flex gap-2">
              <button
                onClick={handleTamperDemo}
                disabled={!proofJson}
                className="px-3 py-1.5 text-sm bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg disabled:opacity-50"
              >
                Flip Decision
              </button>
              <button
                onClick={handleTamperArtifact}
                disabled={!proofJson}
                className="px-3 py-1.5 text-sm bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg disabled:opacity-50"
              >
                Tamper Hash
              </button>
            </div>
          </div>
        </div>

        {/* Verification Result */}
        <div className="glass rounded-2xl p-6 border border-white/5">
          <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Fingerprint className="w-5 h-5 text-amber-400" />
            Verification Result
          </h3>
          
          {error && (
            <div className="p-4 bg-red-500/10 rounded-xl border border-red-500/30 mb-4">
              <p className="text-red-400">{error}</p>
            </div>
          )}
          
          {!verificationResult && !error && (
            <div className="flex flex-col items-center justify-center h-80 text-slate-500">
              <Shield className="w-16 h-16 mb-4 opacity-30" />
              <p>Load a proof bundle and click "Verify" to check integrity</p>
            </div>
          )}
          
          {verificationResult && (
            <div className="space-y-4">
              {/* Main Result Banner */}
              <div className={`p-6 rounded-xl border ${
                verificationResult.valid
                  ? 'bg-emerald-500/10 border-emerald-500/30'
                  : 'bg-red-500/10 border-red-500/30'
              }`}>
                <div className="flex items-center gap-4">
                  {verificationResult.valid ? (
                    <ShieldCheck className="w-12 h-12 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-12 h-12 text-red-400" />
                  )}
                  <div>
                    <h4 className={`text-2xl font-bold ${
                      verificationResult.valid ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      {verificationResult.valid ? 'INTEGRITY VERIFIED' : 'TAMPERING DETECTED'}
                    </h4>
                    <p className="text-slate-300">
                      {verificationResult.valid
                        ? 'This proof bundle has not been modified since signing'
                        : 'This proof bundle has been modified - signature is invalid'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Checks */}
              {verificationResult.checks?.length > 0 && (
                <div className="p-4 bg-slate-800/50 rounded-xl">
                  <h5 className="text-sm font-semibold text-slate-300 mb-2">Verification Checks:</h5>
                  <div className="space-y-1 font-mono text-sm">
                    {verificationResult.checks.map((check: string, i: number) => (
                      <div key={i} className={
                        check.startsWith('✓') ? 'text-emerald-400' :
                        check.startsWith('═') ? 'text-slate-500' :
                        'text-slate-300'
                      }>
                        {check}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Export Options */}
              <div className="p-4 bg-slate-800/50 rounded-xl">
                <h5 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                  <Download className="w-4 h-4" />
                  Export Proof Bundle
                </h5>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleExportProof('json')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    JSON
                  </button>
                  <button
                    onClick={() => handleExportProof('markdown')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Markdown
                  </button>
                  <button
                    onClick={() => handleExportProof('html')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    HTML
                  </button>
                  <button
                    onClick={() => handleExportProof('summary')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Summary
                  </button>
                </div>
              </div>

              {/* Errors */}
              {verificationResult.errors?.length > 0 && (
                <div className="p-4 bg-red-500/10 rounded-xl border border-red-500/20">
                  <h5 className="text-sm font-semibold text-red-400 mb-2">Issues Found:</h5>
                  <div className="space-y-1 font-mono text-sm">
                    {verificationResult.errors.map((err: string, i: number) => (
                      <div key={i} className={
                        err.startsWith('✗') ? 'text-red-400' :
                        err.startsWith('═') ? 'text-red-500' :
                        err.startsWith('  ') ? 'text-red-300' :
                        'text-slate-400'
                      }>
                        {err}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Details */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-xs text-slate-400 uppercase tracking-wider">Signature Valid</div>
                  <div className={`text-lg font-semibold ${
                    verificationResult.details?.signature_valid ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {verificationResult.details?.signature_valid ? 'Yes ✓' : 'No ✗'}
                  </div>
                </div>
                <div className="p-3 bg-slate-800/50 rounded-lg">
                  <div className="text-xs text-slate-400 uppercase tracking-wider">Signer Match</div>
                  <div className={`text-lg font-semibold ${
                    verificationResult.details?.signer_match ? 'text-emerald-400' : 'text-amber-400'
                  }`}>
                    {verificationResult.details?.signer_match ? 'Yes ✓' : 'Different Key'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

type DemoLabProps = {
  currentCode: string;
  semantics: SemanticsMode;
};

type RuntimePolicyRule = {
  id: string;
  event_type: string;
  action: string;
  severity: string;
  priority: number;
  description?: string;
};

type RuntimePolicyDecision = {
  allowed: boolean;
  action: string;
  rule_id?: string | null;
  severity?: string | null;
  message?: string | null;
  evidence?: string | null;
  matched_policies?: string[];
  metadata?: Record<string, unknown>;
};

type DynamicArtifactEntry = {
  history_id: string;
  timestamp: string;
  language: string;
  compliant: boolean;
  artifact_id?: string;
  suite_id?: string;
  suite_name?: string;
  return_code?: number | null;
  timed_out?: boolean;
  duration_seconds?: number;
  replay_fingerprint?: string;
  violation_rule_id?: string | null;
};

type ProofSummary = {
  id: number;
  artifact_hash: string;
  artifact_name?: string;
  decision: string;
  created_at: string;
};

function DemoLabView({ currentCode, semantics }: DemoLabProps) {
  const [activeTab, setActiveTab] = useState<'runtime' | 'batch' | 'graph' | 'proofs' | 'dynamic'>('runtime');

  const [runtimeRules, setRuntimeRules] = useState<RuntimePolicyRule[]>([]);
  const [runtimePolicyFile, setRuntimePolicyFile] = useState<string>('');
  const [runtimeLoading, setRuntimeLoading] = useState(false);
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [runtimeEventType, setRuntimeEventType] = useState<'tool' | 'network' | 'filesystem'>('tool');
  const [runtimeToolName, setRuntimeToolName] = useState('bandit');
  const [runtimeCommand, setRuntimeCommand] = useState('bandit -f json -ll -r target.py');
  const [runtimeLanguage, setRuntimeLanguage] = useState('python');
  const [runtimeHost, setRuntimeHost] = useState('api.example.com');
  const [runtimeMethod, setRuntimeMethod] = useState('GET');
  const [runtimeProtocol, setRuntimeProtocol] = useState('https');
  const [runtimePath, setRuntimePath] = useState('/tmp/output.json');
  const [runtimeOperation, setRuntimeOperation] = useState('write');
  const [runtimeDecision, setRuntimeDecision] = useState<RuntimePolicyDecision | null>(null);
  const [runtimeEvaluating, setRuntimeEvaluating] = useState(false);

  const [batchCases, setBatchCases] = useState<ManagedTestCase[]>([]);
  const [batchSelected, setBatchSelected] = useState<string[]>([]);
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchResult, setBatchResult] = useState<{
    items: Array<{ name: string; compliant: boolean; violation_count: number; risk_score: number }>;
    summary: { total_items: number; compliant_count: number; non_compliant_count: number; total_violations: number; compliance_rate: number };
  } | null>(null);

  const [graphDefinition, setGraphDefinition] = useState<string>('');
  const [graphNodes, setGraphNodes] = useState<Array<{ name: string; description: string }>>([]);
  const [graphEdges, setGraphEdges] = useState<Array<{ from: string; to: string; condition: string }>>([]);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [graphCode, setGraphCode] = useState(currentCode);
  const [graphMaxIterations, setGraphMaxIterations] = useState(3);
  const [graphSemantics, setGraphSemantics] = useState<SemanticsMode>(semantics);
  const [graphSolverDecisionMode, setGraphSolverDecisionMode] = useState<'auto' | 'skeptical' | 'credulous'>('auto');
  const [graphStreaming, setGraphStreaming] = useState(false);
  const [graphEvents, setGraphEvents] = useState<Array<{ event: string; data: unknown; at: string }>>([]);
  const graphAbortRef = useRef<AbortController | null>(null);

  const [proofsLoading, setProofsLoading] = useState(false);
  const [proofsError, setProofsError] = useState<string | null>(null);
  const [proofs, setProofs] = useState<ProofSummary[]>([]);
  const [publicKey, setPublicKey] = useState<{
    fingerprint: string;
    algorithm: string;
    curve: string;
    public_key_pem: string;
  } | null>(null);
  const [selectedProof, setSelectedProof] = useState<Record<string, unknown> | null>(null);
  const [selectedProofHash, setSelectedProofHash] = useState<string | null>(null);
  const [selectedProofLoading, setSelectedProofLoading] = useState(false);

  const [dynamicLoading, setDynamicLoading] = useState(false);
  const [dynamicError, setDynamicError] = useState<string | null>(null);
  const [dynamicLimit, setDynamicLimit] = useState(50);
  const [dynamicViolationsOnly, setDynamicViolationsOnly] = useState(false);
  const [dynamicSuite, setDynamicSuite] = useState('');
  const [dynamicRule, setDynamicRule] = useState('');
  const [dynamicArtifacts, setDynamicArtifacts] = useState<DynamicArtifactEntry[]>([]);

  const loadRuntimePolicies = useCallback(async () => {
    setRuntimeLoading(true);
    setRuntimeError(null);
    try {
      const response = await fetch('/api/v1/runtime/policies');
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Failed to load runtime policies');
      }
      setRuntimeRules(Array.isArray(payload.rules) ? payload.rules : []);
      setRuntimePolicyFile(payload.policy_file || '');
    } catch (err) {
      setRuntimeError(err instanceof Error ? err.message : 'Failed to load runtime policies');
      setRuntimeRules([]);
      setRuntimePolicyFile('');
    } finally {
      setRuntimeLoading(false);
    }
  }, []);

  const evaluateRuntimePolicy = useCallback(async () => {
    setRuntimeEvaluating(true);
    setRuntimeError(null);
    setRuntimeDecision(null);
    try {
      const body: Record<string, unknown> = {
        event_type: runtimeEventType,
      };
      if (runtimeEventType === 'tool') {
        body.tool_name = runtimeToolName;
        body.command = runtimeCommand
          .split(' ')
          .map((token) => token.trim())
          .filter(Boolean);
        body.language = runtimeLanguage;
      } else if (runtimeEventType === 'network') {
        body.host = runtimeHost;
        body.method = runtimeMethod;
        body.protocol = runtimeProtocol;
      } else {
        body.path = runtimePath;
        body.operation = runtimeOperation;
      }

      const response = await fetch('/api/v1/runtime/policies/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Runtime policy evaluation failed');
      }
      setRuntimeDecision(payload.decision || null);
    } catch (err) {
      setRuntimeError(err instanceof Error ? err.message : 'Runtime policy evaluation failed');
    } finally {
      setRuntimeEvaluating(false);
    }
  }, [
    runtimeCommand,
    runtimeEventType,
    runtimeHost,
    runtimeLanguage,
    runtimeMethod,
    runtimeOperation,
    runtimePath,
    runtimeProtocol,
    runtimeToolName,
  ]);

  const loadBatchCases = useCallback(async () => {
    setBatchLoading(true);
    setBatchError(null);
    try {
      const response = await fetch('/api/v1/test-cases');
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Failed to load test cases');
      }
      const cases = Array.isArray(payload.cases) ? payload.cases : [];
      setBatchCases(cases);
      if (cases.length > 0 && batchSelected.length === 0) {
        setBatchSelected(cases.slice(0, 3).map((item: ManagedTestCase) => item.id));
      }
    } catch (err) {
      setBatchCases([]);
      setBatchError(err instanceof Error ? err.message : 'Failed to load test cases');
    } finally {
      setBatchLoading(false);
    }
  }, [batchSelected.length]);

  const runBatchAnalysis = useCallback(async () => {
    if (batchSelected.length === 0) {
      setBatchError('Select at least one test case.');
      return;
    }
    setBatchRunning(true);
    setBatchError(null);
    setBatchResult(null);
    try {
      const details = await Promise.all(
        batchSelected.map(async (caseId) => {
          const response = await fetch(`/api/v1/test-cases/${encodeURIComponent(caseId)}`);
          const payload = await response.json();
          if (!response.ok) {
            throw new Error(payload.detail || `Failed to load ${caseId}`);
          }
          return payload as ManagedTestCase;
        })
      );

      const requestBody = {
        items: details.map((item) => ({
          name: item.name,
          code: item.code || '',
          language: item.language || 'python',
        })),
      };

      const response = await fetch('/api/v1/analyze/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Batch analysis failed');
      }
      setBatchResult(payload);
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : 'Batch analysis failed');
    } finally {
      setBatchRunning(false);
    }
  }, [batchSelected]);

  const loadGraphVisualization = useCallback(async () => {
    setGraphLoading(true);
    setGraphError(null);
    try {
      const response = await fetch('/api/v1/graph/visualize');
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Failed to load graph visualization');
      }
      setGraphDefinition(payload.graph || '');
      setGraphNodes(Array.isArray(payload.nodes) ? payload.nodes : []);
      setGraphEdges(Array.isArray(payload.edges) ? payload.edges : []);
    } catch (err) {
      setGraphError(err instanceof Error ? err.message : 'Failed to load graph visualization');
      setGraphDefinition('');
      setGraphNodes([]);
      setGraphEdges([]);
    } finally {
      setGraphLoading(false);
    }
  }, []);

  const appendGraphEvent = useCallback((event: string, data: unknown) => {
    const next = {
      event,
      data,
      at: new Date().toISOString(),
    };
    setGraphEvents((prev) => [...prev.slice(-149), next]);
  }, []);

  const stopGraphStream = useCallback(() => {
    if (graphAbortRef.current) {
      graphAbortRef.current.abort();
      graphAbortRef.current = null;
    }
    setGraphStreaming(false);
  }, []);

  const startGraphStream = useCallback(async () => {
    setGraphError(null);
    setGraphEvents([]);
    if (graphAbortRef.current) {
      graphAbortRef.current.abort();
    }

    const controller = new AbortController();
    graphAbortRef.current = controller;
    setGraphStreaming(true);

    try {
      const response = await fetch('/api/v1/graph/enforce/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: graphCode,
          language: 'python',
          max_iterations: graphMaxIterations,
          semantics: graphSemantics,
          solver_decision_mode: graphSolverDecisionMode,
        }),
        signal: controller.signal,
      });

      if (!response.ok || !response.body) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || 'Failed to start graph stream');
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        let boundary = buffer.indexOf('\n\n');
        while (boundary >= 0) {
          const packet = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);

          const lines = packet.split('\n');
          let eventName = 'message';
          const dataParts: string[] = [];
          for (const line of lines) {
            if (line.startsWith('event:')) {
              eventName = line.slice(6).trim();
            } else if (line.startsWith('data:')) {
              dataParts.push(line.slice(5).trim());
            }
          }
          const rawData = dataParts.join('\n');
          let parsedData: unknown = rawData;
          try {
            parsedData = rawData ? JSON.parse(rawData) : null;
          } catch {
            parsedData = rawData;
          }

          appendGraphEvent(eventName, parsedData);
          if (eventName === 'error') {
            const eventPayload = parsedData as { error?: string } | null;
            throw new Error(eventPayload?.error || 'Graph stream error');
          }

          boundary = buffer.indexOf('\n\n');
        }
      }
    } catch (err) {
      if ((err as Error).name !== 'AbortError') {
        setGraphError(err instanceof Error ? err.message : 'Graph stream failed');
      }
    } finally {
      if (graphAbortRef.current === controller) {
        graphAbortRef.current = null;
      }
      setGraphStreaming(false);
    }
  }, [appendGraphEvent, graphCode, graphMaxIterations, graphSemantics, graphSolverDecisionMode]);

  const loadProofRegistry = useCallback(async () => {
    setProofsLoading(true);
    setProofsError(null);
    try {
      const [proofsResponse, keyResponse] = await Promise.all([
        fetch('/api/v1/proofs?limit=100'),
        fetch('/api/v1/proof/public-key'),
      ]);
      const proofsPayload = await proofsResponse.json();
      const keyPayload = await keyResponse.json();
      if (!proofsResponse.ok) {
        throw new Error(proofsPayload.detail || 'Failed to load proofs');
      }
      if (!keyResponse.ok) {
        throw new Error(keyPayload.detail || 'Failed to load public key');
      }
      setProofs(Array.isArray(proofsPayload.proofs) ? proofsPayload.proofs : []);
      setPublicKey(keyPayload);
    } catch (err) {
      setProofs([]);
      setPublicKey(null);
      setProofsError(err instanceof Error ? err.message : 'Failed to load proof registry');
    } finally {
      setProofsLoading(false);
    }
  }, []);

  const loadProofBundle = useCallback(async (artifactHash: string) => {
    setSelectedProofHash(artifactHash);
    setSelectedProofLoading(true);
    try {
      const response = await fetch(`/api/v1/proof/${artifactHash}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Failed to load proof bundle');
      }
      setSelectedProof(payload);
    } catch (err) {
      setProofsError(err instanceof Error ? err.message : 'Failed to load proof bundle');
      setSelectedProof(null);
    } finally {
      setSelectedProofLoading(false);
    }
  }, []);

  const loadDynamicArtifacts = useCallback(async () => {
    setDynamicLoading(true);
    setDynamicError(null);
    try {
      const params = new URLSearchParams();
      params.set('limit', String(dynamicLimit));
      if (dynamicViolationsOnly) params.set('violations_only', 'true');
      if (dynamicSuite.trim()) params.set('suite_id', dynamicSuite.trim());
      if (dynamicRule.trim()) params.set('violation_rule_id', dynamicRule.trim());
      const response = await fetch(`/api/v1/history/dynamic-artifacts?${params.toString()}`);
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Failed to load dynamic artifacts');
      }
      setDynamicArtifacts(Array.isArray(payload.artifacts) ? payload.artifacts : []);
    } catch (err) {
      setDynamicArtifacts([]);
      setDynamicError(err instanceof Error ? err.message : 'Failed to load dynamic artifacts');
    } finally {
      setDynamicLoading(false);
    }
  }, [dynamicLimit, dynamicRule, dynamicSuite, dynamicViolationsOnly]);

  useEffect(() => {
    if (activeTab === 'runtime') {
      void loadRuntimePolicies();
    } else if (activeTab === 'batch') {
      void loadBatchCases();
    } else if (activeTab === 'graph') {
      void loadGraphVisualization();
    } else if (activeTab === 'proofs') {
      void loadProofRegistry();
    } else if (activeTab === 'dynamic') {
      void loadDynamicArtifacts();
    }
  }, [activeTab, loadBatchCases, loadDynamicArtifacts, loadGraphVisualization, loadProofRegistry, loadRuntimePolicies]);

  useEffect(() => () => {
    if (graphAbortRef.current) {
      graphAbortRef.current.abort();
    }
  }, []);

  return (
    <div className="space-y-6">
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center gap-4">
          <div className="p-4 rounded-2xl bg-cyan-500/20 border border-cyan-500/30">
            <Terminal className="w-10 h-10 text-cyan-300" />
          </div>
          <div>
            <h2 className="text-2xl font-display font-bold text-white">Demo Lab</h2>
            <p className="text-slate-400">Interactive UI demos for runtime governance, argumentation, proof evidence, and batch compliance runs.</p>
          </div>
        </div>
      </div>

      <div className="glass rounded-xl p-3 border border-white/5">
        <div className="flex flex-wrap gap-2">
          {[
            { id: 'runtime', label: 'Runtime Policies' },
            { id: 'batch', label: 'Batch Runner' },
            { id: 'graph', label: 'LangGraph Stream' },
            { id: 'proofs', label: 'Proof Registry' },
            { id: 'dynamic', label: 'Dynamic Artifacts' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'runtime' | 'batch' | 'graph' | 'proofs' | 'dynamic')}
              className={`px-3 py-2 rounded-lg text-sm transition-colors ${
                activeTab === tab.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                  : 'bg-slate-800/70 text-slate-300 border border-slate-700 hover:border-slate-500'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'runtime' && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-2 glass rounded-2xl p-5 border border-white/5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Event Simulator</h3>
              <button
                onClick={() => void loadRuntimePolicies()}
                className="px-3 py-1.5 text-xs bg-slate-800 text-slate-300 rounded-lg border border-slate-700 hover:border-slate-500"
              >
                Refresh Rules
              </button>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Event Type</label>
              <select
                value={runtimeEventType}
                onChange={(e) => setRuntimeEventType(e.target.value as 'tool' | 'network' | 'filesystem')}
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              >
                <option value="tool">Tool</option>
                <option value="network">Network</option>
                <option value="filesystem">Filesystem</option>
              </select>
            </div>

            {runtimeEventType === 'tool' && (
              <>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Tool</label>
                  <input
                    value={runtimeToolName}
                    onChange={(e) => setRuntimeToolName(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Command</label>
                  <input
                    value={runtimeCommand}
                    onChange={(e) => setRuntimeCommand(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Language</label>
                  <input
                    value={runtimeLanguage}
                    onChange={(e) => setRuntimeLanguage(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                  />
                </div>
              </>
            )}

            {runtimeEventType === 'network' && (
              <>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Host</label>
                  <input
                    value={runtimeHost}
                    onChange={(e) => setRuntimeHost(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Method</label>
                    <input
                      value={runtimeMethod}
                      onChange={(e) => setRuntimeMethod(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-400 mb-1">Protocol</label>
                    <input
                      value={runtimeProtocol}
                      onChange={(e) => setRuntimeProtocol(e.target.value)}
                      className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                    />
                  </div>
                </div>
              </>
            )}

            {runtimeEventType === 'filesystem' && (
              <>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Path</label>
                  <input
                    value={runtimePath}
                    onChange={(e) => setRuntimePath(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Operation</label>
                  <input
                    value={runtimeOperation}
                    onChange={(e) => setRuntimeOperation(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                  />
                </div>
              </>
            )}

            <button
              onClick={() => void evaluateRuntimePolicy()}
              disabled={runtimeEvaluating}
              className="w-full py-2.5 bg-cyan-500/20 text-cyan-300 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {runtimeEvaluating ? 'Evaluating...' : 'Evaluate Policy Decision'}
            </button>

            {runtimeError && (
              <div className="p-3 text-sm bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg">
                {runtimeError}
              </div>
            )}
          </div>

          <div className="xl:col-span-3 space-y-5">
            <div className="glass rounded-2xl p-5 border border-white/5">
              <h3 className="text-lg font-semibold text-white mb-3">Decision Output</h3>
              {!runtimeDecision ? (
                <p className="text-sm text-slate-500">Run an event evaluation to inspect allow/deny/monitor reasoning.</p>
              ) : (
                <div className="space-y-3 text-sm">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      runtimeDecision.allowed ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
                    }`}>
                      {runtimeDecision.allowed ? 'ALLOWED' : 'DENIED'}
                    </span>
                    <span className="px-2 py-1 rounded text-xs bg-slate-800 text-slate-300">
                      action: {runtimeDecision.action}
                    </span>
                    {runtimeDecision.rule_id && (
                      <span className="px-2 py-1 rounded text-xs bg-violet-500/20 text-violet-300 font-mono">
                        {runtimeDecision.rule_id}
                      </span>
                    )}
                  </div>
                  {runtimeDecision.message && <p className="text-slate-300">{runtimeDecision.message}</p>}
                  {runtimeDecision.evidence && (
                    <p className="text-xs text-slate-500 font-mono break-all">{runtimeDecision.evidence}</p>
                  )}
                  {(runtimeDecision.matched_policies || []).length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {(runtimeDecision.matched_policies || []).map((policyId) => (
                        <span key={policyId} className="px-1.5 py-0.5 text-[10px] bg-amber-500/20 text-amber-300 rounded font-mono">
                          {policyId}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="glass rounded-2xl p-5 border border-white/5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-lg font-semibold text-white">Compiled Runtime Rules</h3>
                {runtimePolicyFile && <span className="text-xs text-slate-500 font-mono truncate max-w-[60%]">{runtimePolicyFile}</span>}
              </div>
              {runtimeLoading ? (
                <p className="text-sm text-slate-500">Loading runtime policy rules...</p>
              ) : (
                <div className="space-y-2 max-h-80 overflow-y-auto">
                  {runtimeRules.map((rule) => (
                    <div key={rule.id} className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-xs font-mono text-cyan-300">{rule.id}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">{rule.event_type}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300">{rule.action}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300">priority {rule.priority}</span>
                      </div>
                      {rule.description && <p className="text-xs text-slate-400 mt-1">{rule.description}</p>}
                    </div>
                  ))}
                  {runtimeRules.length === 0 && <p className="text-sm text-slate-500">No runtime rules loaded.</p>}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'batch' && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-2 glass rounded-2xl p-5 border border-white/5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Stored Test Cases</h3>
              <button
                onClick={() => void loadBatchCases()}
                className="px-3 py-1.5 text-xs bg-slate-800 text-slate-300 rounded-lg border border-slate-700 hover:border-slate-500"
              >
                Refresh
              </button>
            </div>

            {batchLoading ? (
              <p className="text-sm text-slate-500">Loading test cases...</p>
            ) : (
              <>
                <div className="flex gap-2">
                  <button
                    onClick={() => setBatchSelected(batchCases.map((item) => item.id))}
                    className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded border border-slate-700"
                  >
                    Select all
                  </button>
                  <button
                    onClick={() => setBatchSelected(batchCases.filter((item) => item.source === 'file').map((item) => item.id))}
                    className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded border border-slate-700"
                  >
                    File samples
                  </button>
                  <button
                    onClick={() => setBatchSelected([])}
                    className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded border border-slate-700"
                  >
                    Clear
                  </button>
                </div>

                <div className="max-h-80 overflow-y-auto space-y-2">
                  {batchCases.map((item) => (
                    <label key={item.id} className="flex items-start gap-2 p-2 rounded bg-slate-800/50 border border-slate-700/60 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={batchSelected.includes(item.id)}
                        onChange={(e) => {
                          setBatchSelected((prev) => {
                            if (e.target.checked) {
                              return [...prev, item.id];
                            }
                            return prev.filter((id) => id !== item.id);
                          });
                        }}
                        className="mt-1"
                      />
                      <div className="min-w-0">
                        <div className="text-xs text-white truncate">{item.name}</div>
                        <div className="text-[11px] text-slate-500">{item.source} | {item.language}</div>
                      </div>
                    </label>
                  ))}
                  {batchCases.length === 0 && <p className="text-sm text-slate-500">No test cases available.</p>}
                </div>

                <button
                  onClick={() => void runBatchAnalysis()}
                  disabled={batchRunning || batchSelected.length === 0}
                  className="w-full py-2.5 bg-cyan-500/20 text-cyan-300 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-50"
                >
                  {batchRunning ? 'Running batch analysis...' : `Run Batch (${batchSelected.length})`}
                </button>
              </>
            )}

            {batchError && (
              <div className="p-3 text-sm bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg">
                {batchError}
              </div>
            )}
          </div>

          <div className="xl:col-span-3 glass rounded-2xl p-5 border border-white/5">
            <h3 className="text-lg font-semibold text-white mb-3">Batch Results</h3>
            {!batchResult ? (
              <p className="text-sm text-slate-500">Select test cases and run batch analysis to compare compliance outcomes.</p>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
                  <div className="p-2 rounded bg-slate-800/70 border border-slate-700">
                    <div className="text-slate-500">Items</div>
                    <div className="text-white font-semibold">{batchResult.summary.total_items}</div>
                  </div>
                  <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30">
                    <div className="text-slate-500">Compliant</div>
                    <div className="text-emerald-300 font-semibold">{batchResult.summary.compliant_count}</div>
                  </div>
                  <div className="p-2 rounded bg-red-500/10 border border-red-500/30">
                    <div className="text-slate-500">Non-compliant</div>
                    <div className="text-red-300 font-semibold">{batchResult.summary.non_compliant_count}</div>
                  </div>
                  <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30">
                    <div className="text-slate-500">Violations</div>
                    <div className="text-amber-300 font-semibold">{batchResult.summary.total_violations}</div>
                  </div>
                  <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/30">
                    <div className="text-slate-500">Compliance Rate</div>
                    <div className="text-cyan-300 font-semibold">{batchResult.summary.compliance_rate}%</div>
                  </div>
                </div>

                <div className="max-h-96 overflow-y-auto space-y-2">
                  {batchResult.items.map((item, idx) => (
                    <div key={`${item.name}-${idx}`} className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm text-white">{item.name}</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                          item.compliant ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'
                        }`}>
                          {item.compliant ? 'PASS' : 'FAIL'}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">
                          {item.violation_count} violations
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300">
                          risk {item.risk_score}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'graph' && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-2 glass rounded-2xl p-5 border border-white/5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Stream Controls</h3>
              <button
                onClick={() => void loadGraphVisualization()}
                className="px-3 py-1.5 text-xs bg-slate-800 text-slate-300 rounded-lg border border-slate-700 hover:border-slate-500"
              >
                Refresh Graph
              </button>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Semantics</label>
              <select
                value={graphSemantics}
                onChange={(e) => setGraphSemantics(e.target.value as SemanticsMode)}
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              >
                <option value="auto">auto</option>
                <option value="grounded">grounded</option>
                <option value="stable">stable</option>
                <option value="preferred">preferred</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Solver Decision Mode</label>
              <select
                value={graphSolverDecisionMode}
                onChange={(e) => setGraphSolverDecisionMode(e.target.value as 'auto' | 'skeptical' | 'credulous')}
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              >
                <option value="auto">auto</option>
                <option value="skeptical">skeptical</option>
                <option value="credulous">credulous</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Max Iterations</label>
              <input
                type="number"
                min={1}
                max={8}
                value={graphMaxIterations}
                onChange={(e) => setGraphMaxIterations(Math.max(1, Number(e.target.value) || 1))}
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              />
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => void startGraphStream()}
                disabled={graphStreaming}
                className="flex-1 py-2.5 bg-cyan-500/20 text-cyan-300 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-50"
              >
                {graphStreaming ? 'Streaming...' : 'Start Stream'}
              </button>
              <button
                onClick={stopGraphStream}
                disabled={!graphStreaming}
                className="px-3 py-2.5 bg-red-500/20 text-red-300 rounded-lg border border-red-500/30 disabled:opacity-50"
              >
                Stop
              </button>
            </div>

            {graphError && (
              <div className="p-3 text-sm bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg">
                {graphError}
              </div>
            )}

            <div>
              <label className="block text-xs text-slate-400 mb-1">Code</label>
              <textarea
                value={graphCode}
                onChange={(e) => setGraphCode(e.target.value)}
                className="w-full h-52 px-3 py-2 bg-slate-900/70 border border-slate-700 rounded-lg text-white font-mono text-xs"
              />
            </div>
          </div>

          <div className="xl:col-span-3 space-y-5">
            <div className="glass rounded-2xl p-5 border border-white/5">
              <h3 className="text-lg font-semibold text-white mb-2">Graph Definition</h3>
              {graphLoading ? (
                <p className="text-sm text-slate-500">Loading graph metadata...</p>
              ) : (
                <>
                  <p className="text-xs text-slate-500 font-mono break-all mb-3">{graphDefinition || 'No graph definition available.'}</p>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs">
                    <div className="p-3 rounded bg-slate-800/60 border border-slate-700/60">
                      <div className="text-slate-400 mb-2">Nodes</div>
                      <div className="space-y-1">
                        {graphNodes.map((node) => (
                          <div key={node.name} className="text-slate-300">
                            <span className="font-mono text-cyan-300">{node.name}</span>
                            <span className="text-slate-500"> - {node.description}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="p-3 rounded bg-slate-800/60 border border-slate-700/60">
                      <div className="text-slate-400 mb-2">Transitions</div>
                      <div className="space-y-1">
                        {graphEdges.map((edge, idx) => (
                          <div key={`${edge.from}-${edge.to}-${idx}`} className="text-slate-300">
                            <span className="font-mono text-violet-300">{edge.from}</span>
                            <span className="text-slate-500">{' -> '}</span>
                            <span className="font-mono text-violet-300">{edge.to}</span>
                            <span className="text-slate-500"> ({edge.condition})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>

            <div className="glass rounded-2xl p-5 border border-white/5">
              <h3 className="text-lg font-semibold text-white mb-2">Live Stream Events</h3>
              <div className="max-h-96 overflow-y-auto space-y-2">
                {graphEvents.length === 0 && (
                  <p className="text-sm text-slate-500">Start streaming to inspect agent_message, state_update, runtime_event, and completion events.</p>
                )}
                {graphEvents.map((entry, idx) => (
                  <div key={`${entry.at}-${idx}`} className="p-3 rounded-lg bg-slate-800/70 border border-slate-700/60">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300">{entry.event}</span>
                      <span className="text-[10px] text-slate-500">{new Date(entry.at).toLocaleTimeString()}</span>
                    </div>
                    <pre className="text-[11px] text-slate-300 whitespace-pre-wrap break-all">
                      {typeof entry.data === 'string' ? entry.data : JSON.stringify(entry.data, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'proofs' && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-2 glass rounded-2xl p-5 border border-white/5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">Proof Registry</h3>
              <button
                onClick={() => void loadProofRegistry()}
                className="px-3 py-1.5 text-xs bg-slate-800 text-slate-300 rounded-lg border border-slate-700 hover:border-slate-500"
              >
                Refresh
              </button>
            </div>

            {proofsLoading ? (
              <p className="text-sm text-slate-500">Loading proofs...</p>
            ) : (
              <div className="max-h-96 overflow-y-auto space-y-2">
                {proofs.map((proof) => (
                  <button
                    key={proof.id}
                    onClick={() => void loadProofBundle(proof.artifact_hash)}
                    className={`w-full text-left p-3 rounded-lg border transition-colors ${
                      selectedProofHash === proof.artifact_hash
                        ? 'bg-cyan-500/10 border-cyan-500/30'
                        : 'bg-slate-800/60 border-slate-700/60 hover:border-slate-500'
                    }`}
                  >
                    <div className="text-xs text-white truncate">{proof.artifact_name || proof.artifact_hash}</div>
                    <div className="text-[11px] text-slate-500 font-mono truncate">{proof.artifact_hash}</div>
                    <div className="text-[11px] text-slate-400 mt-1">{proof.decision} | {new Date(proof.created_at).toLocaleString()}</div>
                  </button>
                ))}
                {proofs.length === 0 && <p className="text-sm text-slate-500">No proofs stored yet.</p>}
              </div>
            )}

            {publicKey && (
              <div className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 text-xs space-y-1">
                <div className="text-slate-400">Signer Public Key</div>
                <div className="text-cyan-300 font-mono break-all">{publicKey.fingerprint}</div>
                <div className="text-slate-500">{publicKey.algorithm} | {publicKey.curve}</div>
              </div>
            )}

            {proofsError && (
              <div className="p-3 text-sm bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg">
                {proofsError}
              </div>
            )}
          </div>

          <div className="xl:col-span-3 glass rounded-2xl p-5 border border-white/5">
            <h3 className="text-lg font-semibold text-white mb-3">Selected Proof Bundle</h3>
            {selectedProofLoading ? (
              <p className="text-sm text-slate-500">Loading proof bundle...</p>
            ) : !selectedProof ? (
              <p className="text-sm text-slate-500">Select a proof to inspect stored evidence and decision details.</p>
            ) : (
              <pre className="text-xs text-slate-300 bg-slate-900/70 border border-slate-700 rounded-lg p-4 overflow-auto max-h-[34rem]">
                {JSON.stringify(selectedProof, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}

      {activeTab === 'dynamic' && (
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          <div className="xl:col-span-2 glass rounded-2xl p-5 border border-white/5 space-y-4">
            <h3 className="text-lg font-semibold text-white">Artifact Filters</h3>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Limit</label>
              <input
                type="number"
                min={1}
                max={500}
                value={dynamicLimit}
                onChange={(e) => setDynamicLimit(Math.min(500, Math.max(1, Number(e.target.value) || 50)))}
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Suite ID</label>
              <input
                value={dynamicSuite}
                onChange={(e) => setDynamicSuite(e.target.value)}
                placeholder="optional"
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Violation Rule</label>
              <input
                value={dynamicRule}
                onChange={(e) => setDynamicRule(e.target.value)}
                placeholder="e.g. SEC-003"
                className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input
                type="checkbox"
                checked={dynamicViolationsOnly}
                onChange={(e) => setDynamicViolationsOnly(e.target.checked)}
              />
              violations only
            </label>
            <button
              onClick={() => void loadDynamicArtifacts()}
              disabled={dynamicLoading}
              className="w-full py-2.5 bg-cyan-500/20 text-cyan-300 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {dynamicLoading ? 'Loading...' : 'Refresh Artifact Index'}
            </button>

            {dynamicError && (
              <div className="p-3 text-sm bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg">
                {dynamicError}
              </div>
            )}
          </div>

          <div className="xl:col-span-3 glass rounded-2xl p-5 border border-white/5">
            <h3 className="text-lg font-semibold text-white mb-3">Dynamic Replay Artifacts</h3>
            <div className="max-h-[40rem] overflow-y-auto space-y-2">
              {dynamicArtifacts.map((artifact, idx) => (
                <div key={`${artifact.history_id}-${artifact.artifact_id || idx}`} className="p-3 rounded-lg bg-slate-800/60 border border-slate-700/60">
                  <div className="flex flex-wrap items-center gap-2 text-[11px]">
                    <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">{artifact.suite_id || 'unknown-suite'}</span>
                    <span className={`px-1.5 py-0.5 rounded ${artifact.compliant ? 'bg-emerald-500/20 text-emerald-300' : 'bg-red-500/20 text-red-300'}`}>
                      {artifact.compliant ? 'compliant' : 'non-compliant'}
                    </span>
                    {artifact.violation_rule_id && (
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono">
                        {artifact.violation_rule_id}
                      </span>
                    )}
                    {artifact.timed_out && (
                      <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-300">timed out</span>
                    )}
                  </div>
                  <div className="text-xs text-slate-400 mt-1">
                    history {artifact.history_id} | {new Date(artifact.timestamp).toLocaleString()} | return {artifact.return_code ?? 'n/a'} | duration {artifact.duration_seconds?.toFixed(3) ?? 'n/a'}s
                  </div>
                  {artifact.replay_fingerprint && (
                    <div className="text-[11px] text-slate-500 font-mono break-all mt-1">
                      replay: {artifact.replay_fingerprint}
                    </div>
                  )}
                </div>
              ))}
              {!dynamicLoading && dynamicArtifacts.length === 0 && (
                <p className="text-sm text-slate-500">No dynamic artifacts matched the current filters.</p>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Policies View with Editor and Groups
function PoliciesView({ 
  policies, 
  initialPolicyData,
  onPolicyCreated 
}: { 
  policies: PolicyRule[];
  initialPolicyData?: {toolName?: string; toolRuleId?: string; description?: string; severity?: string} | null;
  onPolicyCreated?: () => void;
}) {
  const [activeTab, setActiveTab] = useState<'policies' | 'groups'>('policies');
  const [mutationBusy, setMutationBusy] = useState(false);
  const [mutationStatus, setMutationStatus] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'strict' | 'defeasible'>('all');
  const [showEditor, setShowEditor] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<PolicyRule | null>(null);
  const [customPolicies, setCustomPolicies] = useState<PolicyRule[]>([]);
  const [testCode, setTestCode] = useState('');
  const [testResult, setTestResult] = useState<any>(null);
  const [showHistoryModal, setShowHistoryModal] = useState(false);
  const [historyPolicyId, setHistoryPolicyId] = useState<string | null>(null);
  const [policyHistory, setPolicyHistory] = useState<PolicyHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyDiff, setHistoryDiff] = useState<PolicyDiffResponse | null>(null);
  const [fromVersion, setFromVersion] = useState<number | null>(null);
  const [toVersion, setToVersion] = useState<number | null>(null);
  
  // Policy Groups state
  const [policyGroups, setPolicyGroups] = useState<PolicyGroup[]>([]);
  const [showGroupEditor, setShowGroupEditor] = useState(false);
  const [editingGroup, setEditingGroup] = useState<PolicyGroup | null>(null);
  const [groupFormData, setGroupFormData] = useState({
    id: '',
    name: '',
    description: '',
    enabled: true,
    policies: [] as string[]
  });
  const [showRolloutPreviewModal, setShowRolloutPreviewModal] = useState(false);
  const [rolloutOverrides, setRolloutOverrides] = useState<Record<string, boolean>>({});
  const [rolloutLimitCases, setRolloutLimitCases] = useState(20);
  const [rolloutShowChangedOnly, setRolloutShowChangedOnly] = useState(false);
  const [rolloutPreviewLoading, setRolloutPreviewLoading] = useState(false);
  const [rolloutPreviewResult, setRolloutPreviewResult] = useState<{
    baseline: { enabled_group_ids: string[]; policy_ids: string[]; policy_count: number };
    proposed: { enabled_group_ids: string[]; policy_ids: string[]; policy_count: number };
    evaluated_cases: number;
    changed_cases_count: number;
    summary: {
      baseline_compliant: number;
      baseline_non_compliant: number;
      proposed_compliant: number;
      proposed_non_compliant: number;
    };
    cases: Array<{
      id: number;
      name: string;
      language: string;
      baseline: { compliant: boolean; violations: number; unsatisfied_rules: string[] };
      proposed: { compliant: boolean; violations: number; unsatisfied_rules: string[] };
      newly_violated_rules: string[];
      resolved_rules: string[];
      changed: boolean;
    }>;
  } | null>(null);
  
  // Policy templates
  interface PolicyTemplate {
    id: string;
    name: string;
    description: string;
    icon: string;
    category: string;
    policy_count: number;
    policies: string[];
  }
  const [templates, setTemplates] = useState<PolicyTemplate[]>([]);
  const [showTemplates, setShowTemplates] = useState(false);
  const [loadingTemplate, setLoadingTemplate] = useState<string | null>(null);
  const groupFileInputRef = useRef<HTMLInputElement>(null);
  
  // Export/Import policy groups
  const handleExportGroups = async () => {
    try {
      const res = await fetch('/api/v1/policies/groups/export');
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `acpg-policy-groups-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setMutationStatus({ type: 'success', message: 'Policy groups exported.' });
    } catch (e) {
      console.error('Export failed:', e);
      setMutationStatus({ type: 'error', message: 'Failed to export policy groups.' });
    }
  };
  
  const handleImportGroups = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const groups = data.groups || [];
      
      const res = await fetch('/api/v1/policies/groups/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groups, overwrite: false })
      });
      
      if (res.ok) {
        const result = await res.json();
        setMutationStatus({
          type: 'success',
          message: `Imported ${result.total_imported} groups${result.total_skipped > 0 ? ` (${result.total_skipped} skipped)` : ''}.`,
        });
        loadPolicyGroups();
      }
    } catch (e) {
      setMutationStatus({ type: 'error', message: 'Invalid policy-group JSON file.' });
    }
    
    // Reset file input
    if (groupFileInputRef.current) {
      groupFileInputRef.current.value = '';
    }
  };
  
  // Form state for policy editor
  const [formData, setFormData] = useState({
    id: '',
    description: '',
    type: 'strict' as 'strict' | 'defeasible',
    severity: 'medium' as 'low' | 'medium' | 'high' | 'critical',
    checkType: 'regex' as 'regex' | 'ast' | 'manual',
    pattern: '',
    message: '',
    languages: ['python'],
    fix_suggestion: ''
  });
  
  // Load custom policies and groups
  useEffect(() => {
    fetch('/api/v1/policies/file/custom_policies.json')
      .then(res => res.json())
      .then(data => {
        if (data.policies) {
          setCustomPolicies(data.policies);
        }
      })
      .catch(() => {});
    
    loadPolicyGroups();
  }, []);

  // Handle initial policy data from tool mappings
  useEffect(() => {
    if (initialPolicyData) {
      const suggestedId = initialPolicyData.toolRuleId 
        ? `${initialPolicyData.toolName?.toUpperCase() || 'TOOL'}-${initialPolicyData.toolRuleId}`
        : 'NEW-001';
      
      setFormData({
        id: suggestedId,
        description: initialPolicyData.description || `Policy for ${initialPolicyData.toolName}:${initialPolicyData.toolRuleId}`,
        type: 'strict',
        severity: (initialPolicyData.severity as 'low' | 'medium' | 'high' | 'critical') || 'medium',
        checkType: 'manual',
        pattern: '',
        message: initialPolicyData.description || '',
        languages: ['python'],
        fix_suggestion: ''
      });
      setShowEditor(true);
      if (onPolicyCreated) {
        onPolicyCreated();
      }
    }
  }, [initialPolicyData, onPolicyCreated]);
  
  const loadPolicyGroups = () => {
    fetch('/api/v1/policies/groups/')
      .then(res => res.json())
      .then(data => {
        if (data.groups) {
          setPolicyGroups(data.groups);
        }
      })
      .catch(() => {});
  };
  
  const loadTemplates = () => {
    fetch('/api/v1/policies/groups/templates/')
      .then(res => res.json())
      .then(data => {
        if (data.templates) {
          setTemplates(data.templates);
        }
      })
      .catch(() => {});
  };

  const openRolloutPreview = () => {
    const initial: Record<string, boolean> = {};
    for (const group of policyGroups) {
      initial[group.id] = group.enabled;
    }
    setRolloutOverrides(initial);
    setRolloutPreviewResult(null);
    setRolloutShowChangedOnly(false);
    setShowRolloutPreviewModal(true);
  };

  const toggleRolloutGroup = (groupId: string) => {
    setRolloutOverrides(prev => {
      const current = prev[groupId] ?? policyGroups.find(g => g.id === groupId)?.enabled ?? false;
      return { ...prev, [groupId]: !current };
    });
  };

  const runRolloutPreview = async () => {
    setRolloutPreviewLoading(true);
    setMutationStatus(null);
    try {
      const response = await fetch('/api/v1/policies/groups/rollout/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proposed_group_states: rolloutOverrides,
          limit_cases: rolloutLimitCases,
          semantics: 'auto',
          solver_decision_mode: 'auto',
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        setMutationStatus({ type: 'error', message: data.detail || 'Rollout preview failed.' });
        return;
      }
      setRolloutPreviewResult(data);
      setMutationStatus({ type: 'success', message: `Preview complete for ${data.evaluated_cases} cases.` });
    } catch (e) {
      setMutationStatus({ type: 'error', message: 'Rollout preview failed.' });
    } finally {
      setRolloutPreviewLoading(false);
    }
  };

  const loadPolicyHistory = async (policyId: string) => {
    setHistoryLoading(true);
    setHistoryDiff(null);
    try {
      const res = await fetch(`/api/v1/policies/${policyId}/audit/history?limit=100`);
      const data = await res.json();
      const entries: PolicyHistoryEntry[] = data.entries || [];
      setPolicyHistory(entries);
      const versions = entries
        .map(e => e.version)
        .filter((v): v is number => typeof v === 'number')
        .sort((a, b) => a - b);
      if (versions.length >= 2) {
        setFromVersion(versions[versions.length - 2]);
        setToVersion(versions[versions.length - 1]);
      } else if (versions.length === 1) {
        setFromVersion(versions[0]);
        setToVersion(versions[0]);
      } else {
        setFromVersion(null);
        setToVersion(null);
      }
    } catch (e) {
      setPolicyHistory([]);
    } finally {
      setHistoryLoading(false);
    }
  };

  const loadPolicyDiff = async (policyId: string, from: number, to: number) => {
    try {
      const res = await fetch(`/api/v1/policies/${policyId}/audit/diff?from_version=${from}&to_version=${to}`);
      if (!res.ok) {
        setHistoryDiff(null);
        return;
      }
      const data = await res.json();
      setHistoryDiff(data);
    } catch (e) {
      setHistoryDiff(null);
    }
  };
  
  const applyTemplate = async (templateId: string) => {
    setLoadingTemplate(templateId);
    try {
      const res = await fetch(`/api/v1/policies/groups/templates/${templateId}/apply`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (res.ok) {
        loadPolicyGroups();
        setShowTemplates(false);
      }
    } catch (e) {
      console.error('Failed to apply template:', e);
    } finally {
      setLoadingTemplate(null);
    }
  };
  
  // Load templates on mount
  useEffect(() => {
    loadTemplates();
  }, []);

  useEffect(() => {
    if (!showHistoryModal || !historyPolicyId || fromVersion == null || toVersion == null) {
      return;
    }
    loadPolicyDiff(historyPolicyId, fromVersion, toVersion);
  }, [showHistoryModal, historyPolicyId, fromVersion, toVersion]);
  
  const allPolicies = [...policies, ...customPolicies.filter(cp => 
    !policies.some(p => p.id === cp.id)
  )];
  
  const filtered = allPolicies.filter(p => {
    const matchesSearch = p.id.toLowerCase().includes(search.toLowerCase()) ||
                         p.description.toLowerCase().includes(search.toLowerCase());
    const matchesFilter = filter === 'all' || p.type === filter;
    return matchesSearch && matchesFilter;
  });
  
  const grouped = filtered.reduce((acc, p) => {
    const category = p.id.split('-')[0];
    if (!acc[category]) acc[category] = [];
    acc[category].push(p);
    return acc;
  }, {} as Record<string, PolicyRule[]>);
  
  const resetForm = () => {
    setFormData({
      id: '',
      description: '',
      type: 'strict',
      severity: 'medium',
      checkType: 'regex',
      pattern: '',
      message: '',
      languages: ['python'],
      fix_suggestion: ''
    });
    setEditingPolicy(null);
    setTestResult(null);
    setTestCode('');
  };
  
  const handleEdit = (policy: PolicyRule) => {
    setFormData({
      id: policy.id,
      description: policy.description,
      type: policy.type,
      severity: policy.severity,
      checkType: policy.check.type,
      pattern: policy.check.pattern || '',
      message: policy.check.message || '',
      languages: policy.check.languages || ['python'],
      fix_suggestion: policy.fix_suggestion || ''
    });
    setEditingPolicy(policy);
    setShowEditor(true);
  };
  
  const handleTestPolicy = async () => {
    if (!testCode || !formData.pattern) return;
    
    try {
      const response = await fetch('/api/v1/policies/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          policy: {
            id: formData.id || 'TEST-001',
            description: formData.description,
            type: formData.type,
            severity: formData.severity,
            check: {
              type: formData.checkType,
              pattern: formData.pattern,
              languages: formData.languages
            },
            fix_suggestion: formData.fix_suggestion
          },
          code: testCode,
          language: 'python'
        })
      });
      const result = await response.json();
      setTestResult(result);
    } catch (err) {
      setTestResult({ error: 'Test failed' });
    }
  };
  
  const handleSavePolicy = async () => {
    setMutationBusy(true);
    setMutationStatus(null);
    const policyData = {
      id: formData.id,
      description: formData.description,
      type: formData.type,
      severity: formData.severity,
      check: {
        type: formData.checkType,
        pattern: formData.checkType === 'regex' ? formData.pattern : undefined,
        message: formData.checkType === 'manual' ? formData.message : undefined,
        languages: formData.languages
      },
      fix_suggestion: formData.fix_suggestion || undefined
    };
    
    try {
      const url = editingPolicy 
        ? `/api/v1/policies/${editingPolicy.id}`
        : '/api/v1/policies/';
      
      const response = await fetch(url, {
        method: editingPolicy ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policyData)
      });
      
      if (response.ok) {
        // Reload custom policies
        const customRes = await fetch('/api/v1/policies/file/custom_policies.json');
        const customData = await customRes.json();
        setCustomPolicies(customData.policies || []);
        setShowEditor(false);
        resetForm();
        if (onPolicyCreated) {
          onPolicyCreated();
        }
        setMutationStatus({
          type: 'success',
          message: editingPolicy ? `Policy "${policyData.id}" updated.` : `Policy "${policyData.id}" created.`,
        });
      } else {
        const error = await response.json();
        setMutationStatus({ type: 'error', message: error.detail || 'Failed to save policy.' });
      }
    } catch (err) {
      setMutationStatus({ type: 'error', message: 'Failed to save policy.' });
    } finally {
      setMutationBusy(false);
    }
  };
  
  const handleDeletePolicy = async (policyId: string) => {
    const approved = window.confirm(
      `Delete policy "${policyId}"?\n\nThis permanently removes the policy and its future evaluations.`
    );
    if (!approved) return;
    
    setMutationBusy(true);
    setMutationStatus(null);
    try {
      const response = await fetch(`/api/v1/policies/${policyId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setCustomPolicies(prev => prev.filter(p => p.id !== policyId));
        setMutationStatus({ type: 'success', message: `Policy "${policyId}" deleted.` });
      } else {
        const error = await response.json();
        setMutationStatus({ type: 'error', message: error.detail || 'Failed to delete policy.' });
      }
    } catch (err) {
      setMutationStatus({ type: 'error', message: 'Failed to delete policy.' });
    } finally {
      setMutationBusy(false);
    }
  };
  
  const isCustomPolicy = (policyId: string) => 
    customPolicies.some(p => p.id === policyId);
  
  // Group handling functions
  const resetGroupForm = () => {
    setGroupFormData({ id: '', name: '', description: '', enabled: true, policies: [] });
    setEditingGroup(null);
  };
  
  const handleToggleGroup = async (groupId: string) => {
    const target = policyGroups.find(g => g.id === groupId);
    if (!target) return;
    const nextState = !target.enabled;
    const confirmMsg = nextState
      ? `Enable group "${target.name}" (${target.id}) for evaluations?`
      : `Disable group "${target.name}" (${target.id})?\n\nThis removes ${target.policies.length} policies from active checks.`;
    if (!window.confirm(confirmMsg)) {
      return;
    }

    setMutationBusy(true);
    setMutationStatus(null);
    try {
      const response = await fetch(`/api/v1/policies/groups/${groupId}/toggle`, {
        method: 'PATCH'
      });
      if (response.ok) {
        loadPolicyGroups();
        setMutationStatus({
          type: 'success',
          message: `Group "${target.name}" ${nextState ? 'enabled' : 'disabled'}.`,
        });
      } else {
        const error = await response.json();
        setMutationStatus({ type: 'error', message: error.detail || 'Failed to toggle group.' });
      }
    } catch (err) {
      setMutationStatus({ type: 'error', message: 'Failed to toggle group.' });
    } finally {
      setMutationBusy(false);
    }
  };
  
  const handleSaveGroup = async () => {
    setMutationBusy(true);
    setMutationStatus(null);
    try {
      const url = editingGroup 
        ? `/api/v1/policies/groups/${editingGroup.id}`
        : '/api/v1/policies/groups/';
      
      const response = await fetch(url, {
        method: editingGroup ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(groupFormData)
      });
      
      if (response.ok) {
        loadPolicyGroups();
        setShowGroupEditor(false);
        resetGroupForm();
        setMutationStatus({
          type: 'success',
          message: editingGroup
            ? `Group "${groupFormData.name}" updated.`
            : `Group "${groupFormData.name}" created.`,
        });
      } else {
        const error = await response.json();
        setMutationStatus({ type: 'error', message: error.detail || 'Failed to save group.' });
      }
    } catch (err) {
      setMutationStatus({ type: 'error', message: 'Failed to save group.' });
    } finally {
      setMutationBusy(false);
    }
  };
  
  const handleDeleteGroup = async (groupId: string) => {
    const group = policyGroups.find(g => g.id === groupId);
    const approved = window.confirm(
      `Delete group "${group?.name || groupId}"?\n\nThis removes the group definition and ${group?.policies.length ?? 0} policy memberships.`
    );
    if (!approved) return;
    
    setMutationBusy(true);
    setMutationStatus(null);
    try {
      const response = await fetch(`/api/v1/policies/groups/${groupId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        loadPolicyGroups();
        setMutationStatus({ type: 'success', message: `Group "${group?.name || groupId}" deleted.` });
      } else {
        const error = await response.json();
        setMutationStatus({ type: 'error', message: error.detail || 'Failed to delete group.' });
      }
    } catch (err) {
      setMutationStatus({ type: 'error', message: 'Failed to delete group.' });
    } finally {
      setMutationBusy(false);
    }
  };
  
  const handleEditGroup = (group: PolicyGroup) => {
    setGroupFormData({
      id: group.id,
      name: group.name,
      description: group.description,
      enabled: group.enabled,
      policies: group.policies
    });
    setEditingGroup(group);
    setShowGroupEditor(true);
  };
  
  const togglePolicyInGroup = (policyId: string) => {
    setGroupFormData(prev => ({
      ...prev,
      policies: prev.policies.includes(policyId)
        ? prev.policies.filter(p => p !== policyId)
        : [...prev.policies, policyId]
    }));
  };
  
  const enabledGroupCount = policyGroups.filter(g => g.enabled).length;
  const rolloutChangedGroupCount = policyGroups.filter(group => {
    const proposed = rolloutOverrides[group.id] ?? group.enabled;
    return proposed !== group.enabled;
  }).length;
  const rolloutDisplayedCases = rolloutPreviewResult
    ? (rolloutShowChangedOnly
      ? rolloutPreviewResult.cases.filter(item => item.changed)
      : rolloutPreviewResult.cases)
    : [];
  const rolloutBaselineRate = rolloutPreviewResult && rolloutPreviewResult.evaluated_cases > 0
    ? (rolloutPreviewResult.summary.baseline_compliant / rolloutPreviewResult.evaluated_cases) * 100
    : null;
  const rolloutProposedRate = rolloutPreviewResult && rolloutPreviewResult.evaluated_cases > 0
    ? (rolloutPreviewResult.summary.proposed_compliant / rolloutPreviewResult.evaluated_cases) * 100
    : null;
  const rolloutNetComplianceDelta = rolloutPreviewResult
    ? rolloutPreviewResult.summary.proposed_compliant - rolloutPreviewResult.summary.baseline_compliant
    : 0;
  const rolloutNewViolations = rolloutPreviewResult
    ? rolloutPreviewResult.cases.reduce((acc, item) => acc + item.newly_violated_rules.length, 0)
    : 0;
  const rolloutResolvedViolations = rolloutPreviewResult
    ? rolloutPreviewResult.cases.reduce((acc, item) => acc + item.resolved_rules.length, 0)
    : 0;
  
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-violet-500/20 border border-violet-500/30">
              <FileCheck className="w-10 h-10 text-violet-400" />
            </div>
            <div>
              <h2 className="text-2xl font-display font-bold text-white">Policy Library</h2>
              <p className="text-slate-400">
                {allPolicies.length} policies • {policyGroups.length} groups ({enabledGroupCount} active)
              </p>
            </div>
          </div>
          <div className="flex gap-2">
            {activeTab === 'policies' ? (
              <button
                onClick={() => { resetForm(); setShowEditor(true); }}
                disabled={mutationBusy}
                className="flex items-center gap-2 px-4 py-2 bg-violet-500 hover:bg-violet-400 text-white rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Plus className="w-5 h-5" />
                New Policy
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={() => setShowTemplates(true)}
                  disabled={mutationBusy}
                  className="flex items-center gap-2 px-4 py-2 bg-violet-500 hover:bg-violet-400 text-white rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Sparkles className="w-5 h-5" />
                  Templates
                </button>
                <button
                  onClick={handleExportGroups}
                  disabled={mutationBusy}
                  className="flex items-center gap-2 px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Export policy groups"
                >
                  <Download className="w-4 h-4" />
                </button>
                <button
                  onClick={() => groupFileInputRef.current?.click()}
                  disabled={mutationBusy}
                  className="flex items-center gap-2 px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Import policy groups"
                >
                  <Upload className="w-4 h-4" />
                </button>
                <input
                  type="file"
                  ref={groupFileInputRef}
                  accept=".json"
                  onChange={handleImportGroups}
                  className="hidden"
                />
                <button
                  onClick={openRolloutPreview}
                  disabled={mutationBusy}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-white rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  title="Preview rollout impact before changing groups"
                >
                  <Eye className="w-5 h-5" />
                  Preview Rollout
                </button>
                <button
                  onClick={() => { resetGroupForm(); setShowGroupEditor(true); }}
                  disabled={mutationBusy}
                  className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Plus className="w-5 h-5" />
                  New Group
                </button>
              </div>
            )}
          </div>
        </div>
        
        {/* Tabs */}
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setActiveTab('policies')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
              activeTab === 'policies'
                ? 'bg-violet-500/20 text-violet-400 border border-violet-500/30'
                : 'text-slate-400 hover:text-white border border-slate-700'
            }`}
          >
            Policies ({allPolicies.length})
          </button>
          <button
            onClick={() => setActiveTab('groups')}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
              activeTab === 'groups'
                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                : 'text-slate-400 hover:text-white border border-slate-700'
            }`}
          >
            Groups ({policyGroups.length})
          </button>
        </div>

        {mutationStatus && (
          <div className={`mb-4 rounded-xl border px-4 py-3 text-sm ${
            mutationStatus.type === 'success'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
              : mutationStatus.type === 'error'
                ? 'border-red-500/30 bg-red-500/10 text-red-300'
                : 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
          }`}>
            {mutationStatus.message}
          </div>
        )}
        
        {/* Search & Filter - only show for policies tab */}
        {activeTab === 'policies' && (
          <div className="flex gap-4">
            <div className="flex-1 relative">
              <Search className="w-5 h-5 text-slate-400 absolute left-4 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              placeholder="Search policies..."
              className="w-full pl-12 pr-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-violet-500/50"
            />
          </div>
          <div className="flex gap-2">
            {(['all', 'strict', 'defeasible'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                  filter === f
                    ? 'bg-violet-500/20 text-violet-400 border border-violet-500/30'
                    : 'text-slate-400 hover:text-white border border-slate-700'
                }`}
              >
                {f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
        )}
      </div>
      
      {/* Group Editor Modal */}
      {showGroupEditor && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <h3 className="text-xl font-semibold text-white">
                {editingGroup ? `Edit Group: ${editingGroup.name}` : 'Create New Group'}
              </h3>
              <button onClick={() => { setShowGroupEditor(false); resetGroupForm(); }} className="text-slate-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Group Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Group ID</label>
                  <input
                    type="text"
                    value={groupFormData.id}
                    onChange={(e) => setGroupFormData(prev => ({ ...prev, id: e.target.value.toLowerCase().replace(/\s+/g, '-') }))}
                    placeholder="e.g., my-custom-group"
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                    disabled={!!editingGroup}
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Group Name</label>
                  <input
                    type="text"
                    value={groupFormData.name}
                    onChange={(e) => setGroupFormData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="My Custom Group"
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                  />
                </div>
              </div>
              
              <div>
                <label className="block text-sm text-slate-400 mb-2">Description</label>
                <input
                  type="text"
                  value={groupFormData.description}
                  onChange={(e) => setGroupFormData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="What this group is for"
                  className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                />
              </div>
              
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="group-enabled"
                  checked={groupFormData.enabled}
                  onChange={(e) => setGroupFormData(prev => ({ ...prev, enabled: e.target.checked }))}
                  className="w-5 h-5 rounded border-white/20 bg-slate-800"
                />
                <label htmlFor="group-enabled" className="text-sm text-slate-300">Enable this group for evaluations</label>
              </div>
              
              {/* Policy Selection */}
              <div>
                <label className="block text-sm text-slate-400 mb-2">
                  Select Policies ({groupFormData.policies.length} selected)
                </label>
                <div className="max-h-64 overflow-y-auto bg-slate-900/50 rounded-xl p-4 space-y-2">
                  {allPolicies.map(policy => (
                    <label
                      key={policy.id}
                      className={`flex items-center gap-3 p-2 rounded-lg cursor-pointer transition-all ${
                        groupFormData.policies.includes(policy.id)
                          ? 'bg-emerald-500/20 border border-emerald-500/30'
                          : 'hover:bg-slate-800/50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={groupFormData.policies.includes(policy.id)}
                        onChange={() => togglePolicyInGroup(policy.id)}
                        className="w-4 h-4 rounded"
                      />
                      <span className="font-mono text-sm text-violet-400">{policy.id}</span>
                      <span className="text-sm text-slate-400 truncate">{policy.description}</span>
                      <span className={`ml-auto px-1.5 py-0.5 text-[10px] uppercase font-semibold rounded ${
                        policy.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        policy.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        policy.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {policy.severity}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            </div>
            
            {/* Actions */}
            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => { setShowGroupEditor(false); resetGroupForm(); }}
                disabled={mutationBusy}
                className="px-6 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveGroup}
                disabled={!groupFormData.id || !groupFormData.name || mutationBusy}
                className="px-6 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl font-medium"
              >
                {mutationBusy ? 'Saving...' : (editingGroup ? 'Update Group' : 'Create Group')}
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Policy Templates Modal */}
      {showTemplates && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <div>
                <h3 className="text-xl font-semibold text-white flex items-center gap-2">
                  <Sparkles className="w-6 h-6 text-violet-400" />
                  Policy Templates
                </h3>
                <p className="text-sm text-slate-400 mt-1">Quick-start with pre-built policy groups</p>
              </div>
              <button onClick={() => setShowTemplates(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6">
              <div className="grid grid-cols-2 gap-4">
                {templates.map(template => (
                  <div 
                    key={template.id}
                    className="group p-4 bg-slate-800/30 hover:bg-slate-800/50 border border-white/5 hover:border-violet-500/30 rounded-xl transition-all cursor-pointer"
                    onClick={() => applyTemplate(template.id)}
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-2xl">{template.icon}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <h4 className="font-semibold text-white group-hover:text-violet-300 transition-colors">
                            {template.name}
                          </h4>
                          <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
                            {template.policy_count} policies
                          </span>
                        </div>
                        <p className="text-sm text-slate-400 mt-1">{template.description}</p>
                        <div className="flex flex-wrap gap-1 mt-2">
                          {template.policies.slice(0, 4).map(policyId => (
                            <span key={policyId} className="text-[10px] font-mono px-1.5 py-0.5 bg-violet-500/10 text-violet-400 rounded">
                              {policyId}
                            </span>
                          ))}
                          {template.policies.length > 4 && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-700 text-slate-400 rounded">
                              +{template.policies.length - 4}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    {loadingTemplate === template.id && (
                      <div className="mt-3 flex items-center gap-2 text-sm text-violet-400">
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Creating group...
                      </div>
                    )}
                  </div>
                ))}
              </div>
              
              {templates.length === 0 && (
                <div className="text-center py-12 text-slate-400">
                  <Sparkles className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No templates available</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Rollout Preview Modal */}
      {showRolloutPreviewModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-6xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <div>
                <h3 className="text-xl font-semibold text-white">Policy Rollout Preview</h3>
                <p className="text-sm text-slate-400 mt-1">
                  Simulate group state changes and evaluate impact on stored test cases before rollout.
                </p>
              </div>
              <button
                onClick={() => {
                  setShowRolloutPreviewModal(false);
                  setRolloutPreviewResult(null);
                }}
                className="text-slate-400 hover:text-white"
              >
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-semibold text-white uppercase tracking-wider">Proposed Group States</h4>
                    <div className="flex items-center gap-2">
                      <label className="text-xs text-slate-400">Cases</label>
                      <input
                        type="number"
                        min={1}
                        max={200}
                        value={rolloutLimitCases}
                        onChange={(e) => setRolloutLimitCases(Math.max(1, Math.min(200, Number(e.target.value) || 20)))}
                        className="w-20 px-2 py-1 bg-slate-800/50 border border-white/10 rounded text-white text-sm"
                      />
                    </div>
                  </div>
                  <div className="text-xs text-slate-400">
                    Planned group changes: <span className="font-mono text-cyan-300">{rolloutChangedGroupCount}</span>
                  </div>
                  <div className="max-h-72 overflow-auto space-y-2 pr-1">
                    {policyGroups.map(group => {
                      const proposedEnabled = rolloutOverrides[group.id] ?? group.enabled;
                      const changed = proposedEnabled !== group.enabled;
                      return (
                        <div
                          key={`rollout-${group.id}`}
                          className={`flex items-center justify-between p-3 rounded-lg border ${
                            changed
                              ? 'border-cyan-500/40 bg-cyan-500/10'
                              : 'border-white/10 bg-slate-800/40'
                          }`}
                        >
                          <div>
                            <div className="font-medium text-white text-sm">{group.name}</div>
                            <div className="text-xs text-slate-400 font-mono">{group.id}</div>
                            {changed && (
                              <div className="text-[11px] text-cyan-300 mt-1">
                                {group.enabled ? 'Will be disabled' : 'Will be enabled'}
                              </div>
                            )}
                          </div>
                          <button
                            onClick={() => toggleRolloutGroup(group.id)}
                            className={`w-12 h-7 rounded-full transition-all relative ${
                              proposedEnabled ? 'bg-emerald-500' : 'bg-slate-700'
                            }`}
                            title={`Proposed: ${proposedEnabled ? 'enabled' : 'disabled'}`}
                          >
                            <div className={`absolute top-1 w-5 h-5 bg-white rounded-full transition-all ${
                              proposedEnabled ? 'left-6' : 'left-1'
                            }`} />
                          </button>
                        </div>
                      );
                    })}
                  </div>
                  <button
                    onClick={runRolloutPreview}
                    disabled={rolloutPreviewLoading}
                    className="w-full px-4 py-3 bg-cyan-500 hover:bg-cyan-400 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl font-medium transition-all"
                  >
                    {rolloutPreviewLoading ? 'Evaluating...' : 'Run Preview'}
                  </button>
                </div>

                <div className="space-y-4">
                  {!rolloutPreviewResult ? (
                    <div className="h-full min-h-[220px] rounded-xl border border-white/10 bg-slate-800/30 p-4 text-sm text-slate-500">
                      Preview results will appear here.
                    </div>
                  ) : (
                    <>
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                          <div className="text-xs text-emerald-300 uppercase tracking-wider">Baseline Compliant</div>
                          <div className="text-2xl font-semibold text-emerald-200">
                            {rolloutPreviewResult.summary.baseline_compliant}
                          </div>
                          {rolloutBaselineRate != null && (
                            <div className="text-xs text-emerald-300 mt-1">
                              {rolloutBaselineRate.toFixed(1)}%
                            </div>
                          )}
                        </div>
                        <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                          <div className="text-xs text-cyan-300 uppercase tracking-wider">Proposed Compliant</div>
                          <div className="text-2xl font-semibold text-cyan-200">
                            {rolloutPreviewResult.summary.proposed_compliant}
                          </div>
                          {rolloutProposedRate != null && (
                            <div className="text-xs text-cyan-300 mt-1">
                              {rolloutProposedRate.toFixed(1)}%
                            </div>
                          )}
                        </div>
                        <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                          <div className="text-xs text-amber-300 uppercase tracking-wider">Cases Evaluated</div>
                          <div className="text-2xl font-semibold text-amber-200">
                            {rolloutPreviewResult.evaluated_cases}
                          </div>
                        </div>
                        <div className="p-3 rounded-lg bg-violet-500/10 border border-violet-500/20">
                          <div className="text-xs text-violet-300 uppercase tracking-wider">Cases Changed</div>
                          <div className="text-2xl font-semibold text-violet-200">
                            {rolloutPreviewResult.changed_cases_count}
                          </div>
                          <div className="text-xs text-violet-300 mt-1">
                            {rolloutPreviewResult.evaluated_cases > 0
                              ? `${((rolloutPreviewResult.changed_cases_count / rolloutPreviewResult.evaluated_cases) * 100).toFixed(1)}%`
                              : '0.0%'}
                          </div>
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div className="rounded-lg border border-white/10 bg-slate-800/40 px-3 py-2 text-xs text-slate-300">
                          Net compliance delta:{' '}
                          <span className={rolloutNetComplianceDelta >= 0 ? 'text-emerald-300 font-semibold' : 'text-red-300 font-semibold'}>
                            {rolloutNetComplianceDelta >= 0 ? '+' : ''}{rolloutNetComplianceDelta}
                          </span>
                        </div>
                        <div className="rounded-lg border border-white/10 bg-slate-800/40 px-3 py-2 text-xs text-slate-300">
                          New violations introduced: <span className="font-mono text-red-300">{rolloutNewViolations}</span>
                        </div>
                        <div className="rounded-lg border border-white/10 bg-slate-800/40 px-3 py-2 text-xs text-slate-300">
                          Violations resolved: <span className="font-mono text-emerald-300">{rolloutResolvedViolations}</span>
                        </div>
                      </div>
                      <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3">
                        Baseline policies: <span className="font-mono">{rolloutPreviewResult.baseline.policy_count}</span>
                        <span>•</span>
                        Proposed policies: <span className="font-mono">{rolloutPreviewResult.proposed.policy_count}</span>
                        <label className="inline-flex items-center gap-2 ml-auto cursor-pointer">
                          <input
                            type="checkbox"
                            checked={rolloutShowChangedOnly}
                            onChange={(e) => setRolloutShowChangedOnly(e.target.checked)}
                            className="rounded border-white/20 bg-slate-800"
                          />
                          <span className="text-xs text-slate-300">
                            Show changed cases only ({rolloutPreviewResult.changed_cases_count})
                          </span>
                        </label>
                      </div>
                      <div className="max-h-72 overflow-auto border border-white/10 rounded-lg">
                        <table className="w-full text-xs">
                          <thead className="bg-slate-900/50 text-slate-400 uppercase tracking-wider">
                            <tr>
                              <th className="text-left px-3 py-2">Case</th>
                              <th className="text-left px-3 py-2">Baseline</th>
                              <th className="text-left px-3 py-2">Proposed</th>
                              <th className="text-left px-3 py-2">Delta</th>
                            </tr>
                          </thead>
                          <tbody>
                            {rolloutDisplayedCases.map(item => (
                              <tr
                                key={`rollout-case-${item.id}`}
                                className={`border-t border-white/5 ${item.changed ? 'bg-cyan-500/[0.03]' : ''}`}
                              >
                                <td className="px-3 py-2">
                                  <div className="text-slate-200 font-medium">{item.name}</div>
                                  <div className="text-slate-500 font-mono">{item.language}</div>
                                </td>
                                <td className="px-3 py-2">
                                  <span className={item.baseline.compliant ? 'text-emerald-300' : 'text-red-300'}>
                                    {item.baseline.compliant ? 'Compliant' : 'Non-compliant'}
                                  </span>
                                </td>
                                <td className="px-3 py-2">
                                  <span className={item.proposed.compliant ? 'text-emerald-300' : 'text-red-300'}>
                                    {item.proposed.compliant ? 'Compliant' : 'Non-compliant'}
                                  </span>
                                </td>
                                <td className="px-3 py-2">
                                  {item.changed ? (
                                    <div className="space-y-1">
                                      {item.newly_violated_rules.length > 0 && (
                                        <div className="text-red-300">
                                          + {item.newly_violated_rules.join(', ')}
                                        </div>
                                      )}
                                      {item.resolved_rules.length > 0 && (
                                        <div className="text-emerald-300">
                                          - {item.resolved_rules.join(', ')}
                                        </div>
                                      )}
                                    </div>
                                  ) : (
                                    <span className="text-slate-500">No change</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                            {rolloutDisplayedCases.length === 0 && (
                              <tr>
                                <td className="px-3 py-4 text-slate-500" colSpan={4}>
                                  No changed cases for current filter.
                                </td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Policy History Modal */}
      {showHistoryModal && historyPolicyId && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-6xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <div>
                <h3 className="text-xl font-semibold text-white">Policy History</h3>
                <p className="text-sm text-slate-400 mt-1 font-mono">{historyPolicyId}</p>
              </div>
              <button
                onClick={() => {
                  setShowHistoryModal(false);
                  setHistoryPolicyId(null);
                  setHistoryDiff(null);
                  setPolicyHistory([]);
                }}
                className="text-slate-400 hover:text-white"
              >
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            <div className="p-6 space-y-5">
              {historyLoading ? (
                <p className="text-slate-400 text-sm">Loading history...</p>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-slate-400 mb-2">From version</label>
                      <select
                        value={fromVersion ?? ''}
                        onChange={(e) => setFromVersion(Number(e.target.value))}
                        className="w-full px-3 py-2 bg-slate-800/50 border border-white/10 rounded-lg text-white"
                      >
                        {policyHistory
                          .map(entry => entry.version)
                          .filter((version): version is number => typeof version === 'number')
                          .sort((a, b) => a - b)
                          .map(version => (
                            <option key={`from-${version}`} value={version}>
                              v{version}
                            </option>
                          ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm text-slate-400 mb-2">To version</label>
                      <select
                        value={toVersion ?? ''}
                        onChange={(e) => setToVersion(Number(e.target.value))}
                        className="w-full px-3 py-2 bg-slate-800/50 border border-white/10 rounded-lg text-white"
                      >
                        {policyHistory
                          .map(entry => entry.version)
                          .filter((version): version is number => typeof version === 'number')
                          .sort((a, b) => a - b)
                          .map(version => (
                            <option key={`to-${version}`} value={version}>
                              v{version}
                            </option>
                          ))}
                      </select>
                    </div>
                  </div>

                  {historyDiff && (
                    <div className="space-y-3">
                      <div className="p-3 bg-slate-800/40 border border-white/10 rounded-lg">
                        <div className="text-xs uppercase tracking-wider text-slate-500 mb-2">Changed Fields</div>
                        <div className="flex flex-wrap gap-2">
                          {historyDiff.changed_fields.length > 0 ? (
                            historyDiff.changed_fields.map(field => (
                              <span
                                key={field}
                                className="px-2 py-1 rounded-md text-xs font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                              >
                                {field}
                              </span>
                            ))
                          ) : (
                            <span className="text-xs text-slate-500">No field changes detected.</span>
                          )}
                        </div>
                      </div>
                      <div className="rounded-lg border border-white/10 overflow-hidden">
                        <DiffEditor
                          original={historyDiff.before_json}
                          modified={historyDiff.after_json}
                          language="json"
                          height="320px"
                          options={{
                            readOnly: true,
                            minimap: { enabled: false },
                            fontSize: 12,
                            wordWrap: 'on',
                          }}
                        />
                      </div>
                    </div>
                  )}

                  <div className="border border-white/10 rounded-lg overflow-hidden">
                    <div className="px-4 py-2 bg-slate-800/40 text-sm text-slate-300 font-medium">
                      Version Timeline
                    </div>
                    <div className="max-h-64 overflow-auto divide-y divide-white/5">
                      {policyHistory.length === 0 ? (
                        <div className="px-4 py-4 text-sm text-slate-500">No history records available.</div>
                      ) : (
                        policyHistory.map(entry => (
                          <div key={entry.id} className="px-4 py-3 text-sm">
                            <div className="flex items-center justify-between gap-3">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-cyan-300">v{entry.version ?? '?'}</span>
                                <span className="px-2 py-0.5 rounded text-[11px] uppercase bg-slate-700 text-slate-300">
                                  {entry.action}
                                </span>
                                {entry.changed_by && (
                                  <span className="text-xs text-slate-500">by {entry.changed_by}</span>
                                )}
                              </div>
                              <span className="text-xs text-slate-500">
                                {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'unknown time'}
                              </span>
                            </div>
                            {entry.changed_fields && entry.changed_fields.length > 0 && (
                              <div className="mt-2 flex flex-wrap gap-1">
                                {entry.changed_fields.slice(0, 8).map(field => (
                                  <span key={`${entry.id}-${field}`} className="text-[10px] px-1.5 py-0.5 bg-slate-800 text-slate-400 rounded font-mono">
                                    {field}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* Policy Editor Modal */}
      {showEditor && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-8">
          <div className="glass rounded-2xl border border-white/10 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-white/10 flex items-center justify-between">
              <h3 className="text-xl font-semibold text-white">
                {editingPolicy ? `Edit Policy: ${editingPolicy.id}` : 'Create New Policy'}
              </h3>
              <button onClick={() => { setShowEditor(false); resetForm(); }} className="text-slate-400 hover:text-white">
                <XCircle className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-6 space-y-6">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Policy ID</label>
                  <input
                    type="text"
                    value={formData.id}
                    onChange={(e) => setFormData(prev => ({ ...prev, id: e.target.value.toUpperCase() }))}
                    placeholder="e.g., CUSTOM-001"
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                    disabled={!!editingPolicy}
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Description</label>
                  <input
                    type="text"
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                    placeholder="What this policy checks for"
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                  />
                </div>
              </div>
              
              {/* Type & Severity */}
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Type</label>
                  <select
                    value={formData.type}
                    onChange={(e) => setFormData(prev => ({ ...prev, type: e.target.value as any }))}
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white"
                  >
                    <option value="strict">Strict</option>
                    <option value="defeasible">Defeasible</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Severity</label>
                  <select
                    value={formData.severity}
                    onChange={(e) => setFormData(prev => ({ ...prev, severity: e.target.value as any }))}
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Check Type</label>
                  <select
                    value={formData.checkType}
                    onChange={(e) => setFormData(prev => ({ ...prev, checkType: e.target.value as any }))}
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white"
                  >
                    <option value="regex">Regex Pattern</option>
                    <option value="manual">Manual Review</option>
                  </select>
                </div>
              </div>
              
              {/* Pattern */}
              {formData.checkType === 'regex' && (
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Regex Pattern</label>
                  <input
                    type="text"
                    value={formData.pattern}
                    onChange={(e) => setFormData(prev => ({ ...prev, pattern: e.target.value }))}
                    placeholder={'e.g., password\\s*=\\s*[\'"].*[\'"]'}
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white font-mono placeholder-slate-500"
                  />
                </div>
              )}
              
              {formData.checkType === 'manual' && (
                <div>
                  <label className="block text-sm text-slate-400 mb-2">Review Message</label>
                  <input
                    type="text"
                    value={formData.message}
                    onChange={(e) => setFormData(prev => ({ ...prev, message: e.target.value }))}
                    placeholder="Instructions for manual review"
                    className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                  />
                </div>
              )}
              
              {/* Fix Suggestion */}
              <div>
                <label className="block text-sm text-slate-400 mb-2">Fix Suggestion</label>
                <input
                  type="text"
                  value={formData.fix_suggestion}
                  onChange={(e) => setFormData(prev => ({ ...prev, fix_suggestion: e.target.value }))}
                  placeholder="How to fix violations of this policy"
                  className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500"
                />
              </div>
              
              {/* Test Section */}
              {formData.checkType === 'regex' && formData.pattern && (
                <div className="border-t border-white/10 pt-6">
                  <h4 className="text-lg font-semibold text-white mb-4">Test Policy</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm text-slate-400 mb-2">Test Code</label>
                      <textarea
                        value={testCode}
                        onChange={(e) => setTestCode(e.target.value)}
                        placeholder="Paste code to test against this policy..."
                        className="w-full h-32 px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white font-mono text-sm placeholder-slate-500"
                      />
                      <button
                        onClick={handleTestPolicy}
                        className="mt-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-white rounded-lg text-sm font-medium"
                      >
                        Run Test
                      </button>
                    </div>
                    <div>
                      <label className="block text-sm text-slate-400 mb-2">Test Results</label>
                      <div className="h-32 px-4 py-3 bg-slate-900/50 border border-white/10 rounded-xl overflow-auto">
                        {testResult ? (
                          testResult.error ? (
                            <p className="text-red-400 text-sm">{testResult.error}</p>
                          ) : (
                            <div className="text-sm">
                              <p className={testResult.violations_found > 0 ? 'text-amber-400' : 'text-emerald-400'}>
                                {testResult.violations_found} violation(s) found
                              </p>
                              {testResult.violations?.map((v: any, i: number) => (
                                <div key={i} className="mt-2 p-2 bg-slate-800/50 rounded text-xs">
                                  <span className="text-slate-400">Line {v.line}:</span>{' '}
                                  <span className="text-white font-mono">{v.evidence}</span>
                                </div>
                              ))}
                            </div>
                          )
                        ) : (
                          <p className="text-slate-500 text-sm">Test results will appear here</p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
            
            {/* Actions */}
            <div className="p-6 border-t border-white/10 flex justify-end gap-3">
              <button
                onClick={() => { setShowEditor(false); resetForm(); }}
                disabled={mutationBusy}
                className="px-6 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Cancel
              </button>
              <button
                onClick={handleSavePolicy}
                disabled={!formData.id || !formData.description || mutationBusy}
                className="px-6 py-2 bg-violet-500 hover:bg-violet-400 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl font-medium"
              >
                {mutationBusy ? 'Saving...' : (editingPolicy ? 'Update Policy' : 'Create Policy')}
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Policies Tab Content */}
      {activeTab === 'policies' && (
        <div className="grid grid-cols-2 gap-6">
          {Object.entries(grouped).map(([category, catPolicies]) => (
            <div key={category} className="glass rounded-2xl p-6 border border-white/5">
              <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                <span className="px-2 py-1 bg-violet-500/20 text-violet-400 rounded-lg font-mono text-sm">
                  {category}
                </span>
                <span className="text-slate-400 text-sm font-normal">
                  {catPolicies.length} {catPolicies.length === 1 ? 'policy' : 'policies'}
                </span>
              </h3>
              <div className="space-y-3">
                {catPolicies.map(policy => (
                  <div
                    key={policy.id}
                    className={`p-4 bg-slate-800/50 rounded-xl border transition-all ${
                      isCustomPolicy(policy.id) 
                        ? 'border-violet-500/30 hover:border-violet-500/50' 
                        : 'border-white/5 hover:border-violet-500/30'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-violet-400">{policy.id}</span>
                        <span className={`px-1.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider rounded ${
                          policy.type === 'strict'
                            ? 'bg-red-500/10 text-red-400'
                            : 'bg-amber-500/10 text-amber-400'
                        }`}>
                          {policy.type}
                        </span>
                        <span className={`px-1.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider rounded ${
                          policy.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                          policy.severity === 'high' ? 'bg-orange-500/10 text-orange-400' :
                          policy.severity === 'medium' ? 'bg-amber-500/10 text-amber-400' :
                          'bg-slate-700 text-slate-400'
                        }`}>
                          {policy.severity}
                        </span>
                        {isCustomPolicy(policy.id) && (
                          <span className="px-1.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider rounded bg-violet-500/20 text-violet-400">
                            Custom
                          </span>
                        )}
                      </div>
                      <div className="flex gap-1">
                        <button
                          onClick={() => {
                            setHistoryPolicyId(policy.id);
                            setShowHistoryModal(true);
                            loadPolicyHistory(policy.id);
                          }}
                          disabled={mutationBusy}
                          className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
                          title="View history and diffs"
                        >
                          <Clock className="w-4 h-4" />
                        </button>
                      {isCustomPolicy(policy.id) && (
                        <>
                          <button
                            onClick={() => handleEdit(policy)}
                            disabled={mutationBusy}
                            className="p-1.5 text-slate-400 hover:text-violet-400 hover:bg-violet-500/10 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeletePolicy(policy.id)}
                            disabled={mutationBusy}
                            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </>
                      )}
                      </div>
                    </div>
                    <p className="text-sm text-slate-400">{policy.description}</p>
                    {policy.check?.pattern && (
                      <p className="text-xs text-slate-500 font-mono mt-2 truncate">
                        Pattern: {policy.check.pattern}
                      </p>
                    )}
                    {policy.fix_suggestion && (
                      <p className="text-xs text-cyan-400 mt-2">
                        💡 {policy.fix_suggestion}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      
      {/* Groups Tab Content */}
      {activeTab === 'groups' && (
        <div className="space-y-4">
          {policyGroups.length === 0 ? (
            <div className="glass rounded-2xl p-12 border border-white/5 text-center">
              <FileCheck className="w-16 h-16 text-slate-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-white mb-2">No Policy Groups</h3>
              <p className="text-slate-400 mb-6">Create groups to organize and enable/disable sets of policies together.</p>
              <button
                onClick={() => { resetGroupForm(); setShowGroupEditor(true); }}
                disabled={mutationBusy}
                className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Plus className="w-5 h-5" />
                Create First Group
              </button>
            </div>
          ) : (
            policyGroups.map(group => (
              <div 
                key={group.id} 
                className={`glass rounded-2xl p-6 border transition-all ${
                  group.enabled 
                    ? 'border-emerald-500/30 bg-emerald-500/5' 
                    : 'border-white/5 opacity-60'
                }`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-4">
                    <button
                      onClick={() => handleToggleGroup(group.id)}
                      disabled={mutationBusy}
                      className={`w-12 h-7 rounded-full transition-all relative ${
                        group.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                      } disabled:opacity-40 disabled:cursor-not-allowed`}
                    >
                      <div className={`absolute top-1 w-5 h-5 bg-white rounded-full transition-all ${
                        group.enabled ? 'left-6' : 'left-1'
                      }`} />
                    </button>
                    <div>
                      <h3 className="text-lg font-semibold text-white">{group.name}</h3>
                      <p className="text-sm text-slate-400">{group.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`px-3 py-1 text-sm rounded-lg ${
                      group.enabled 
                        ? 'bg-emerald-500/20 text-emerald-400' 
                        : 'bg-slate-700 text-slate-400'
                    }`}>
                      {group.policies.length} policies
                    </span>
                    <button
                      onClick={() => handleEditGroup(group)}
                      disabled={mutationBusy}
                      className="p-2 text-slate-400 hover:text-violet-400 hover:bg-violet-500/10 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteGroup(group.id)}
                      disabled={mutationBusy}
                      className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                
                {/* Policy list with descriptions */}
                <div className="flex flex-wrap gap-2">
                  {group.policies.slice(0, 10).map((policyId, idx) => {
                    // Use policy_details from API response, or fallback to allPolicies lookup
                    const policyDetail = group.policy_details?.[idx];
                    const policy = policyDetail || allPolicies.find(p => p.id === policyId);
                    const description = policyDetail?.description || (policy as any)?.description || policyId;
                    const severity = policyDetail?.severity || (policy as any)?.severity;
                    
                    return (
                      <span 
                        key={policyId} 
                        className="group/policy relative px-2 py-1 bg-slate-800/50 text-slate-300 text-xs font-mono rounded-lg cursor-help"
                        title={description}
                      >
                        {policyId}
                        {/* Tooltip with description */}
                        <div className="absolute bottom-full left-0 mb-2 hidden group-hover/policy:block z-50 w-72 p-3 bg-slate-900 border border-slate-700 rounded-lg shadow-xl text-left">
                          <div className="font-semibold text-violet-400 mb-1">{policyId}</div>
                          <div className="text-slate-300 text-xs font-sans leading-relaxed">{description}</div>
                          {severity && (
                            <div className="flex gap-2 mt-2">
                              <span className={`px-1.5 py-0.5 text-[10px] uppercase font-semibold rounded ${
                                severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                                severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                                severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                                'bg-slate-700 text-slate-400'
                              }`}>{severity}</span>
                            </div>
                          )}
                        </div>
                      </span>
                    );
                  })}
                  {group.policies.length > 10 && (
                    <span className="px-2 py-1 bg-slate-800/50 text-slate-500 text-xs rounded-lg">
                      +{group.policies.length - 10} more
                    </span>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

// Models Configuration View
type ModelProviderDiagnostics = {
  code?: string;
  summary?: string;
  checks?: string[];
  suggestions?: string[];
  base_url?: string;
  model?: string;
  provider_type?: string;
  raw_error?: string;
};

type OpenAIModelMetadata = {
  model: string;
  display_name: string;
  family?: string;
  preferred_endpoint?: string;
  is_legacy?: boolean;
  context_window?: number;
  max_output_tokens?: number;
  input_cost_per_1m?: number | null;
  cached_input_cost_per_1m?: number | null;
  output_cost_per_1m?: number | null;
  knowledge_cutoff?: string | null;
  docs_url?: string;
};

type ProviderFormState = {
  id: string;
  type: string;
  name: string;
  base_url: string;
  api_key: string;
  model: string;
  max_tokens: number;
  temperature: number;
  context_window: number;
  max_output_tokens?: number | null;
  preferred_endpoint?: string;
  request_timeout_seconds?: number | null;
  input_cost_per_1m?: number | null;
  cached_input_cost_per_1m?: number | null;
  output_cost_per_1m?: number | null;
  docs_url?: string | null;
  is_active?: boolean;
  api_key_set?: boolean;
};

type ProviderConnectionStatus = 'unknown' | 'testing' | 'success' | 'error';
type ProviderStatusFilter = 'all' | 'online' | 'offline' | 'untested';

type ProviderTestSnapshot = {
  tested_at: string;
  success: boolean;
  duration_ms: number;
  endpoint?: string;
  total_tokens?: number;
  estimated_cost_usd?: number | null;
  error?: string;
};

type ProviderTestResult = {
  id: string;
  provider: string;
  model: string;
  success: boolean;
  response?: string | null;
  error?: string | null;
  diagnostics?: ModelProviderDiagnostics | null;
  endpoint?: string | null;
  usage?: { total_tokens?: number } | null;
  estimated_cost_usd?: number | null;
  duration_ms: number;
  timeout_seconds: number;
};

type ActiveProviderTest = {
  id: string;
  providerName: string;
  model: string;
  timeoutSeconds: number;
  startedAtMs: number;
};

function ModelsConfigurationView() {
  const [providers, setProviders] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeProvider, setActiveProvider] = useState<string>('');
  const [editingProvider, setEditingProvider] = useState<any>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<ProviderTestResult | null>(null);
  const [activeTest, setActiveTest] = useState<ActiveProviderTest | null>(null);
  const [activeTestElapsedMs, setActiveTestElapsedMs] = useState(0);
  const [providerStatus, setProviderStatus] = useState<Record<string, ProviderConnectionStatus>>({});
  const [providerDiagnostics, setProviderDiagnostics] = useState<Record<string, ModelProviderDiagnostics | null>>({});
  const [providerTestSnapshots, setProviderTestSnapshots] = useState<Record<string, ProviderTestSnapshot>>({});
  const [statusFilter, setStatusFilter] = useState<ProviderStatusFilter>('all');
  const [testingAll, setTestingAll] = useState(false);
  const [openaiCatalog, setOpenaiCatalog] = useState<OpenAIModelMetadata[]>([]);
  const [openaiCatalogLoading, setOpenaiCatalogLoading] = useState(false);
  const editFormRef = useRef<HTMLDivElement | null>(null);
  
  const [newProvider, setNewProvider] = useState<ProviderFormState>({
    id: '',
    type: 'openai',
    name: '',
    base_url: 'https://api.openai.com/v1',
    api_key: '${OPENAI_API_KEY}',
    model: 'gpt-4',
    max_tokens: 2000,
    temperature: 0.3,
    context_window: 8192,
    max_output_tokens: null,
    preferred_endpoint: 'responses',
    request_timeout_seconds: null,
    input_cost_per_1m: null,
    cached_input_cost_per_1m: null,
    output_cost_per_1m: null,
    docs_url: null,
  });

  const loadProviders = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/llm/config');
      const data = await res.json();
      setActiveProvider(data.active_provider || '');
      setProviders(
        Object.entries(data.providers || {}).map(([id, config]: [string, any]) => ({
          id,
          ...config
        }))
      );
    } catch (err) {
      setError('Failed to load providers');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadProviders();
  }, [loadProviders]);

  const loadOpenAICatalog = useCallback(async () => {
    setOpenaiCatalogLoading(true);
    try {
      const res = await fetch('/api/v1/llm/catalog/openai');
      if (!res.ok) {
        throw new Error('Failed to load OpenAI model catalog');
      }
      const data = await res.json();
      setOpenaiCatalog(data.models || []);
    } catch {
      setOpenaiCatalog([]);
    } finally {
      setOpenaiCatalogLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadOpenAICatalog();
  }, [loadOpenAICatalog]);

  const resetNewProvider = useCallback(() => {
    setNewProvider({
      id: '',
      type: 'openai',
      name: '',
      base_url: 'https://api.openai.com/v1',
      api_key: '${OPENAI_API_KEY}',
      model: 'gpt-4',
      max_tokens: 2000,
      temperature: 0.3,
      context_window: 8192,
      max_output_tokens: null,
      preferred_endpoint: 'responses',
      request_timeout_seconds: null,
      input_cost_per_1m: null,
      cached_input_cost_per_1m: null,
      output_cost_per_1m: null,
      docs_url: null,
    });
  }, []);

  const applyOpenAIModelMetadata = useCallback((target: ProviderFormState, modelName: string): ProviderFormState => {
    const metadata = openaiCatalog.find(m => m.model === modelName);
    if (!metadata) {
      return { ...target, model: modelName };
    }

    const safeOutputMax = metadata.max_output_tokens ?? null;
    const defaultMaxTokens = safeOutputMax ? Math.min(safeOutputMax, 8192) : target.max_tokens;

    return {
      ...target,
      model: metadata.model,
      name: target.name || metadata.display_name,
      context_window: metadata.context_window ?? target.context_window,
      max_output_tokens: metadata.max_output_tokens ?? target.max_output_tokens ?? null,
      preferred_endpoint: metadata.preferred_endpoint ?? target.preferred_endpoint ?? 'responses',
      input_cost_per_1m: metadata.input_cost_per_1m ?? null,
      cached_input_cost_per_1m: metadata.cached_input_cost_per_1m ?? null,
      output_cost_per_1m: metadata.output_cost_per_1m ?? null,
      docs_url: metadata.docs_url ?? null,
      max_tokens: target.max_tokens || defaultMaxTokens,
    };
  }, [openaiCatalog]);

  useEffect(() => {
    if (showAddForm || editingProvider) {
      requestAnimationFrame(() => {
        editFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
    }
  }, [showAddForm, editingProvider]);

  const toEditableProvider = useCallback((provider: any): ProviderFormState => {
    const providerType = provider.type || 'openai_compatible';
    return {
      id: provider.id || '',
      type: providerType,
      name: provider.name || provider.id || '',
      base_url: provider.base_url || '',
      api_key: provider.api_key || '',
      model: provider.model || '',
      max_tokens: provider.max_tokens ?? 2000,
      temperature: provider.temperature ?? 0.3,
      context_window: provider.context_window ?? 8192,
      max_output_tokens: provider.max_output_tokens ?? null,
      preferred_endpoint:
        provider.preferred_endpoint
        || (providerType === 'anthropic' ? 'anthropic_messages' : 'responses'),
      request_timeout_seconds: provider.request_timeout_seconds ?? null,
      input_cost_per_1m: provider.input_cost_per_1m ?? null,
      cached_input_cost_per_1m: provider.cached_input_cost_per_1m ?? null,
      output_cost_per_1m: provider.output_cost_per_1m ?? null,
      docs_url: provider.docs_url ?? null,
      api_key_set: provider.api_key_set ?? false,
      is_active: provider.is_active ?? false,
    };
  }, []);

  const handleSaveProvider = useCallback(async () => {
    setSaving(true);
    try {
      const providerData: ProviderFormState = (editingProvider || newProvider) as ProviderFormState;
      const isNew = !editingProvider;
      
      // Build payload - exclude api_key if editing and it's hidden/empty (keep existing)
      const payload: Record<string, any> = { ...providerData };
      if (!isNew && (payload.api_key === '***HIDDEN***' || payload.api_key === '')) {
        delete payload.api_key;  // Don't send api_key to keep the existing one
      }
      
      const url = isNew 
        ? '/api/v1/llm/providers/'
        : `/api/v1/llm/providers/${providerData.id}`;
      
      const res = await fetch(url, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to save');
      }
      
      await loadProviders();
      setProviderStatus(prev => ({ ...prev, [providerData.id]: 'unknown' }));
      setProviderDiagnostics(prev => ({ ...prev, [providerData.id]: null }));
      setShowAddForm(false);
      setEditingProvider(null);
      resetNewProvider();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }, [editingProvider, loadProviders, newProvider, resetNewProvider]);

  const handleDeleteProvider = async (id: string) => {
    if (!confirm(`Delete provider "${id}"?`)) return;
    try {
      const res = await fetch(`/api/v1/llm/providers/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to delete');
      }
      await loadProviders();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSetActive = async (id: string) => {
    try {
      const res = await fetch('/api/v1/llm/config/set-active', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: id })
      });
      if (!res.ok) throw new Error('Failed to set active');
      setActiveProvider(id);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleEditProvider = useCallback(async (id: string, seedProvider?: ProviderFormState) => {
    try {
      setError(null);
      if (seedProvider) {
        setShowAddForm(false);
        setEditingProvider(seedProvider);
      }
      const res = await fetch(`/api/v1/llm/providers/${id}`);
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to load provider details');
      }
      let provider = await res.json();
      if (provider.type === 'openai' && provider.model) {
        provider = applyOpenAIModelMetadata(provider as ProviderFormState, provider.model);
      }
      setShowAddForm(false);
      setEditingProvider(toEditableProvider(provider));
    } catch (err: any) {
      setError(err.message || 'Failed to load provider details');
    }
  }, [applyOpenAIModelMetadata, toEditableProvider]);

  useEffect(() => {
    if (!activeTest || testing !== activeTest.id) {
      return;
    }
    setActiveTestElapsedMs(Math.max(0, Date.now() - activeTest.startedAtMs));
    const interval = window.setInterval(() => {
      setActiveTestElapsedMs(Math.max(0, Date.now() - activeTest.startedAtMs));
    }, 200);
    return () => window.clearInterval(interval);
  }, [activeTest, testing]);

  const handleTestProvider = useCallback(async (id: string, showResult = true) => {
    const startedAtMs = Date.now();
    const timeoutSeconds = MODEL_TEST_TIMEOUT_SECONDS;
    const provider = providers.find((p) => p.id === id);
    const providerName = provider?.name || id;
    const providerModel = provider?.model || 'unknown-model';
    setTesting(id);
    setActiveTest({
      id,
      providerName,
      model: providerModel,
      timeoutSeconds,
      startedAtMs,
    });
    setActiveTestElapsedMs(0);
    setProviderStatus(prev => ({ ...prev, [id]: 'testing' }));
    setProviderDiagnostics(prev => ({ ...prev, [id]: null }));
    if (showResult) setTestResult(null);
    
    try {
      const res = await fetch('/api/v1/llm/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: id, timeout_seconds: timeoutSeconds }),
      });
      const result = await res.json();
      if (!res.ok) {
        throw new Error(result.detail || result.error || `Failed to test provider "${id}"`);
      }
      const durationMs = Date.now() - startedAtMs;
      const resolvedProviderName = result.provider || providerName;
      const resolvedModel = result.model || providerModel;
      
      setProviderStatus(prev => ({ ...prev, [id]: result.success ? 'success' : 'error' }));
      setProviderDiagnostics(prev => ({ ...prev, [id]: result.success ? null : (result.diagnostics || null) }));
      setProviderTestSnapshots(prev => ({
        ...prev,
        [id]: {
          tested_at: new Date().toISOString(),
          success: !!result.success,
          duration_ms: durationMs,
          endpoint: result.endpoint,
          total_tokens: result.usage?.total_tokens,
          estimated_cost_usd: result.estimated_cost_usd ?? null,
          error: result.error || result.diagnostics?.summary,
        },
      }));
      if (showResult) {
        setTestResult({
          id,
          provider: resolvedProviderName,
          model: resolvedModel,
          success: !!result.success,
          response: result.response ?? null,
          error: result.error ?? null,
          diagnostics: result.diagnostics ?? null,
          endpoint: result.endpoint ?? null,
          usage: result.usage ?? null,
          estimated_cost_usd: result.estimated_cost_usd ?? null,
          duration_ms: durationMs,
          timeout_seconds: timeoutSeconds,
        });
      }

      return result.success;
    } catch (err: any) {
      const durationMs = Date.now() - startedAtMs;
      setProviderStatus(prev => ({ ...prev, [id]: 'error' }));
      const fallbackDiagnostics: ModelProviderDiagnostics = {
        code: 'test_request_failed',
        summary: `Failed to test ${providerName} (${providerModel}).`,
        suggestions: [
          'Verify backend is running and reachable.',
          'Inspect backend logs for /api/v1/llm/test errors.',
        ],
        raw_error: err.message,
      };
      setProviderDiagnostics(prev => ({ ...prev, [id]: fallbackDiagnostics }));
      setProviderTestSnapshots(prev => ({
        ...prev,
        [id]: {
          tested_at: new Date().toISOString(),
          success: false,
          duration_ms: durationMs,
          error: err.message,
        },
      }));
      if (showResult) {
        setTestResult({
          id,
          provider: providerName,
          model: providerModel,
          success: false,
          error: err.message,
          diagnostics: fallbackDiagnostics,
          duration_ms: durationMs,
          timeout_seconds: timeoutSeconds,
        });
      }
      return false;
    } finally {
      setTesting(null);
      setActiveTest(null);
    }
  }, [providers]);

  const handleTestAllProviders = async () => {
    setTestingAll(true);
    setTestResult(null);
    
    // Reset all statuses to testing
    const initialStatus: Record<string, 'testing'> = {};
    providers.forEach(p => { initialStatus[p.id] = 'testing'; });
    setProviderStatus(initialStatus);
    
    // Test each provider sequentially
    for (const provider of providers) {
      await handleTestProvider(provider.id, false);
    }

    setTestingAll(false);
  };

  const setFormProvider = useCallback((updater: (prev: ProviderFormState) => ProviderFormState) => {
    if (editingProvider) {
      setEditingProvider((prev: ProviderFormState | null) => updater((prev || editingProvider) as ProviderFormState));
    } else {
      setNewProvider(prev => updater(prev));
    }
  }, [editingProvider]);

  const handleProviderTypeChange = useCallback((nextType: string) => {
    setFormProvider(prev => {
      let next: ProviderFormState = { ...prev, type: nextType };

      if (nextType === 'openai') {
        if (!next.base_url || !next.base_url.includes('openai.com')) {
          next.base_url = 'https://api.openai.com/v1';
        }
        if (!next.api_key || next.api_key === 'not-needed' || next.api_key === 'ollama') {
          next.api_key = '${OPENAI_API_KEY}';
        }
        if (!next.preferred_endpoint || next.preferred_endpoint === 'anthropic_messages') {
          next.preferred_endpoint = 'responses';
        }
        if (next.model) {
          next = applyOpenAIModelMetadata(next, next.model);
        }
      } else if (nextType === 'anthropic') {
        next.preferred_endpoint = 'anthropic_messages';
      } else if (nextType === 'openai_compatible') {
        if (!next.preferred_endpoint || next.preferred_endpoint === 'anthropic_messages') {
          next.preferred_endpoint = 'responses';
        }
      }

      return next;
    });
  }, [applyOpenAIModelMetadata, setFormProvider]);

  const handleOpenAIModelChange = useCallback((modelName: string) => {
    setFormProvider(prev => applyOpenAIModelMetadata(prev, modelName));
  }, [applyOpenAIModelMetadata, setFormProvider]);

  const providerTypes = [
    { value: 'openai', label: 'OpenAI API' },
    { value: 'openai_compatible', label: 'OpenAI Compatible (vLLM, Ollama)' },
    { value: 'anthropic', label: 'Anthropic API (Claude, Kimi)' }
  ];

  const formProvider = (editingProvider || newProvider) as ProviderFormState;
  const isOpenAIForm = formProvider.type === 'openai';
  const selectedOpenAIModel = openaiCatalog.find(m => m.model === formProvider.model);
  const endpointCounts = providers.reduce((acc, provider) => {
    const key = provider.preferred_endpoint || 'responses';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const providerHealth = providers.reduce(
    (acc, provider) => {
      const status = providerStatus[provider.id] || 'unknown';
      if (status === 'success') acc.online += 1;
      else if (status === 'error') acc.offline += 1;
      else acc.untested += 1;
      return acc;
    },
    { online: 0, offline: 0, untested: 0 },
  );
  const statusFilterOptions: Array<{ id: ProviderStatusFilter; label: string; count: number }> = [
    { id: 'all', label: 'All', count: providers.length },
    { id: 'online', label: 'Online', count: providerHealth.online },
    { id: 'offline', label: 'Offline', count: providerHealth.offline },
    { id: 'untested', label: 'Untested', count: providerHealth.untested },
  ];
  const filteredProviders = providers.filter(provider => {
    const status = providerStatus[provider.id] || 'unknown';
    if (statusFilter === 'online') return status === 'success';
    if (statusFilter === 'offline') return status === 'error';
    if (statusFilter === 'untested') return status === 'unknown' || status === 'testing';
    return true;
  });

  if (loading) {
    return (
      <div className="glass rounded-2xl p-12 border border-white/5 text-center">
        <RefreshCw className="w-8 h-8 text-slate-400 animate-spin mx-auto mb-4" />
        <p className="text-slate-400">Loading model configuration...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="glass rounded-2xl p-6 border border-white/5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-cyan-500/20 border border-cyan-500/30">
              <Bot className="w-10 h-10 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-2xl font-display font-bold text-white">Model Configuration</h2>
              <p className="text-slate-400">Configure and manage LLM providers for code generation</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleTestAllProviders}
              disabled={testingAll}
              className="px-4 py-2 bg-emerald-500/20 text-emerald-400 rounded-xl hover:bg-emerald-500/30 transition-colors flex items-center gap-2 disabled:opacity-50"
            >
              {testingAll ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Testing...
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Test All
                </>
              )}
            </button>
            <button
              onClick={() => { setEditingProvider(null); resetNewProvider(); setShowAddForm(true); }}
              className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-xl hover:bg-cyan-500/30 transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Add Provider
            </button>
          </div>
        </div>
      </div>

      <div className="glass rounded-xl p-4 border border-white/5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="px-2.5 py-1 rounded-full bg-slate-800 text-slate-300">
              Providers: <span className="font-semibold text-white">{providers.length}</span>
            </span>
            <span className="px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-300">
              Online: <span className="font-semibold">{providerHealth.online}</span>
            </span>
            <span className="px-2.5 py-1 rounded-full bg-red-500/10 text-red-300">
              Offline: <span className="font-semibold">{providerHealth.offline}</span>
            </span>
            <span className="px-2.5 py-1 rounded-full bg-slate-700/60 text-slate-300">
              Untested: <span className="font-semibold">{providerHealth.untested}</span>
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {statusFilterOptions.map(option => (
              <button
                key={option.id}
                onClick={() => setStatusFilter(option.id)}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  statusFilter === option.id
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'bg-slate-800/70 text-slate-300 border border-slate-700 hover:border-slate-500'
                }`}
              >
                {option.label} ({option.count})
              </button>
            ))}
          </div>
        </div>
        <div className="mt-2 text-xs text-slate-500">
          Endpoint preferences: {Object.entries(endpointCounts).map(([endpoint, count]) => `${endpoint} (${count})`).join(', ') || 'none'}
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="glass rounded-xl p-4 border border-red-500/30 bg-red-500/10">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <span className="text-red-300">{error}</span>
            </div>
            <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {activeTest && testing === activeTest.id && (
        <div className="glass rounded-xl p-4 border border-amber-500/30 bg-amber-500/10">
          <div className="flex items-center gap-3">
            <RefreshCw className="w-4 h-4 text-amber-300 animate-spin" />
            <div className="text-sm">
              <div className="text-amber-200 font-medium">
                Testing {activeTest.providerName} ({activeTest.model})
              </div>
              <div className="text-amber-100/80 text-xs mt-1">
                Elapsed: {formatMsSeconds(activeTestElapsedMs)} / timeout {activeTest.timeoutSeconds}s
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add/Edit Form */}
      {(showAddForm || editingProvider) && (
        <div ref={editFormRef} className="glass rounded-2xl p-6 border border-cyan-500/20 bg-cyan-500/5">
          <h3 className="text-lg font-semibold text-white mb-4">
            {editingProvider ? 'Edit Provider' : 'Add New Provider'}
          </h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Provider ID</label>
              <input
                type="text"
                value={formProvider.id}
                onChange={(e) => setFormProvider(prev => ({ ...prev, id: e.target.value }))}
                disabled={!!editingProvider}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white disabled:opacity-50"
                placeholder="my_provider"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Display Name</label>
              <input
                type="text"
                value={formProvider.name}
                onChange={(e) => setFormProvider(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="My Custom Model"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Provider Type</label>
              <select
                value={formProvider.type}
                onChange={(e) => handleProviderTypeChange(e.target.value)}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              >
                {providerTypes.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Model Name</label>
              {isOpenAIForm ? (
                <div className="space-y-2">
                  <select
                    value={formProvider.model}
                    onChange={(e) => handleOpenAIModelChange(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  >
                    {openaiCatalogLoading && <option value={formProvider.model}>Loading catalog...</option>}
                    {!openaiCatalogLoading && openaiCatalog.length === 0 && (
                      <option value={formProvider.model}>Catalog unavailable</option>
                    )}
                    {!openaiCatalogLoading && openaiCatalog.map((m) => (
                      <option key={m.model} value={m.model}>
                        {m.display_name} ({m.model})
                      </option>
                    ))}
                  </select>
                  <input
                    type="text"
                    value={formProvider.model}
                    onChange={(e) => setFormProvider(prev => ({ ...prev, model: e.target.value }))}
                    className="w-full px-3 py-2 bg-slate-800/30 border border-slate-700 rounded-lg text-white font-mono text-sm"
                    placeholder="Or enter custom model id"
                  />
                  {selectedOpenAIModel?.docs_url && (
                    <a
                      href={selectedOpenAIModel.docs_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      View model metadata
                    </a>
                  )}
                </div>
              ) : (
                <input
                  type="text"
                  value={formProvider.model}
                  onChange={(e) => setFormProvider(prev => ({ ...prev, model: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                  placeholder="gpt-4"
                />
              )}
            </div>
            <div className="col-span-2">
              <label className="block text-sm text-slate-400 mb-1">Base URL</label>
              <input
                type="text"
                value={formProvider.base_url}
                onChange={(e) => setFormProvider(prev => ({ ...prev, base_url: e.target.value }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white font-mono text-sm"
                placeholder="https://api.openai.com/v1"
              />
            </div>
            <div className="col-span-2">
              <label className="block text-sm text-slate-400 mb-1">
                API Key 
                <span className="text-xs text-slate-500 ml-2">
                  (use {"${ENV_VAR}"} to reference environment variables)
                </span>
              </label>
              <div className="relative">
                <input
                  type="text"
                  value={formProvider.api_key === '***HIDDEN***' 
                    ? '' 
                    : formProvider.api_key}
                  onChange={(e) => setFormProvider(prev => ({ ...prev, api_key: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white font-mono text-sm"
                  placeholder={editingProvider?.api_key === '***HIDDEN***' 
                    ? "Enter new API key to change (current key is hidden)" 
                    : "${OPENAI_API_KEY}"}
                />
                {editingProvider?.api_key_set && editingProvider?.api_key === '***HIDDEN***' && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
                    <div className="w-2 h-2 bg-emerald-500 rounded-full" />
                    <span className="text-xs text-emerald-400">Key set</span>
                  </div>
                )}
              </div>
              {editingProvider && editingProvider.api_key === '***HIDDEN***' && (
                <p className="text-xs text-amber-400 mt-1">
                  Leave blank to keep existing key, or enter a new value to change it
                </p>
              )}
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Max Tokens</label>
              <input
                type="number"
                value={formProvider.max_tokens}
                onChange={(e) => {
                  const nextValue = parseInt(e.target.value, 10);
                  setFormProvider(prev => ({
                    ...prev,
                    max_tokens: Number.isFinite(nextValue) ? nextValue : prev.max_tokens,
                  }));
                }}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Temperature</label>
              <input
                type="number"
                step="0.1"
                value={formProvider.temperature}
                onChange={(e) => {
                  const nextValue = parseFloat(e.target.value);
                  setFormProvider(prev => ({
                    ...prev,
                    temperature: Number.isFinite(nextValue) ? nextValue : prev.temperature,
                  }));
                }}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Context Window</label>
              <input
                type="number"
                value={formProvider.context_window}
                onChange={(e) => {
                  const nextValue = parseInt(e.target.value, 10);
                  setFormProvider(prev => ({
                    ...prev,
                    context_window: Number.isFinite(nextValue) ? nextValue : prev.context_window,
                  }));
                }}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Max Output Tokens</label>
              <input
                type="number"
                value={formProvider.max_output_tokens ?? ''}
                onChange={(e) => setFormProvider(prev => ({ ...prev, max_output_tokens: e.target.value ? parseInt(e.target.value) : null }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="Model capability"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Endpoint Preference</label>
              <select
                value={formProvider.preferred_endpoint || 'responses'}
                onChange={(e) => setFormProvider(prev => ({ ...prev, preferred_endpoint: e.target.value }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                disabled={formProvider.type === 'anthropic'}
              >
                <option value="responses">Responses (modern)</option>
                <option value="chat_completions">Chat Completions</option>
                <option value="completions_legacy">Legacy Completions</option>
                {formProvider.type === 'anthropic' && <option value="anthropic_messages">Anthropic Messages</option>}
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Request Timeout (seconds)</label>
              <input
                type="number"
                min={1}
                max={300}
                step="1"
                value={formProvider.request_timeout_seconds ?? ''}
                onChange={(e) => setFormProvider(prev => ({
                  ...prev,
                  request_timeout_seconds: e.target.value ? Number(e.target.value) : null,
                }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="default (35s)"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Input Cost ($ / 1M tokens)</label>
              <input
                type="number"
                step="0.0001"
                value={formProvider.input_cost_per_1m ?? ''}
                onChange={(e) => setFormProvider(prev => ({ ...prev, input_cost_per_1m: e.target.value ? parseFloat(e.target.value) : null }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Output Cost ($ / 1M tokens)</label>
              <input
                type="number"
                step="0.0001"
                value={formProvider.output_cost_per_1m ?? ''}
                onChange={(e) => setFormProvider(prev => ({ ...prev, output_cost_per_1m: e.target.value ? parseFloat(e.target.value) : null }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Cached Input Cost ($ / 1M tokens)</label>
              <input
                type="number"
                step="0.0001"
                value={formProvider.cached_input_cost_per_1m ?? ''}
                onChange={(e) => setFormProvider(prev => ({ ...prev, cached_input_cost_per_1m: e.target.value ? parseFloat(e.target.value) : null }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
          </div>
          <div className="flex gap-3 mt-6">
            <button
              onClick={handleSaveProvider}
              disabled={saving}
              className="px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg hover:bg-cyan-500/30 transition-colors disabled:opacity-50"
            >
              {saving ? 'Saving...' : 'Save Provider'}
            </button>
            <button
              onClick={() => { setShowAddForm(false); setEditingProvider(null); resetNewProvider(); }}
              className="px-4 py-2 bg-slate-700 text-slate-300 rounded-lg hover:bg-slate-600 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Test Result */}
      {testResult && (
        <div className={`glass rounded-xl p-4 border ${
          testResult.success ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-red-500/30 bg-red-500/10'
        }`}>
          <div className="flex items-center gap-3">
            {testResult.success ? (
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            ) : (
              <XCircle className="w-5 h-5 text-red-400" />
            )}
            <div>
              <span className={testResult.success ? 'text-emerald-300' : 'text-red-300'}>
                {testResult.success ? 'Connection successful' : 'Connection failed'}: {testResult.provider} ({testResult.model})
              </span>
              <p className="text-xs text-slate-400 mt-1">
                Latency: {formatMsSeconds(testResult.duration_ms)} (timeout {testResult.timeout_seconds}s)
              </p>
              {testResult.response && (
                <p className="text-sm text-slate-400 mt-1">Response: {testResult.response}</p>
              )}
              {testResult.endpoint && (
                <p className="text-xs text-slate-400 mt-1">Endpoint: {testResult.endpoint}</p>
              )}
              {testResult.usage?.total_tokens != null && (
                <p className="text-xs text-slate-400 mt-1">
                  Usage: {testResult.usage.total_tokens.toLocaleString()} tokens
                </p>
              )}
              {testResult.estimated_cost_usd != null && (
                <p className="text-xs text-cyan-300 mt-1">
                  Estimated cost: ${Number(testResult.estimated_cost_usd).toFixed(8)}
                </p>
              )}
              {testResult.error && (
                <p className="text-sm text-red-400 mt-1">{testResult.error}</p>
              )}
              {!testResult.success && testResult.diagnostics?.summary && (
                <p className="text-sm text-amber-300 mt-1">{testResult.diagnostics.summary}</p>
              )}
              {!testResult.success && testResult.diagnostics?.checks?.length ? (
                <div className="mt-2 text-xs text-slate-300">
                  {testResult.diagnostics.checks.slice(0, 3).map((check: string, idx: number) => (
                    <p key={idx}>• {check}</p>
                  ))}
                </div>
              ) : null}
              {!testResult.success && (testResult.diagnostics?.suggestions?.length ?? 0) > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  {(testResult.diagnostics?.suggestions ?? []).slice(0, 2).map((suggestion: string, idx: number) => (
                    <p key={idx}>• {suggestion}</p>
                  ))}
                </div>
              )}
              {!testResult.success && testResult.diagnostics?.raw_error && (
                <p className="text-[11px] text-slate-500 mt-2 font-mono break-all">
                  raw: {testResult.diagnostics.raw_error}
                </p>
              )}
            </div>
            <button 
              onClick={() => setTestResult(null)}
              className="ml-auto text-slate-400 hover:text-white"
            >
              <XCircle className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Providers List */}
      <div className="space-y-4">
        {filteredProviders.length === 0 && (
          <div className="glass rounded-xl p-6 border border-white/5 text-center text-slate-400 text-sm">
            No providers match the selected filter.
          </div>
        )}
        {filteredProviders.map(provider => (
          <div
            key={provider.id}
            className={`glass rounded-2xl p-6 border transition-all ${
              provider.id === activeProvider 
                ? 'border-cyan-500/30 bg-cyan-500/5' 
                : 'border-white/5 hover:border-white/10'
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-start gap-4">
                <div className={`relative p-3 rounded-xl ${
                  provider.id === activeProvider 
                    ? 'bg-cyan-500/20' 
                    : 'bg-slate-800/50'
                }`}>
                  <Bot className={`w-6 h-6 ${
                    provider.id === activeProvider ? 'text-cyan-400' : 'text-slate-400'
                  }`} />
                  {/* Status indicator */}
                  {providerStatus[provider.id] && (
                    <div className={`absolute -top-1 -right-1 w-4 h-4 rounded-full border-2 border-slate-900 flex items-center justify-center ${
                      providerStatus[provider.id] === 'testing' ? 'bg-amber-500' :
                      providerStatus[provider.id] === 'success' ? 'bg-emerald-500' :
                      providerStatus[provider.id] === 'error' ? 'bg-red-500' :
                      'bg-slate-500'
                    }`}>
                      {providerStatus[provider.id] === 'testing' && (
                        <RefreshCw className="w-2.5 h-2.5 text-white animate-spin" />
                      )}
                      {providerStatus[provider.id] === 'success' && (
                        <Check className="w-2.5 h-2.5 text-white" />
                      )}
                      {providerStatus[provider.id] === 'error' && (
                        <XCircle className="w-2.5 h-2.5 text-white" />
                      )}
                    </div>
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-lg font-semibold text-white">{provider.name}</h3>
                    {provider.id === activeProvider && (
                      <span className="px-2 py-0.5 text-xs bg-cyan-500/20 text-cyan-400 rounded-full">
                        Active
                      </span>
                    )}
                    {providerStatus[provider.id] === 'success' && (
                      <span className="px-2 py-0.5 text-xs bg-emerald-500/20 text-emerald-400 rounded-full">
                        Online
                      </span>
                    )}
                    {providerStatus[provider.id] === 'error' && (
                      <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded-full">
                        Offline
                      </span>
                    )}
                    {providerStatus[provider.id] === 'testing' && activeTest?.id === provider.id && (
                      <span className="px-2 py-0.5 text-xs bg-amber-500/20 text-amber-300 rounded-full">
                        Testing {formatMsSeconds(activeTestElapsedMs)}
                      </span>
                    )}
                    {editingProvider?.id === provider.id && (
                      <span className="px-2 py-0.5 text-xs bg-violet-500/20 text-violet-300 rounded-full">
                        Editing
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-slate-400 font-mono mt-1">{provider.id}</p>
                  <div className="flex items-center gap-4 mt-3 text-sm">
                    <span className="text-slate-400">
                      <span className="text-slate-500">Type:</span>{' '}
                      <span className="text-slate-300">{provider.type}</span>
                    </span>
                    <span className="text-slate-400">
                      <span className="text-slate-500">Model:</span>{' '}
                      <span className="text-slate-300 font-mono">{provider.model}</span>
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-2 text-sm text-slate-500">
                    <span>Max tokens: {provider.max_tokens}</span>
                    <span>Temp: {provider.temperature}</span>
                    <span>Context: {provider.context_window?.toLocaleString()}</span>
                    <span>Timeout: {provider.request_timeout_seconds ? `${provider.request_timeout_seconds}s` : 'default'}</span>
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-slate-500">
                    {provider.max_output_tokens && <span>Max output: {provider.max_output_tokens?.toLocaleString()}</span>}
                    {provider.preferred_endpoint && (
                      <span className={`px-1.5 py-0.5 rounded ${
                        provider.preferred_endpoint === 'responses'
                          ? 'bg-cyan-500/15 text-cyan-300'
                          : provider.preferred_endpoint === 'chat_completions'
                            ? 'bg-amber-500/15 text-amber-300'
                            : 'bg-slate-700/70 text-slate-300'
                      }`}>
                        Endpoint: {provider.preferred_endpoint}
                      </span>
                    )}
                    {(provider.input_cost_per_1m || provider.output_cost_per_1m) && (
                      <span>
                        Cost/1M in/out: ${provider.input_cost_per_1m ?? 'n/a'} / ${provider.output_cost_per_1m ?? 'n/a'}
                      </span>
                    )}
                  </div>
                  {providerTestSnapshots[provider.id] ? (
                    <div className="mt-2 text-xs text-slate-400 flex flex-wrap items-center gap-3">
                      <span>
                        Last test: {new Date(providerTestSnapshots[provider.id].tested_at).toLocaleString()}
                      </span>
                      <span>
                        Latency: {(providerTestSnapshots[provider.id].duration_ms / 1000).toFixed(2)}s
                      </span>
                      {providerTestSnapshots[provider.id].endpoint && (
                        <span>Used: {providerTestSnapshots[provider.id].endpoint}</span>
                      )}
                      {providerTestSnapshots[provider.id].total_tokens != null && (
                        <span>Tokens: {providerTestSnapshots[provider.id].total_tokens?.toLocaleString()}</span>
                      )}
                      {providerTestSnapshots[provider.id].estimated_cost_usd != null && (
                        <span className="text-cyan-300">
                          Cost: ${Number(providerTestSnapshots[provider.id].estimated_cost_usd).toFixed(8)}
                        </span>
                      )}
                    </div>
                  ) : (
                    <div className="mt-2 text-xs text-slate-500">
                      Last test: not yet run
                    </div>
                  )}
                  {provider.docs_url && (
                    <a
                      href={provider.docs_url}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex mt-2 text-xs text-cyan-300 hover:text-cyan-200 underline"
                    >
                      Model documentation
                    </a>
                  )}
                  <div className="mt-2 text-xs text-slate-500 font-mono truncate max-w-md">
                    {provider.base_url}
                  </div>
                  {providerStatus[provider.id] === 'error' && providerDiagnostics[provider.id] && (
                    <div className="mt-3 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 max-w-2xl">
                      <p className="text-xs text-red-300">
                        {providerDiagnostics[provider.id]?.summary || 'Provider appears offline.'}
                      </p>
                      {providerDiagnostics[provider.id]?.code && (
                        <p className="text-[11px] text-slate-400 mt-1 font-mono">
                          code: {providerDiagnostics[provider.id]?.code}
                        </p>
                      )}
                      {providerDiagnostics[provider.id]?.suggestions?.length ? (
                        <div className="mt-1 text-[11px] text-slate-300">
                          {providerDiagnostics[provider.id]?.suggestions?.slice(0, 2).map((suggestion, idx) => (
                            <p key={idx}>• {suggestion}</p>
                          ))}
                        </div>
                      ) : null}
                      {providerDiagnostics[provider.id]?.checks?.length ? (
                        <div className="mt-1 text-[11px] text-slate-400">
                          {providerDiagnostics[provider.id]?.checks?.slice(0, 3).map((check, idx) => (
                            <p key={idx}>• {check}</p>
                          ))}
                        </div>
                      ) : null}
                      {providerDiagnostics[provider.id]?.raw_error ? (
                        <p className="text-[11px] text-slate-500 mt-1 font-mono break-all">
                          raw: {providerDiagnostics[provider.id]?.raw_error}
                        </p>
                      ) : null}
                    </div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {provider.id !== activeProvider && (
                  <button
                    onClick={() => handleSetActive(provider.id)}
                    className="px-3 py-1.5 text-sm bg-cyan-500/10 text-cyan-400 rounded-lg hover:bg-cyan-500/20 transition-colors"
                  >
                    Set Active
                  </button>
                )}
                <button
                  onClick={() => handleTestProvider(provider.id)}
                  disabled={testing === provider.id || testingAll}
                  className="px-3 py-1.5 text-sm bg-emerald-500/10 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                >
                  {testing === provider.id ? `Testing ${formatMsSeconds(activeTestElapsedMs)}` : 'Test'}
                </button>
                <button
                  onClick={() => {
                    const seeded = toEditableProvider(provider);
                    void handleEditProvider(provider.id, seeded);
                  }}
                  className="px-3 py-1.5 text-sm bg-violet-500/10 text-violet-300 rounded-lg hover:bg-violet-500/20 transition-colors flex items-center gap-1.5"
                >
                  <Edit2 className="w-4 h-4" />
                  Edit
                </button>
                {provider.id !== activeProvider && (
                  <button
                    onClick={() => handleDeleteProvider(provider.id)}
                    className="px-3 py-1.5 text-sm bg-red-500/10 text-red-300 rounded-lg hover:bg-red-500/20 transition-colors flex items-center gap-1.5"
                  >
                    <Trash2 className="w-4 h-4" />
                    Delete
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Help Text */}
      <div className="glass rounded-xl p-4 border border-white/5">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-slate-400 mt-0.5" />
          <div className="text-sm text-slate-400">
            <p className="mb-2">
              <strong className="text-slate-300">Security Tip:</strong> Use environment variable references 
              (e.g., <code className="text-cyan-400">{"${OPENAI_API_KEY}"}</code>) instead of hardcoding API keys.
            </p>
            <p>
              Configuration is saved to <code className="text-cyan-400">llm_config.yaml</code>. 
              Set environment variables in your <code className="text-cyan-400">.env</code> file.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Policy Panel (Collapsed)
function PolicyPanel({ policies }: { policies: PolicyRule[] }) {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <div className="glass rounded-2xl overflow-hidden border border-white/5">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-violet-500/10">
            <FileCheck className="w-5 h-5 text-violet-400" />
          </div>
          <span className="font-semibold text-slate-200">Policy Reference</span>
          <span className="px-2.5 py-0.5 text-xs font-medium bg-slate-800/80 text-slate-400 rounded-full">
            {policies.length} rules
          </span>
        </div>
        {isOpen ? (
          <ChevronDown className="w-5 h-5 text-slate-400" />
        ) : (
          <ChevronRight className="w-5 h-5 text-slate-400" />
        )}
      </button>
      {isOpen && (
        <div className="border-t border-white/5 max-h-[200px] overflow-y-auto animate-fade-in">
          {policies.map((policy, index) => (
            <div
              key={index}
              className="px-5 py-3 border-b border-white/5 last:border-b-0 hover:bg-white/[0.02]"
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm font-semibold text-violet-400">{policy.id}</span>
                <span className={`px-1.5 py-0.5 text-[10px] uppercase font-semibold tracking-wider rounded ${
                  policy.type === 'strict'
                    ? 'bg-red-500/10 text-red-400'
                    : 'bg-amber-500/10 text-amber-400'
                }`}>
                  {policy.type}
                </span>
              </div>
              <p className="text-sm text-slate-500">{policy.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
