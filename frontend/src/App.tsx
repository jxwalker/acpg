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
  SemanticsMode, ManagedTestCase
} from './types';
import { MODEL_TEST_TIMEOUT_SECONDS, formatMsSeconds, humanizeStopReason } from './utils/formatting';
import { buildEnforceFailureExplanation } from './utils/remediation';
import { safeArray, safeObject } from './utils/safe-helpers';
import FormalProofView from './views/FormalProofView';
import ToolRulesBrowser from './views/ToolRulesBrowser';
import ToolMappingsView from './views/ToolMappingsView';
import ProofVerifier from './views/ProofVerifier';
import DemoLabView from './views/DemoLabView';
import PoliciesView from './views/PoliciesView';
import ModelsConfigurationView from './views/ModelsConfigurationView';

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

type WorkflowStep = 'idle' | 'prosecutor' | 'adjudicator' | 'generator' | 'proof' | 'complete';
type ViewMode = 'editor' | 'diff' | 'proof' | 'policies' | 'verify' | 'tools' | 'metrics' | 'models';
type CodeViewMode = 'current' | 'original' | 'fixed' | 'diff';

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
        <>
        <div className="fixed inset-0 z-30" onClick={() => setShowHistory(false)} />
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
              <div className="text-xs text-slate-500">No analysis history in this time window. Run code analysis to generate compliance trend data, or widen the date range.</div>
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
        </>
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
                      {/* Progress bar */}
                      <div className="mt-3 h-1.5 bg-slate-700/50 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${
                          analysisProgress.phase === 'generating'
                            ? 'bg-gradient-to-r from-violet-500 via-cyan-400 to-violet-500 animate-progress-indeterminate'
                            : 'bg-gradient-to-r from-violet-500 to-cyan-500 animate-progress-indeterminate'
                        }`} />
                      </div>
                      {/* Phase steps */}
                      <div className="mt-2 flex gap-1.5">
                        {['starting', 'tools', 'adjudicating', 'generating'].map((phase) => {
                          const phases = ['starting', 'tools', 'adjudicating', 'generating'];
                          const currentIdx = phases.indexOf(analysisProgress!.phase);
                          const phaseIdx = phases.indexOf(phase);
                          const labels: Record<string, string> = {
                            starting: 'Init', tools: 'Tools', adjudicating: 'Adjudicate', generating: 'Fix'
                          };
                          return (
                            <div key={phase} className={`text-[10px] px-1.5 py-0.5 rounded ${
                              phaseIdx < currentIdx ? 'bg-emerald-500/20 text-emerald-400'
                                : phaseIdx === currentIdx ? 'bg-violet-500/20 text-violet-300'
                                : 'bg-slate-800/50 text-slate-600'
                            }`}>
                              {labels[phase]}
                            </div>
                          );
                        })}
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

              {/* Structured violation cards */}
              {enforceFailure.targetedFixes && enforceFailure.targetedFixes.length > 0 && (
                <div className="mt-3 space-y-2">
                  <p className="text-[11px] uppercase tracking-wide text-cyan-300/80 mb-1">Targeted fixes</p>
                  {enforceFailure.targetedFixes.map((fix) => (
                    <div key={fix.ruleId} className="rounded-lg border border-white/10 bg-slate-800/60 overflow-hidden">
                      {/* Card header: rule ID, count, severity */}
                      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-white/5 bg-slate-700/40">
                        <span className="text-xs font-mono font-semibold text-cyan-300">{fix.ruleId}</span>
                        {fix.lines.length > 1 && (
                          <span className="text-[10px] text-slate-400">&times;{fix.lines.length}</span>
                        )}
                        <span className={`ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                          fix.severity === 'critical' ? 'bg-red-500/30 text-red-300' :
                          fix.severity === 'high' ? 'bg-orange-500/30 text-orange-300' :
                          fix.severity === 'medium' ? 'bg-amber-500/30 text-amber-300' :
                          'bg-slate-500/30 text-slate-300'
                        }`}>
                          {fix.severity}
                        </span>
                      </div>
                      {/* Card body */}
                      <div className="px-3 py-2 space-y-1.5">
                        {fix.description && (
                          <p className="text-xs text-slate-300">{fix.description}</p>
                        )}
                        {fix.evidence && (
                          <div className="font-mono text-[11px] text-amber-200/90 bg-slate-900/80 rounded px-2 py-1.5 flex items-baseline gap-2 overflow-x-auto">
                            <span className="whitespace-pre">{fix.evidence}</span>
                            {fix.lines.length > 0 && (
                              <span className="text-slate-500 text-[10px] whitespace-nowrap ml-auto">
                                line{fix.lines.length > 1 ? 's' : ''} {fix.lines.slice(0, 4).join(', ')}
                              </span>
                            )}
                          </div>
                        )}
                        {!fix.evidence && fix.lines.length > 0 && (
                          <p className="text-[10px] text-slate-500 font-mono">
                            line{fix.lines.length > 1 ? 's' : ''} {fix.lines.slice(0, 4).join(', ')}
                          </p>
                        )}
                        <p className="text-xs text-cyan-200">
                          <span className="text-cyan-400 font-semibold">Fix: </span>{fix.hint}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Fallback to flat targeted actions if no structured fixes */}
              {(!enforceFailure.targetedFixes || enforceFailure.targetedFixes.length === 0) &&
                enforceFailure.targetedActions && enforceFailure.targetedActions.length > 0 && (
                <div className="mt-2 text-xs text-cyan-200">
                  <p className="text-[11px] uppercase tracking-wide text-cyan-300/80 mb-1">Targeted next fixes</p>
                  {enforceFailure.targetedActions.map((action, idx) => (
                    <p key={idx}>• {action}</p>
                  ))}
                </div>
              )}

              {enforceFailure.actions.length > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  <p className="text-[11px] uppercase tracking-wide text-slate-400/80 mb-1">Next steps</p>
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
    { value: 'markdown', label: 'Markdown', icon: 'md' },
    { value: 'html', label: 'HTML', icon: 'html' },
    { value: 'summary', label: 'Summary', icon: 'txt' },
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
              {policies.map((p: any, i: number) => (
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
