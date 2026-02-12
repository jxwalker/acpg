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
  }
  const [history, setHistory] = useState<HistoryEntry[]>([]);
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
    setLlmProviderStatus(prev => ({ ...prev, [id]: 'testing' }));
    try {
      // Switch to provider
      await fetch('/api/v1/llm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: id })
      });
      // Test it
      const res = await fetch('/api/v1/llm/test', { method: 'POST' });
      const result = await res.json();
      const success = result.success;
      setLlmProviderStatus(prev => ({ ...prev, [id]: success ? 'success' : 'error' }));
      if (showToast) {
        const provider = llmProviders.find(p => p.id === id);
        const name = provider?.name || id;
        addToast(
          success ? `${name} is online and working` : `${name} connection failed`,
          success ? 'success' : 'error'
        );
      }
      return success;
    } catch {
      setLlmProviderStatus(prev => ({ ...prev, [id]: 'error' }));
      if (showToast) {
        const provider = llmProviders.find(p => p.id === id);
        const name = provider?.name || id;
        addToast(`${name} connection failed`, 'error');
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
      .then(async (data) => {
        const providers = data || [];
        setLlmProviders(providers);
        // Auto-test the active provider
        const activeProvider = providers.find((p: any) => p.is_active);
        if (activeProvider) {
          await testLlmProvider(activeProvider.id);
        }
      })
      .catch(() => setLlmProviders([]));
  }, []);

  // Test all LLM providers
  const testAllLlmProviders = async () => {
    if (llmProviders.length === 0) return;
    setTestingAllLlm(true);
    const originalActive = llmProviders.find(p => p.is_active)?.id;
    
    let successCount = 0;
    for (const provider of llmProviders) {
      const success = await testLlmProvider(provider.id);
      if (success) successCount++;
    }
    
    // Switch back to original
    if (originalActive) {
      await fetch('/api/v1/llm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: originalActive })
      });
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
      const response = await fetch('/api/v1/test-cases');
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
  }, []);

  useEffect(() => {
    void loadTestCases();
    
    // Load analysis history
    fetch('/api/v1/history?limit=20')
      .then(res => res.json())
      .then(data => setHistory(data.history || []))
      .catch(() => {});
    
    // Load enabled policy groups count
    fetch('/api/v1/policies/groups/')
      .then(res => res.json())
      .then(data => setEnabledGroupsCount({
        groups: data.enabled_groups || 0,
        policies: data.enabled_policies || 0
      }))
      .catch(() => {});
  }, [loadTestCases]);

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

  const [analysisProgress, setAnalysisProgress] = useState<{
    phase: string;
    tool?: string;
    message?: string;
  } | null>(null);

  // Refresh history after analysis
  const refreshHistory = useCallback(() => {
    fetch('/api/v1/history?limit=20')
      .then(res => res.json())
      .then(data => setHistory(data.history || []))
      .catch(() => {});
  }, []);

  const handleAnalyze = useCallback(async () => {
    setError(null);
    setEnforceResult(null);
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
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language, semantics, addToast]);

  const handleEnforce = useCallback(async () => {
    setError(null);
    setOriginalCode(code); // Save original for diff
    setAnalysisProgress({ phase: 'starting', message: 'Starting enforcement...' });
    addToast('Starting auto-fix...', 'info', 2000);
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
      setAnalysisProgress({ phase: 'generating', message: 'Generating fixes...' });
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
      addToast('Auto-fix completed successfully', 'success');
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Enforcement failed';
      setError(errorMsg);
      addToast(errorMsg, 'error');
      setAnalysisProgress(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language, semantics, addToast]);

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
      await loadTestCases();
      addToast(`Saved test case "${name.trim()}"`, 'success');
    } catch (err) {
      addToast('Failed to create test case', 'error');
    }
  }, [code, language, loadTestCases, addToast]);

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
      await loadTestCases();
      addToast(`Updated test case "${name.trim()}"`, 'success');
    } catch (err) {
      addToast('Failed to update test case', 'error');
    }
  }, [code, language, loadTestCases, addToast]);

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
      await loadTestCases();
      addToast(`Deleted "${testCase.name}"`, 'success');
    } catch (err) {
      addToast('Failed to delete test case', 'error');
    }
  }, [loadTestCases, addToast]);

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
                      .then(() => setHistory([]))
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
                        {analysisProgress.phase === 'generating' && 'Generating Fixes'}
                      </div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        {analysisProgress.message}
                        {analysisProgress.tool && ` (${analysisProgress.tool})`}
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
}: { 
  adjudication: AdjudicationResult | null;
  violations: Violation[];
  enforceResult: EnforceResponse | null;
  isAnalyzing: boolean;
  analysis: AnalysisResult | null;
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
                  Stop reason: {enforceResult.performance.stopped_early_reason}
                </span>
              )}
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
            <div className="font-mono text-sm text-slate-300 truncate">{proof.artifact.hash.slice(0, 16)}...</div>
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
                <span className="font-mono text-sm text-slate-200">{proof.artifact.hash.slice(0, 24)}...</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Language</span>
                <span className="text-slate-200">{proof.artifact.language}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Generator</span>
                <span className="text-slate-200">{proof.artifact.generator}</span>
              </div>
              <div className="flex justify-between py-2">
                <span className="text-slate-400">Timestamp</span>
                <span className="text-slate-200">{new Date(proof.artifact.timestamp).toLocaleString()}</span>
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
                <span className="text-slate-200">{proof.signed.algorithm}</span>
              </div>
              <div className="flex justify-between py-2 border-b border-white/5">
                <span className="text-slate-400">Signer</span>
                <span className="text-slate-200">{proof.signed.signer}</span>
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
              Verified Policies ({proof.policies.length})
            </h3>
            <div className="grid grid-cols-4 gap-3">
              {proof.policies.map((p, i) => (
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
  const args = proof.argumentation?.arguments || [];
  
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
                    <div className="text-xs text-slate-500 mt-1 max-w-32 truncate" title={violation.evidence}>
                      {violation.evidence}
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
  
  const toggleStep = (step: number) => {
    setExpandedSteps(prev => ({ ...prev, [step]: !prev[step] }));
  };
  
  // Extract reasoning steps from the proof
  const reasoningSteps = proof.argumentation?.reasoning_trace?.filter(
    (item: any) => item.step !== undefined
  ) || [];
  
  // Extract legacy format data
  const proofArguments = proof.argumentation?.arguments || [];
  const proofAttacks = proof.argumentation?.attacks || [];
  const groundedExtension = proof.argumentation?.grounded_extension;
  const summary = proof.argumentation?.summary;
  
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
            <div className="text-white font-semibold">{summary?.total_arguments || proofArguments.length}</div>
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
      
      {/* Plain English Explanation */}
      {proof.argumentation?.explanation && (
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
            <p className="text-slate-200">{proof.argumentation.explanation.summary}</p>
          </div>
          
          {/* What happened for each violation */}
          {proof.argumentation.explanation.what_happened?.length > 0 && (
            <div className="space-y-3 mb-4">
              <h4 className="text-sm font-semibold text-slate-300">Policy Violations Explained:</h4>
              {proof.argumentation.explanation.what_happened.map((item: any, i: number) => (
                <div key={i} className="p-4 bg-red-500/5 rounded-xl border border-red-500/20">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded">
                      {item.policy}
                    </span>
                    <span className="text-red-400 font-semibold">{item.result}</span>
                  </div>
                  <p className="text-sm text-slate-300 mb-2">{item.explanation}</p>
                  {item.evidence && (
                    <div className="text-xs text-slate-400 font-mono bg-slate-900/50 px-3 py-2 rounded">
                      Evidence: {item.evidence}
                    </div>
                  )}
                </div>
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
              {Object.entries(proof.argumentation.explanation.terminology || {}).map(([term, def]: [string, any]) => (
                <div key={term} className="p-2 bg-slate-800/50 rounded-lg">
                  <span className="font-mono text-cyan-400 text-sm">{term}</span>
                  <p className="text-xs text-slate-400 mt-1">{def}</p>
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
                  <h3 className="text-lg font-semibold text-white">{step.title}</h3>
                  <p className="text-sm text-slate-400">{step.description}</p>
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
                        {step.logic.map((rule: string, i: number) => (
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
                        {step.algorithm.map((line: string, i: number) => (
                          <div key={i} className="text-slate-300">{line}</div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Arguments by type */}
                  {step.arguments && (
                    <div className="mt-4 grid grid-cols-2 gap-4">
                      {step.arguments.compliance?.length > 0 && (
                        <div className="p-4 bg-emerald-500/5 rounded-xl border border-emerald-500/20">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Compliance Arguments ({step.arguments.compliance.length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {step.arguments.compliance.map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-emerald-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-emerald-400' : 'text-slate-500'
                                }`}>{arg.id}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-emerald-300' : 'text-slate-500'
                                }`}>({arg.status})</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {step.arguments.violation?.length > 0 && (
                        <div className="p-4 bg-red-500/5 rounded-xl border border-red-500/20">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violation Arguments ({step.arguments.violation.length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {step.arguments.violation.map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-red-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-red-400' : 'text-slate-500'
                                }`}>{arg.id}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-red-300' : 'text-slate-500'
                                }`}>({arg.status})</span>
                                {arg.evidence && (
                                  <div className="mt-1 text-slate-400 truncate">Evidence: {arg.evidence}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Attacks */}
                  {step.attacks && step.attacks.length > 0 && (
                    <div className="mt-4 p-4 bg-orange-500/5 rounded-xl border border-orange-500/20">
                      <div className="text-xs text-orange-400 uppercase tracking-wider mb-2">
                        Attack Relations ({step.attacks.length})
                      </div>
                      <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                        {step.attacks.map((attack: any, i: number) => (
                          <div key={i} className={`p-2 rounded-lg text-xs flex items-center gap-2 ${
                            attack.effective ? 'bg-orange-500/10' : 'bg-slate-800/50'
                          }`}>
                            <span className="font-mono text-slate-300">{attack.attacker}</span>
                            <span className={attack.effective ? 'text-orange-400' : 'text-slate-500'}>→</span>
                            <span className="font-mono text-slate-300">{attack.target}</span>
                            <span className={`ml-auto ${attack.effective ? 'text-orange-400' : 'text-slate-500'}`}>
                              {attack.effective ? '✓' : '✗'}
                            </span>
                          </div>
                        ))}
                      </div>
                      {step.attacks.some((a: any) => a.reason) && (
                        <div className="mt-3 pt-3 border-t border-orange-500/20">
                          {step.attacks.filter((a: any) => a.reason).slice(0, 3).map((attack: any, i: number) => (
                            <div key={i} className="text-xs text-slate-400 mb-1">
                              <span className="text-orange-400">{attack.attacker} → {attack.target}:</span> {attack.reason}
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
                          {step.result.accepted.map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                              {id}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                        <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                          Rejected ({step.result.rejected_count})
                        </div>
                        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                          {step.result.rejected.map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                              {id}
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
                          {step.decision}
                        </div>
                      </div>
                      <p className="text-sm text-slate-300">{step.reasoning}</p>
                      
                      {step.satisfied_policies?.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Satisfied Policies ({step.satisfied_policies.length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {step.satisfied_policies.map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                                {id}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      
                      {step.violated_policies?.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violated Policies ({step.violated_policies.length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {step.violated_policies.map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded">
                                {id}
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
                        {arg.id}
                      </span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        arg.type === 'compliance' ? 'bg-emerald-500/20 text-emerald-400' :
                        arg.type === 'violation' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {arg.type}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{arg.details}</p>
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
                    <span className="font-mono text-slate-300">{attack.relation}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Grounded Extension */}
          {groundedExtension && (
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                <div className="text-xs text-emerald-300 uppercase tracking-wider mb-2">Accepted</div>
                <div className="flex flex-wrap gap-1">
                  {groundedExtension.accepted?.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                      {id}
                    </span>
                  ))}
                </div>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">Rejected</div>
                <div className="flex flex-wrap gap-1">
                  {groundedExtension.rejected?.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                      {id}
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
    } catch (e) {
      console.error('Export failed:', e);
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
        alert(`Imported ${result.total_imported} groups${result.total_skipped > 0 ? ` (${result.total_skipped} skipped)` : ''}`);
        loadPolicyGroups();
      }
    } catch (e) {
      alert('Invalid JSON file');
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
        alert(data.detail || 'Rollout preview failed');
        return;
      }
      setRolloutPreviewResult(data);
    } catch (e) {
      alert('Rollout preview failed');
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
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to save policy');
      }
    } catch (err) {
      alert('Failed to save policy');
    }
  };
  
  const handleDeletePolicy = async (policyId: string) => {
    if (!confirm(`Delete policy "${policyId}"?`)) return;
    
    try {
      const response = await fetch(`/api/v1/policies/${policyId}`, {
        method: 'DELETE'
      });
      
      if (response.ok) {
        setCustomPolicies(prev => prev.filter(p => p.id !== policyId));
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to delete policy');
      }
    } catch (err) {
      alert('Failed to delete policy');
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
    try {
      const response = await fetch(`/api/v1/policies/groups/${groupId}/toggle`, {
        method: 'PATCH'
      });
      if (response.ok) {
        loadPolicyGroups();
      }
    } catch (err) {
      alert('Failed to toggle group');
    }
  };
  
  const handleSaveGroup = async () => {
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
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to save group');
      }
    } catch (err) {
      alert('Failed to save group');
    }
  };
  
  const handleDeleteGroup = async (groupId: string) => {
    if (!confirm(`Delete group "${groupId}"?`)) return;
    
    try {
      const response = await fetch(`/api/v1/policies/groups/${groupId}`, {
        method: 'DELETE'
      });
      if (response.ok) {
        loadPolicyGroups();
      } else {
        const error = await response.json();
        alert(error.detail || 'Failed to delete group');
      }
    } catch (err) {
      alert('Failed to delete group');
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
                className="flex items-center gap-2 px-4 py-2 bg-violet-500 hover:bg-violet-400 text-white rounded-xl font-medium transition-all"
              >
                <Plus className="w-5 h-5" />
                New Policy
              </button>
            ) : (
              <div className="flex gap-2">
                <button
                  onClick={() => setShowTemplates(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-violet-500 hover:bg-violet-400 text-white rounded-xl font-medium transition-all"
                >
                  <Sparkles className="w-5 h-5" />
                  Templates
                </button>
                <button
                  onClick={handleExportGroups}
                  className="flex items-center gap-2 px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
                  title="Export policy groups"
                >
                  <Download className="w-4 h-4" />
                </button>
                <button
                  onClick={() => groupFileInputRef.current?.click()}
                  className="flex items-center gap-2 px-3 py-2 text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
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
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-white rounded-xl font-medium transition-all"
                  title="Preview rollout impact before changing groups"
                >
                  <Eye className="w-5 h-5" />
                  Preview Rollout
                </button>
                <button
                  onClick={() => { resetGroupForm(); setShowGroupEditor(true); }}
                  className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl font-medium transition-all"
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
                className="px-6 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveGroup}
                disabled={!groupFormData.id || !groupFormData.name}
                className="px-6 py-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl font-medium"
              >
                {editingGroup ? 'Update Group' : 'Create Group'}
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
                  <div className="max-h-72 overflow-auto space-y-2 pr-1">
                    {policyGroups.map(group => {
                      const proposedEnabled = rolloutOverrides[group.id] ?? group.enabled;
                      return (
                        <div
                          key={`rollout-${group.id}`}
                          className="flex items-center justify-between p-3 rounded-lg border border-white/10 bg-slate-800/40"
                        >
                          <div>
                            <div className="font-medium text-white text-sm">{group.name}</div>
                            <div className="text-xs text-slate-400 font-mono">{group.id}</div>
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
                        </div>
                        <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                          <div className="text-xs text-cyan-300 uppercase tracking-wider">Proposed Compliant</div>
                          <div className="text-2xl font-semibold text-cyan-200">
                            {rolloutPreviewResult.summary.proposed_compliant}
                          </div>
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
                        </div>
                      </div>
                      <div className="text-xs text-slate-400">
                        Baseline policies: <span className="font-mono">{rolloutPreviewResult.baseline.policy_count}</span>
                        {' • '}
                        Proposed policies: <span className="font-mono">{rolloutPreviewResult.proposed.policy_count}</span>
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
                            {rolloutPreviewResult.cases.map(item => (
                              <tr key={`rollout-case-${item.id}`} className="border-t border-white/5">
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
                className="px-6 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl"
              >
                Cancel
              </button>
              <button
                onClick={handleSavePolicy}
                disabled={!formData.id || !formData.description}
                className="px-6 py-2 bg-violet-500 hover:bg-violet-400 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl font-medium"
              >
                {editingPolicy ? 'Update Policy' : 'Create Policy'}
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
                          className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 rounded-lg"
                          title="View history and diffs"
                        >
                          <Clock className="w-4 h-4" />
                        </button>
                      {isCustomPolicy(policy.id) && (
                        <>
                          <button
                            onClick={() => handleEdit(policy)}
                            className="p-1.5 text-slate-400 hover:text-violet-400 hover:bg-violet-500/10 rounded-lg"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeletePolicy(policy.id)}
                            className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg"
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
                className="inline-flex items-center gap-2 px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl font-medium transition-all"
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
                      className={`w-12 h-7 rounded-full transition-all relative ${
                        group.enabled ? 'bg-emerald-500' : 'bg-slate-700'
                      }`}
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
                      className="p-2 text-slate-400 hover:text-violet-400 hover:bg-violet-500/10 rounded-lg"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleDeleteGroup(group.id)}
                      className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg"
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
  input_cost_per_1m?: number | null;
  cached_input_cost_per_1m?: number | null;
  output_cost_per_1m?: number | null;
  docs_url?: string | null;
  is_active?: boolean;
  api_key_set?: boolean;
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
  const [testResult, setTestResult] = useState<any>(null);
  const [providerStatus, setProviderStatus] = useState<Record<string, 'unknown' | 'testing' | 'success' | 'error'>>({});
  const [providerDiagnostics, setProviderDiagnostics] = useState<Record<string, ModelProviderDiagnostics | null>>({});
  const [testingAll, setTestingAll] = useState(false);
  const [openaiCatalog, setOpenaiCatalog] = useState<OpenAIModelMetadata[]>([]);
  const [openaiCatalogLoading, setOpenaiCatalogLoading] = useState(false);
  const editFormRef = useRef<HTMLDivElement | null>(null);
  const initialActiveTestedRef = useRef<string | null>(null);
  
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

  const handleEditProvider = useCallback(async (id: string) => {
    try {
      setError(null);
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
      setEditingProvider(provider);
    } catch (err: any) {
      setError(err.message || 'Failed to load provider details');
    }
  }, [applyOpenAIModelMetadata]);

  const handleTestProvider = useCallback(async (id: string, showResult = true) => {
    setTesting(id);
    setProviderStatus(prev => ({ ...prev, [id]: 'testing' }));
    setProviderDiagnostics(prev => ({ ...prev, [id]: null }));
    if (showResult) setTestResult(null);
    
    try {
      // First switch to this provider temporarily
      await fetch('/api/v1/llm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: id })
      });
      
      // Run the test
      const res = await fetch('/api/v1/llm/test', { method: 'POST' });
      const result = await res.json();
      
      setProviderStatus(prev => ({ ...prev, [id]: result.success ? 'success' : 'error' }));
      setProviderDiagnostics(prev => ({ ...prev, [id]: result.success ? null : (result.diagnostics || null) }));
      if (showResult) setTestResult({ id, ...result });
      
      // Switch back to original active
      if (activeProvider && activeProvider !== id) {
        await fetch('/api/v1/llm/switch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ provider_id: activeProvider })
        });
      }
      
      return result.success;
    } catch (err: any) {
      setProviderStatus(prev => ({ ...prev, [id]: 'error' }));
      const fallbackDiagnostics: ModelProviderDiagnostics = {
        code: 'test_request_failed',
        summary: 'Failed to call model test endpoint.',
        suggestions: [
          'Verify backend is running and reachable.',
          'Inspect backend logs for /api/v1/llm/test errors.',
        ],
        raw_error: err.message,
      };
      setProviderDiagnostics(prev => ({ ...prev, [id]: fallbackDiagnostics }));
      if (showResult) setTestResult({ id, success: false, error: err.message, diagnostics: fallbackDiagnostics });
      return false;
    } finally {
      setTesting(null);
    }
  }, [activeProvider]);

  useEffect(() => {
    if (!loading && activeProvider && providers.some(p => p.id === activeProvider) && initialActiveTestedRef.current !== activeProvider) {
      initialActiveTestedRef.current = activeProvider;
      void handleTestProvider(activeProvider, false);
    }
  }, [loading, activeProvider, providers, handleTestProvider]);

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
    
    // Switch back to original active provider
    if (activeProvider) {
      await fetch('/api/v1/llm/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider_id: activeProvider })
      });
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
                onChange={(e) => setFormProvider(prev => ({ ...prev, max_tokens: parseInt(e.target.value) }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Temperature</label>
              <input
                type="number"
                step="0.1"
                value={formProvider.temperature}
                onChange={(e) => setFormProvider(prev => ({ ...prev, temperature: parseFloat(e.target.value) }))}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Context Window</label>
              <input
                type="number"
                value={formProvider.context_window}
                onChange={(e) => setFormProvider(prev => ({ ...prev, context_window: parseInt(e.target.value) }))}
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
                {testResult.success ? 'Connection successful!' : 'Connection failed'}
              </span>
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
              {!testResult.success && testResult.diagnostics?.suggestions?.length > 0 && (
                <div className="mt-2 text-xs text-slate-300">
                  {testResult.diagnostics.suggestions.slice(0, 2).map((suggestion: string, idx: number) => (
                    <p key={idx}>• {suggestion}</p>
                  ))}
                </div>
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
        {providers.map(provider => (
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
                  </div>
                  <div className="flex items-center gap-4 mt-1 text-xs text-slate-500">
                    {provider.max_output_tokens && <span>Max output: {provider.max_output_tokens?.toLocaleString()}</span>}
                    {provider.preferred_endpoint && <span>Endpoint: {provider.preferred_endpoint}</span>}
                    {(provider.input_cost_per_1m || provider.output_cost_per_1m) && (
                      <span>
                        Cost/1M in/out: ${provider.input_cost_per_1m ?? 'n/a'} / ${provider.output_cost_per_1m ?? 'n/a'}
                      </span>
                    )}
                  </div>
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
                  disabled={testing === provider.id}
                  className="px-3 py-1.5 text-sm bg-emerald-500/10 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
                >
                  {testing === provider.id ? 'Testing...' : 'Test'}
                </button>
                <button
                  onClick={() => { void handleEditProvider(provider.id); }}
                  className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-all"
                >
                  <Edit2 className="w-4 h-4" />
                </button>
                {provider.id !== activeProvider && (
                  <button
                    onClick={() => handleDeleteProvider(provider.id)}
                    className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all"
                  >
                    <Trash2 className="w-4 h-4" />
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
