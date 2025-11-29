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
  List, Plus, Edit2, BookOpen, Settings, Link2, Power
} from 'lucide-react';
import { api } from './api';
import type { 
  PolicyRule, Violation, AnalysisResult, 
  AdjudicationResult, ProofBundle, EnforceResponse 
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
type ViewMode = 'editor' | 'diff' | 'proof' | 'policies' | 'verify' | 'tools';
type CodeViewMode = 'current' | 'original' | 'fixed' | 'diff';

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
}

export default function App() {
  const [code, setCode] = useState(SAMPLE_CODE);
  const [originalCode, setOriginalCode] = useState(SAMPLE_CODE);
  const [language] = useState('python');
  const [workflow, setWorkflow] = useState<WorkflowState>({ 
    step: 'idle', 
    iteration: 0, 
    maxIterations: 3,
    violations: 0 
  });
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [adjudication, setAdjudication] = useState<AdjudicationResult | null>(null);
  const [enforceResult, setEnforceResult] = useState<EnforceResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [llmProvider, setLlmProvider] = useState<string>('Loading...');
  const [viewMode, setViewMode] = useState<ViewMode>('editor');
  const [codeViewMode, setCodeViewMode] = useState<CodeViewMode>('current');
  const [savedCodes, setSavedCodes] = useState<SavedCode[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [complianceReport, setComplianceReport] = useState<any>(null);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [sampleFiles, setSampleFiles] = useState<Array<{name: string; description: string; violations: string[]}>>([]);
  const [sampleFilesLoading, setSampleFilesLoading] = useState(true);
  const [showSampleMenu, setShowSampleMenu] = useState(false);
  const [enabledGroupsCount, setEnabledGroupsCount] = useState({ groups: 0, policies: 0 });
  const [policyCreationData, setPolicyCreationData] = useState<{toolName?: string; toolRuleId?: string; description?: string; severity?: string} | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load saved codes from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('acpg_saved_codes');
    if (saved) {
      setSavedCodes(JSON.parse(saved));
    }
  }, []);

  // Load policies, LLM info, and sample files on mount
  useEffect(() => {
    api.listPolicies()
      .then(data => setPolicies(data.policies))
      .catch(err => console.error('Failed to load policies:', err));
    
    fetch('/api/v1/llm/active')
      .then(res => res.json())
      .then(data => setLlmProvider(data.name || 'Unknown'))
      .catch(() => setLlmProvider('GPT-4'));
    
    // Load sample files
    setSampleFilesLoading(true);
    fetch('/api/v1/samples')
      .then(res => {
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }
        return res.json();
      })
      .then(data => {
        console.log('Loaded samples:', data.samples?.length || 0);
        setSampleFiles(data.samples || []);
        setSampleFilesLoading(false);
      })
      .catch(err => {
        console.error('Failed to load samples:', err);
        setSampleFiles([]);
        setSampleFilesLoading(false);
      });
    
    // Load enabled policy groups count
    fetch('/api/v1/policies/groups/')
      .then(res => res.json())
      .then(data => setEnabledGroupsCount({
        groups: data.enabled_groups || 0,
        policies: data.enabled_policies || 0
      }))
      .catch(() => {});
  }, []);

  const [analysisProgress, setAnalysisProgress] = useState<{
    phase: string;
    tool?: string;
    message?: string;
  } | null>(null);

  const handleAnalyze = useCallback(async () => {
    setError(null);
    setEnforceResult(null);
    setAnalysisProgress({ phase: 'starting', message: 'Initializing analysis...' });
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
      const adjResult = await api.adjudicate(analysisResult);
      setAdjudication(adjResult);
      
      await new Promise(r => setTimeout(r, 200));
      setAnalysisProgress({ phase: 'complete', message: 'Analysis complete' });
        setAnalysisProgress({ phase: 'complete', message: 'Enforcement complete' });
        setWorkflow(w => ({ ...w, step: 'complete' }));
        setTimeout(() => setAnalysisProgress(null), 2000);
      
      // Clear progress after a moment
      setTimeout(() => setAnalysisProgress(null), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setAnalysisProgress(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language]);

  const handleEnforce = useCallback(async () => {
    setError(null);
    setOriginalCode(code); // Save original for diff
    setAnalysisProgress({ phase: 'starting', message: 'Starting enforcement...' });
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
      
      const result = await api.enforce(code, language, 3);
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
      const adjResult = await api.adjudicate(finalAnalysis);
      setAdjudication(adjResult);
      
      setAnalysisProgress({ phase: 'complete', message: 'Enforcement complete' });
      setWorkflow(w => ({ ...w, step: 'complete', violations: finalAnalysis.violations.length }));
      setTimeout(() => setAnalysisProgress(null), 2000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enforcement failed');
      setAnalysisProgress(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language]);

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

  const handleLoadSampleFile = async (filename: string) => {
    try {
      const response = await fetch(`/api/v1/samples/${filename}`);
      if (!response.ok) throw new Error('Failed to load sample');
      const data = await response.json();
      setCode(data.content);
      setOriginalCode(data.content);
      setAnalysis(null);
      setAdjudication(null);
      setEnforceResult(null);
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
      setViewMode('editor');
      setCodeViewMode('current');
      setShowSampleMenu(false);
    } catch (err) {
      setError('Failed to load sample file');
    }
  };

  const handleSaveCode = () => {
    if (!saveName.trim()) return;
    
    const newSave: SavedCode = {
      id: Date.now().toString(),
      name: saveName.trim(),
      code,
      language,
      savedAt: new Date().toISOString()
    };
    
    const updated = [...savedCodes, newSave];
    setSavedCodes(updated);
    localStorage.setItem('acpg_saved_codes', JSON.stringify(updated));
    setShowSaveDialog(false);
    setSaveName('');
  };

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

  const handleDownloadProof = () => {
    if (!enforceResult?.proof_bundle) return;
    const blob = new Blob([JSON.stringify(enforceResult.proof_bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'proof_bundle.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyProof = useCallback(() => {
    if (enforceResult?.proof_bundle) {
      navigator.clipboard.writeText(JSON.stringify(enforceResult.proof_bundle, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [enforceResult]);

  const isProcessing = workflow.step !== 'idle' && workflow.step !== 'complete';

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
              
              {/* LLM Badge */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50">
                <Bot className="w-4 h-4 text-cyan-400" />
                <span className="text-sm text-slate-300">{llmProvider}</span>
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
              
              {/* Sample Files Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setShowSampleMenu(!showSampleMenu)}
                  className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all flex items-center gap-2"
                >
                  <FolderOpen className="w-4 h-4 text-amber-400" />
                  Samples
                  <ChevronDown className={`w-4 h-4 transition-transform ${showSampleMenu ? 'rotate-180' : ''}`} />
                </button>
                
                {showSampleMenu && (
                  <div className="absolute top-full right-0 mt-2 w-80 glass rounded-xl border border-white/10 shadow-2xl z-50 overflow-hidden">
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
                    </div>
                    
                    {sampleFilesLoading ? (
                      <div className="p-4 text-center text-slate-400 text-sm">
                        Loading samples...
                      </div>
                    ) : sampleFiles.length > 0 ? (
                      <>
                        <div className="p-2 border-t border-white/10">
                          <span className="text-xs text-slate-500 uppercase tracking-wider px-2">Sample Files ({sampleFiles.length})</span>
                        </div>
                        <div className="p-1 max-h-64 overflow-y-auto">
                          {sampleFiles.map(sample => (
                            <button
                              key={sample.name}
                              onClick={() => handleLoadSampleFile(sample.name)}
                              className="w-full text-left px-3 py-2 text-sm text-slate-300 hover:text-white hover:bg-white/10 rounded-lg"
                            >
                              <div className="flex items-center gap-3">
                                <FileCode className="w-4 h-4 text-violet-400 flex-shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <div className="font-medium font-mono text-xs truncate">{sample.name}</div>
                                  <div className="text-xs text-slate-500 truncate">{sample.description}</div>
                                  {sample.violations?.length > 0 && (
                                    <div className="flex gap-1 mt-1 flex-wrap">
                                      {sample.violations.slice(0, 3).map(v => (
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
                        No sample files found
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>

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
                      theme="vs-dark"
                      options={{
                        readOnly: true,
                        renderSideBySide: true,
                        minimap: { enabled: false },
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
                      theme="vs-dark"
                      options={{
                        readOnly: true,
                        minimap: { enabled: false },
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
                      theme="vs-dark"
                      options={{
                        readOnly: true,
                        minimap: { enabled: false },
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
                      theme="vs-dark"
                      options={{
                        minimap: { enabled: false },
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
                      }}
                    />
                  )}
                </div>
              </div>

              {/* Saved Codes Library */}
              {savedCodes.length > 0 && (
                <div className="glass rounded-xl p-4 border border-white/5">
                  <div className="flex items-center gap-2 mb-3">
                    <FolderOpen className="w-4 h-4 text-amber-400" />
                    <span className="text-sm font-medium text-slate-300">Saved Code Library</span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {savedCodes.map(saved => (
                      <div key={saved.id} className="flex items-center gap-1 bg-slate-800/50 rounded-lg pl-3 pr-1 py-1">
                        <button
                          onClick={() => handleLoadCode(saved)}
                          className="text-sm text-slate-300 hover:text-white"
                        >
                          {saved.name}
                        </button>
                        <button
                          onClick={() => handleDeleteSaved(saved.id)}
                          className="p-1 text-slate-500 hover:text-red-400"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

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
                      setTimeout(() => {
                        const event = new CustomEvent('createMapping', { 
                          detail: { toolName, toolRuleId: ruleId } 
                        });
                        window.dispatchEvent(event);
                      }, 100);
                    }}
                  />
                ) : null;
              })()}

              {/* Violations List */}
              {analysis && analysis.violations.length > 0 && (
                <ViolationsList violations={analysis.violations} policies={policies} />
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
          <div className="glass rounded-2xl p-6 w-96 border border-white/10">
            <h3 className="text-lg font-semibold text-white mb-4">Save Code</h3>
            <input
              type="text"
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="Enter a name..."
              className="w-full px-4 py-3 bg-slate-800/50 border border-white/10 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/50"
              autoFocus
            />
            <div className="flex gap-3 mt-4">
              <button
                onClick={() => setShowSaveDialog(false)}
                className="flex-1 px-4 py-2 text-slate-400 hover:text-white border border-slate-700 rounded-xl"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveCode}
                className="flex-1 px-4 py-2 bg-emerald-500 text-white rounded-xl hover:bg-emerald-400"
              >
                Save
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

// Compliance Status Component
function ComplianceStatus({ 
  adjudication, 
  violations,
  enforceResult
}: { 
  adjudication: AdjudicationResult | null;
  violations: Violation[];
  enforceResult: EnforceResponse | null;
}) {
  // Count violations by severity
  const severityCounts = violations.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  
  const violationCount = violations.length;

  if (!adjudication) {
    return (
      <div className="glass rounded-2xl p-6 border border-white/5 animate-fade-in">
        <div className="flex items-center gap-4">
          <div className="p-4 rounded-2xl bg-slate-800/50">
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

  return (
    <div className={`glass rounded-2xl p-6 border animate-scale-in ${
      isCompliant 
        ? 'border-emerald-500/30 glow-emerald' 
        : 'border-red-500/30 glow-red'
    }`}>
      <div className="flex items-start gap-4">
        <div className={`p-4 rounded-2xl ${
          isCompliant ? 'bg-emerald-500/10' : 'bg-red-500/10'
        }`}>
          {isCompliant ? (
            <ShieldCheck className="w-10 h-10 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-10 h-10 text-red-400" />
          )}
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3">
            <h3 className={`text-xl font-display font-bold ${
              isCompliant ? 'text-emerald-400' : 'text-red-400'
            }`}>
              {isCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
            </h3>
            {isCompliant && (
              <span className="px-2 py-0.5 text-xs font-semibold bg-emerald-500/20 text-emerald-400 rounded-full animate-pulse">
                CERTIFIED
              </span>
            )}
          </div>
          <p className="text-sm text-slate-400 mt-1">
            {isCompliant 
              ? `All ${adjudication.satisfied_rules.length} security policies satisfied`
              : `${violationCount} violation${violationCount !== 1 ? 's' : ''} require attention`
            }
          </p>
          
          {/* Severity breakdown for non-compliant */}
          {!isCompliant && violationCount > 0 && (
            <div className="flex items-center gap-2 mt-2">
              {severityCounts.critical > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-red-500/20 text-red-400 rounded">
                  {severityCounts.critical} critical
                </span>
              )}
              {severityCounts.high > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-orange-500/20 text-orange-400 rounded">
                  {severityCounts.high} high
                </span>
              )}
              {severityCounts.medium > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-amber-500/20 text-amber-400 rounded">
                  {severityCounts.medium} medium
                </span>
              )}
              {severityCounts.low > 0 && (
                <span className="px-2 py-0.5 text-xs font-semibold bg-slate-500/20 text-slate-400 rounded">
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
                <div className="text-2xl font-bold text-emerald-400">
                  {adjudication.satisfied_rules.length}
                </div>
                <div className="text-xs text-slate-500">Policies Passed</div>
              </div>
              {!isCompliant && (
                <>
                  <div className="h-8 w-px bg-slate-700" />
                  <div className="text-center">
                    <div className="text-2xl font-bold text-red-400">{violationCount}</div>
                    <div className="text-xs text-slate-500">Remaining</div>
                  </div>
                </>
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
  policies 
}: { 
  violations: Violation[];
  policies: PolicyRule[];
}) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const toggleExpand = (index: number) => {
    setExpanded(prev => ({ ...prev, [index]: !prev[index] }));
  };

  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'critical': return { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30' };
      case 'high': return { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' };
      case 'medium': return { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' };
      default: return { color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/30' };
    }
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
        <span className="px-3 py-1 text-sm font-semibold bg-red-500/10 text-red-400 rounded-full">
          {violations.length} found
        </span>
      </div>
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
                  <span className="text-xs text-slate-500 font-mono bg-slate-800/50 px-2 py-1 rounded">
                    L{violation.line}
                  </span>
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
  onDownload: () => void;
  copied: boolean;
}) {
  const [activeTab, setActiveTab] = useState<'overview' | 'formal' | 'json'>('overview');
  
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
            <button
              onClick={onDownload}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl"
            >
              <Download className="w-4 h-4" />
              Download
            </button>
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
interface PolicyGroup {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  policies: string[];
  policy_count?: number;
}

// Tools Configuration View
function ToolsConfigurationView({ 
  onCreatePolicy 
}: { 
  onCreatePolicy?: (data: {toolName: string; toolRuleId: string; description?: string; severity?: string}) => void;
}) {
  const [activeTab, setActiveTab] = useState<'tools' | 'mappings' | 'rules'>('tools');
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
  
  // Listen for createMapping events from unmapped findings
  useEffect(() => {
    const handleCreateMapping = (event: CustomEvent) => {
      const { toolName, toolRuleId } = event.detail;
      setNewMapping({
        toolName,
        toolRuleId,
        policyId: '',
        confidence: 'medium',
        severity: 'medium',
        description: ''
      });
      setShowAddForm(true);
    };
    
    window.addEventListener('createMapping', handleCreateMapping as EventListener);
    return () => {
      window.removeEventListener('createMapping', handleCreateMapping as EventListener);
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
          <div className="space-y-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Tool Name</label>
              <input
                type="text"
                value={newMapping.toolName}
                onChange={(e) => setNewMapping({...newMapping, toolName: e.target.value})}
                className="w-full px-3 py-2 bg-slate-800/50 border border-slate-700 rounded-lg text-white"
                placeholder="e.g., bandit"
                disabled={!!editingMapping}
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
                disabled={!!editingMapping}
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
              <button
                onClick={() => { resetGroupForm(); setShowGroupEditor(true); }}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-400 text-white rounded-xl font-medium transition-all"
              >
                <Plus className="w-5 h-5" />
                New Group
              </button>
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
                      {isCustomPolicy(policy.id) && (
                        <div className="flex gap-1">
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
                        </div>
                      )}
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
                
                {/* Policy list */}
                <div className="flex flex-wrap gap-2">
                  {group.policies.slice(0, 10).map(policyId => (
                    <span 
                      key={policyId} 
                      className="px-2 py-1 bg-slate-800/50 text-slate-300 text-xs font-mono rounded-lg"
                    >
                      {policyId}
                    </span>
                  ))}
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
