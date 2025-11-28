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
  ArrowLeftRight, List
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
type ViewMode = 'editor' | 'diff' | 'proof' | 'policies';

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
  const [savedCodes, setSavedCodes] = useState<SavedCode[]>([]);
  const [showSaveDialog, setShowSaveDialog] = useState(false);
  const [saveName, setSaveName] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load saved codes from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('acpg_saved_codes');
    if (saved) {
      setSavedCodes(JSON.parse(saved));
    }
  }, []);

  // Load policies and LLM info on mount
  useEffect(() => {
    api.listPolicies()
      .then(data => setPolicies(data.policies))
      .catch(err => console.error('Failed to load policies:', err));
    
    fetch('http://localhost:8000/api/v1/llm/active')
      .then(res => res.json())
      .then(data => setLlmProvider(data.name || 'Unknown'))
      .catch(() => setLlmProvider('GPT-4'));
  }, []);

  const handleAnalyze = useCallback(async () => {
    setError(null);
    setEnforceResult(null);
    setWorkflow({ step: 'prosecutor', iteration: 0, maxIterations: 3, violations: 0 });
    
    try {
      const analysisResult = await api.analyze(code, language);
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 500));
      
      setWorkflow(w => ({ ...w, step: 'adjudicator' }));
      const adjResult = await api.adjudicate(analysisResult);
      setAdjudication(adjResult);
      
      await new Promise(r => setTimeout(r, 300));
      setWorkflow(w => ({ ...w, step: 'complete' }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language]);

  const handleEnforce = useCallback(async () => {
    setError(null);
    setOriginalCode(code); // Save original for diff
    setWorkflow({ step: 'prosecutor', iteration: 1, maxIterations: 3, violations: 0 });
    
    try {
      const analysisResult = await api.analyze(code, language);
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 400));
      setWorkflow(w => ({ ...w, step: 'adjudicator' }));
      
      await new Promise(r => setTimeout(r, 400));
      setWorkflow(w => ({ ...w, step: 'generator' }));
      
      const result = await api.enforce(code, language, 3);
      setEnforceResult(result);
      
      if (result.final_code !== code) {
        setCode(result.final_code);
        // Auto-switch to diff view
        setViewMode('diff');
      }
      
      setWorkflow(w => ({ ...w, step: 'proof', iteration: result.iterations }));
      await new Promise(r => setTimeout(r, 400));
      
      const finalAnalysis = await api.analyze(result.final_code, language);
      setAnalysis(finalAnalysis);
      
      const adjResult = await api.adjudicate(finalAnalysis);
      setAdjudication(adjResult);
      
      setWorkflow(w => ({ ...w, step: 'complete', violations: finalAnalysis.violations.length }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enforcement failed');
      setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    }
  }, [code, language]);

  const handleLoadSample = (type: 'dirty' | 'clean') => {
    const newCode = type === 'dirty' ? SAMPLE_CODE : CLEAN_SAMPLE;
    setCode(newCode);
    setOriginalCode(newCode);
    setAnalysis(null);
    setAdjudication(null);
    setEnforceResult(null);
    setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
    setViewMode('editor');
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
                  onClick={() => setViewMode('editor')}
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
                  onClick={() => setViewMode('diff')}
                  disabled={!enforceResult}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-all ${
                    viewMode === 'diff' 
                      ? 'bg-slate-700 text-white' 
                      : 'text-slate-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed'
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <ArrowLeftRight className="w-4 h-4" />
                    Diff
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
              </div>
              
              <div className="h-6 w-px bg-slate-700" />
              
              {/* LLM Badge */}
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50">
                <Bot className="w-4 h-4 text-cyan-400" />
                <span className="text-sm text-slate-300">{llmProvider}</span>
              </div>
              
              <div className="h-6 w-px bg-slate-700" />
              
              {/* Sample buttons */}
              <button
                onClick={() => handleLoadSample('dirty')}
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
              >
                <span className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  Vulnerable
                </span>
              </button>
              <button
                onClick={() => handleLoadSample('clean')}
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
              >
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Clean
                </span>
              </button>
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
        {viewMode === 'policies' ? (
          <PoliciesView policies={policies} />
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
                    {viewMode === 'diff' ? (
                      <>
                        <GitBranch className="w-5 h-5 text-violet-400" />
                        <span className="font-medium text-slate-200">Code Diff</span>
                        <span className="px-2 py-0.5 text-xs font-mono font-medium bg-violet-500/20 text-violet-400 rounded-md">
                          original → fixed
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
                      <span>{code.split('\n').length} lines</span>
                    </div>
                  </div>
                </div>
                
                {/* Editor Content */}
                <div className="h-[520px] bg-gray-950/50">
                  {viewMode === 'diff' ? (
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
                  <span>Analyze Code</span>
                </button>
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
              {/* Compliance Status */}
              <ComplianceStatus 
                adjudication={adjudication} 
                violationCount={analysis?.violations.length ?? 0}
                enforceResult={enforceResult}
              />

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
  violationCount,
  enforceResult
}: { 
  adjudication: AdjudicationResult | null;
  violationCount: number;
  enforceResult: EnforceResponse | null;
}) {
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

// Policies View
function PoliciesView({ policies }: { policies: PolicyRule[] }) {
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<'all' | 'strict' | 'defeasible'>('all');
  
  const filtered = policies.filter(p => {
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
              <p className="text-slate-400">{policies.length} security policies loaded</p>
            </div>
          </div>
        </div>
        
        {/* Search & Filter */}
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
      </div>
      
      {/* Policy Groups */}
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
                  className="p-4 bg-slate-800/50 rounded-xl border border-white/5 hover:border-violet-500/30 transition-all"
                >
                  <div className="flex items-center gap-2 mb-2">
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
                  </div>
                  <p className="text-sm text-slate-400">{policy.description}</p>
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
