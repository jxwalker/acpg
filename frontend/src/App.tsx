import { useState, useCallback, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { 
  Shield, ShieldCheck, ShieldAlert,
  RefreshCw, FileCode, 
  AlertTriangle, CheckCircle2, XCircle, Info,
  ChevronDown, ChevronRight, Copy, Check,
  Bot, Search, Scale, FileCheck, Lock, Fingerprint,
  Sparkles, Terminal, Clock
} from 'lucide-react';
import { api } from './api';
import type { 
  PolicyRule, Violation, AnalysisResult, 
  AdjudicationResult, ProofBundle, EnforceResponse 
} from './types';

// Sample vulnerable code
const SAMPLE_CODE = `def login(username, password_input):
    """Login function with security vulnerabilities."""
    
    # Hardcoded credentials - SEC-001
    password = "secret123"
    api_key = "sk-1234567890abcdef"
    
    # SQL injection - SQL-001
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    
    # Dangerous eval - SEC-003
    result = eval(password_input)
    
    # Weak crypto - CRYPTO-001
    import hashlib
    hash = hashlib.md5(password.encode()).hexdigest()
    
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

interface WorkflowState {
  step: WorkflowStep;
  iteration: number;
  maxIterations: number;
  violations: number;
}

export default function App() {
  const [code, setCode] = useState(SAMPLE_CODE);
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

  // Load policies and LLM info on mount
  useEffect(() => {
    api.listPolicies()
      .then(data => setPolicies(data.policies))
      .catch(err => console.error('Failed to load policies:', err));
    
    // Try to get LLM provider info
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
      // Step 1: Prosecutor
      const analysisResult = await api.analyze(code, language);
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 500));
      
      // Step 2: Adjudicator
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
    setWorkflow({ step: 'prosecutor', iteration: 1, maxIterations: 3, violations: 0 });
    
    try {
      // Simulate step-by-step workflow
      const analysisResult = await api.analyze(code, language);
      setAnalysis(analysisResult);
      setWorkflow(w => ({ ...w, violations: analysisResult.violations.length }));
      
      await new Promise(r => setTimeout(r, 400));
      setWorkflow(w => ({ ...w, step: 'adjudicator' }));
      
      await new Promise(r => setTimeout(r, 400));
      setWorkflow(w => ({ ...w, step: 'generator' }));
      
      // Full enforcement
      const result = await api.enforce(code, language, 3);
      setEnforceResult(result);
      
      if (result.final_code !== code) {
        setCode(result.final_code);
      }
      
      // Final analysis
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
    setCode(type === 'dirty' ? SAMPLE_CODE : CLEAN_SAMPLE);
    setAnalysis(null);
    setAdjudication(null);
    setEnforceResult(null);
    setWorkflow({ step: 'idle', iteration: 0, maxIterations: 3, violations: 0 });
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
            
            {/* LLM Badge & Controls */}
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-800/50 border border-slate-700/50">
                <Bot className="w-4 h-4 text-cyan-400" />
                <span className="text-sm text-slate-300">{llmProvider}</span>
              </div>
              <div className="h-6 w-px bg-slate-700" />
              <button
                onClick={() => handleLoadSample('dirty')}
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
              >
                <span className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  Vulnerable Code
                </span>
              </button>
              <button
                onClick={() => handleLoadSample('clean')}
                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-800/50 rounded-xl transition-all"
              >
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  Clean Code
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
        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
          {/* Left Panel - Code Editor (3 cols) */}
          <div className="xl:col-span-3 space-y-5">
            <div className="glass rounded-2xl overflow-hidden border border-white/5">
              <div className="px-5 py-4 border-b border-white/5 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1.5">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-amber-500/80" />
                    <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
                  </div>
                  <div className="h-4 w-px bg-slate-700" />
                  <FileCode className="w-5 h-5 text-slate-400" />
                  <span className="font-medium text-slate-200">code.py</span>
                  <span className="px-2 py-0.5 text-xs font-mono font-medium bg-slate-800 rounded-md text-slate-400">
                    {language}
                  </span>
                </div>
                <div className="flex items-center gap-2 text-xs text-slate-500">
                  <Terminal className="w-4 h-4" />
                  <span>{code.split('\n').length} lines</span>
                </div>
              </div>
              <div className="h-[520px] bg-gray-950/50">
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
              </div>
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

            {/* Proof Bundle */}
            {enforceResult?.proof_bundle && (
              <ProofBundleCard 
                proof={enforceResult.proof_bundle} 
                onCopy={handleCopyProof}
                copied={copied}
                iterations={enforceResult.iterations}
              />
            )}

            {/* Policy Reference */}
            <PolicyPanel policies={policies} />
          </div>
        </div>
      </main>
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
      
      {/* Iteration indicator */}
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
            <div 
              key={index}
              className="border-b border-white/5 last:border-b-0"
            >
              <button
                onClick={() => toggleExpand(index)}
                className="w-full px-5 py-4 flex items-center gap-4 hover:bg-white/[0.02] transition-colors text-left"
              >
                <div className={`w-1 h-8 rounded-full ${severity.bg}`} style={{ backgroundColor: severity.color.replace('text-', '') }} />
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

// Proof Bundle Card Component
function ProofBundleCard({ 
  proof, 
  onCopy, 
  copied,
  iterations
}: { 
  proof: ProofBundle;
  onCopy: () => void;
  copied: boolean;
  iterations: number;
}) {
  return (
    <div className="gradient-border rounded-2xl overflow-hidden animate-scale-in stagger-2">
      <div className="p-6 space-y-4">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 border border-emerald-500/30">
              <Fingerprint className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h3 className="font-display font-bold text-white">Proof Bundle</h3>
              <p className="text-xs text-slate-400">Cryptographically Signed Certificate</p>
            </div>
          </div>
          <button
            onClick={onCopy}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium
                     bg-white/5 hover:bg-white/10 text-slate-300 hover:text-white
                     rounded-xl transition-all border border-white/10"
          >
            {copied ? (
              <>
                <Check className="w-4 h-4 text-emerald-400" />
                <span className="text-emerald-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-4 h-4" />
                <span>Export</span>
              </>
            )}
          </button>
        </div>
        
        {/* Details Grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Artifact Hash</div>
            <div className="font-mono text-sm text-slate-300 truncate">{proof.artifact.hash.slice(0, 20)}...</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Decision</div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="font-semibold text-emerald-400">{proof.decision}</span>
            </div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Algorithm</div>
            <div className="font-mono text-sm text-slate-300">{proof.signed.algorithm}</div>
          </div>
          <div className="p-3 rounded-xl bg-slate-900/50 border border-white/5">
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Iterations</div>
            <div className="font-semibold text-cyan-400">{iterations}</div>
          </div>
        </div>
        
        {/* Policies */}
        <div className="pt-3 border-t border-white/5">
          <div className="text-xs text-slate-500 uppercase tracking-wider mb-3">Verified Policies</div>
          <div className="flex flex-wrap gap-2">
            {proof.policies.map((p, i) => (
              <span 
                key={i}
                className={`px-2.5 py-1 text-xs font-mono font-medium rounded-lg flex items-center gap-1.5 ${
                  p.result === 'satisfied' 
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' 
                    : 'bg-red-500/10 text-red-400 border border-red-500/30'
                }`}
              >
                {p.result === 'satisfied' ? (
                  <CheckCircle2 className="w-3 h-3" />
                ) : (
                  <XCircle className="w-3 h-3" />
                )}
                {p.id}
              </span>
            ))}
          </div>
        </div>
        
        {/* Signature Preview */}
        <div className="p-3 rounded-xl bg-gradient-to-r from-slate-900/80 to-slate-800/50 border border-white/5">
          <div className="flex items-center gap-2 mb-2">
            <Lock className="w-4 h-4 text-violet-400" />
            <span className="text-xs text-slate-400 uppercase tracking-wider">ECDSA Signature</span>
          </div>
          <div className="font-mono text-xs text-slate-500 break-all">
            {proof.signed.signature.slice(0, 64)}...
          </div>
        </div>
      </div>
    </div>
  );
}

// Policy Panel Component
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
