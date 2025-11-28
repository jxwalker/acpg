import { useState, useCallback, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { 
  Shield, ShieldCheck, ShieldAlert, ShieldX,
  Play, Zap, Download, RefreshCw, FileCode, 
  AlertTriangle, CheckCircle2, XCircle, Info,
  ChevronDown, ChevronRight, Copy, Check
} from 'lucide-react';
import { api } from './api';
import type { 
  PolicyRule, Violation, AnalysisResult, 
  AdjudicationResult, ProofBundle, EnforceResponse 
} from './types';

// Sample code for demonstration
const SAMPLE_CODE = `def login(username, password_input):
    # Hardcoded credentials - violation!
    password = "secret123"
    api_key = "sk-1234567890"
    
    # SQL injection vulnerability
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    
    # Using eval - dangerous!
    result = eval(password_input)
    
    return authenticate(username, password)
`;

const CLEAN_SAMPLE = `import os
import hashlib
from typing import Optional

def login(username: str, password_input: str) -> Optional[dict]:
    """Secure login function following best practices."""
    # Get credentials from environment
    stored_hash = os.environ.get("PASSWORD_HASH")
    
    # Use parameterized queries
    query = "SELECT * FROM users WHERE name = ?"
    user = db.execute(query, (username,))
    
    # Secure password verification
    input_hash = hashlib.sha256(password_input.encode()).hexdigest()
    
    if input_hash == stored_hash:
        return {"status": "authenticated", "user": username}
    return None
`;

type AppState = 'idle' | 'analyzing' | 'enforcing' | 'complete';

export default function App() {
  const [code, setCode] = useState(SAMPLE_CODE);
  const [language] = useState('python');
  const [appState, setAppState] = useState<AppState>('idle');
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [adjudication, setAdjudication] = useState<AdjudicationResult | null>(null);
  const [enforceResult, setEnforceResult] = useState<EnforceResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Load policies on mount
  useEffect(() => {
    api.listPolicies()
      .then(data => setPolicies(data.policies))
      .catch(err => console.error('Failed to load policies:', err));
  }, []);

  const handleAnalyze = useCallback(async () => {
    setAppState('analyzing');
    setError(null);
    setEnforceResult(null);
    
    try {
      const analysisResult = await api.analyze(code, language);
      setAnalysis(analysisResult);
      
      const adjResult = await api.adjudicate(analysisResult);
      setAdjudication(adjResult);
      
      setAppState('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setAppState('idle');
    }
  }, [code, language]);

  const handleEnforce = useCallback(async () => {
    setAppState('enforcing');
    setError(null);
    
    try {
      const result = await api.enforce(code, language, 3);
      setEnforceResult(result);
      
      if (result.compliant && result.final_code !== code) {
        setCode(result.final_code);
      }
      
      // Re-analyze the final code
      const analysisResult = await api.analyze(result.final_code, language);
      setAnalysis(analysisResult);
      
      const adjResult = await api.adjudicate(analysisResult);
      setAdjudication(adjResult);
      
      setAppState('complete');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Enforcement failed');
      setAppState('idle');
    }
  }, [code, language]);

  const handleLoadSample = (type: 'dirty' | 'clean') => {
    setCode(type === 'dirty' ? SAMPLE_CODE : CLEAN_SAMPLE);
    setAnalysis(null);
    setAdjudication(null);
    setEnforceResult(null);
    setAppState('idle');
  };

  const handleCopyProof = useCallback(() => {
    if (enforceResult?.proof_bundle) {
      navigator.clipboard.writeText(JSON.stringify(enforceResult.proof_bundle, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [enforceResult]);

  const isCompliant = adjudication?.compliant ?? false;
  const violationCount = analysis?.violations.length ?? 0;

  return (
    <div className="min-h-screen pattern-grid">
      {/* Header */}
      <header className="glass border-b border-slate-700/50 sticky top-0 z-50">
        <div className="max-w-[1800px] mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-gradient-to-br from-acpg-500 to-acpg-700 shadow-lg shadow-acpg-500/20">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-white tracking-tight">ACPG</h1>
                  <p className="text-xs text-slate-400 font-medium">Agentic Compliance Governor</p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              <button
                onClick={() => handleLoadSample('dirty')}
                className="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
              >
                Load Vulnerable Code
              </button>
              <button
                onClick={() => handleLoadSample('clean')}
                className="px-3 py-2 text-sm font-medium text-slate-300 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors"
              >
                Load Clean Code
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1800px] mx-auto px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left Panel - Code Editor */}
          <div className="space-y-4">
            <div className="glass rounded-2xl overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <FileCode className="w-5 h-5 text-acpg-400" />
                  <span className="font-medium text-slate-200">Code Editor</span>
                  <span className="px-2 py-0.5 text-xs font-medium bg-slate-700 rounded-full text-slate-300">
                    {language}
                  </span>
                </div>
              </div>
              <div className="h-[500px]">
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
                    padding: { top: 16, bottom: 16 },
                    lineNumbers: 'on',
                    scrollBeyondLastLine: false,
                    renderLineHighlight: 'line',
                    cursorBlinking: 'smooth',
                  }}
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex gap-3">
              <button
                onClick={handleAnalyze}
                disabled={appState === 'analyzing' || appState === 'enforcing'}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-slate-700 hover:bg-slate-600 disabled:bg-slate-800 disabled:text-slate-500 text-white font-semibold rounded-xl transition-all duration-200"
              >
                {appState === 'analyzing' ? (
                  <RefreshCw className="w-5 h-5 animate-spin" />
                ) : (
                  <Play className="w-5 h-5" />
                )}
                Analyze
              </button>
              <button
                onClick={handleEnforce}
                disabled={appState === 'analyzing' || appState === 'enforcing'}
                className="flex-1 flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-acpg-600 to-acpg-500 hover:from-acpg-500 hover:to-acpg-400 disabled:from-slate-700 disabled:to-slate-700 disabled:text-slate-500 text-white font-semibold rounded-xl transition-all duration-200 shadow-lg shadow-acpg-500/20"
              >
                {appState === 'enforcing' ? (
                  <RefreshCw className="w-5 h-5 animate-spin" />
                ) : (
                  <Zap className="w-5 h-5" />
                )}
                Auto-Fix & Certify
              </button>
            </div>

            {/* Error Display */}
            {error && (
              <div className="glass rounded-xl p-4 border border-red-500/30 bg-red-500/10 animate-slide-in">
                <div className="flex items-center gap-3">
                  <XCircle className="w-5 h-5 text-red-400" />
                  <span className="text-red-300">{error}</span>
                </div>
              </div>
            )}
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-4">
            {/* Compliance Status */}
            <ComplianceStatus 
              adjudication={adjudication} 
              violationCount={violationCount}
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
      <div className="glass rounded-2xl p-6 border border-slate-700/50">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-slate-700/50">
            <Shield className="w-8 h-8 text-slate-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-slate-200">Ready to Analyze</h3>
            <p className="text-sm text-slate-400">Click "Analyze" to check compliance</p>
          </div>
        </div>
      </div>
    );
  }

  const isCompliant = adjudication.compliant;

  return (
    <div className={`glass rounded-2xl p-6 border animate-slide-in ${
      isCompliant 
        ? 'border-acpg-500/30 glow-green' 
        : 'border-red-500/30 glow-red'
    }`}>
      <div className="flex items-center gap-4">
        <div className={`p-3 rounded-xl ${
          isCompliant ? 'bg-acpg-500/20' : 'bg-red-500/20'
        }`}>
          {isCompliant ? (
            <ShieldCheck className="w-8 h-8 text-acpg-400" />
          ) : (
            <ShieldAlert className="w-8 h-8 text-red-400" />
          )}
        </div>
        <div className="flex-1">
          <h3 className={`text-lg font-semibold ${
            isCompliant ? 'text-acpg-400' : 'text-red-400'
          }`}>
            {isCompliant ? 'Compliant' : 'Non-Compliant'}
          </h3>
          <p className="text-sm text-slate-400">
            {isCompliant 
              ? `All ${adjudication.satisfied_rules.length} policies satisfied`
              : `${violationCount} violation${violationCount !== 1 ? 's' : ''} detected`
            }
          </p>
        </div>
        {enforceResult && (
          <div className="text-right">
            <div className="text-sm text-slate-400">Iterations</div>
            <div className="text-2xl font-bold text-white">{enforceResult.iterations}</div>
          </div>
        )}
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

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/20 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/20 border-orange-500/30';
      case 'medium': return 'text-amber-400 bg-amber-500/20 border-amber-500/30';
      default: return 'text-slate-400 bg-slate-500/20 border-slate-500/30';
    }
  };

  const getPolicy = (ruleId: string) => policies.find(p => p.id === ruleId);

  return (
    <div className="glass rounded-2xl overflow-hidden border border-slate-700/50 animate-slide-in">
      <div className="px-4 py-3 border-b border-slate-700/50 flex items-center gap-3">
        <AlertTriangle className="w-5 h-5 text-amber-400" />
        <span className="font-medium text-slate-200">Violations Found</span>
        <span className="px-2 py-0.5 text-xs font-medium bg-red-500/20 text-red-400 rounded-full">
          {violations.length}
        </span>
      </div>
      <div className="max-h-[300px] overflow-y-auto">
        {violations.map((violation, index) => {
          const policy = getPolicy(violation.rule_id);
          const isExpanded = expanded[index];
          
          return (
            <div 
              key={index}
              className="border-b border-slate-700/30 last:border-b-0"
            >
              <button
                onClick={() => toggleExpand(index)}
                className="w-full px-4 py-3 flex items-center gap-3 hover:bg-slate-700/20 transition-colors text-left"
              >
                {isExpanded ? (
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-400" />
                )}
                <span className={`px-2 py-0.5 text-xs font-mono font-medium rounded border ${getSeverityColor(violation.severity)}`}>
                  {violation.rule_id}
                </span>
                <span className="flex-1 text-sm text-slate-300 truncate">
                  {violation.description}
                </span>
                {violation.line && (
                  <span className="text-xs text-slate-500 font-mono">
                    line {violation.line}
                  </span>
                )}
              </button>
              {isExpanded && (
                <div className="px-4 pb-3 pl-11 space-y-2 animate-fade-in">
                  {violation.evidence && (
                    <div className="p-2 bg-slate-800/50 rounded-lg font-mono text-xs text-slate-300">
                      {violation.evidence}
                    </div>
                  )}
                  {policy?.fix_suggestion && (
                    <div className="flex items-start gap-2 text-sm">
                      <Info className="w-4 h-4 text-cyan-400 mt-0.5" />
                      <span className="text-slate-400">
                        <span className="text-cyan-400 font-medium">Fix:</span> {policy.fix_suggestion}
                      </span>
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
  copied 
}: { 
  proof: ProofBundle;
  onCopy: () => void;
  copied: boolean;
}) {
  return (
    <div className="glass rounded-2xl overflow-hidden border border-acpg-500/30 glow-green animate-slide-in">
      <div className="px-4 py-3 border-b border-acpg-500/20 flex items-center justify-between bg-acpg-500/10">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-5 h-5 text-acpg-400" />
          <span className="font-medium text-acpg-400">Proof Bundle Generated</span>
        </div>
        <button
          onClick={onCopy}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-acpg-500/20 hover:bg-acpg-500/30 text-acpg-400 rounded-lg transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-4 h-4" />
              Copied!
            </>
          ) : (
            <>
              <Copy className="w-4 h-4" />
              Copy JSON
            </>
          )}
        </button>
      </div>
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Artifact Hash</div>
            <div className="font-mono text-slate-300 truncate">{proof.artifact.hash.slice(0, 16)}...</div>
          </div>
          <div>
            <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Decision</div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-acpg-400" />
              <span className="text-acpg-400 font-medium">{proof.decision}</span>
            </div>
          </div>
          <div>
            <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Signer</div>
            <div className="text-slate-300">{proof.signed.signer}</div>
          </div>
          <div>
            <div className="text-slate-500 text-xs uppercase tracking-wider mb-1">Algorithm</div>
            <div className="text-slate-300">{proof.signed.algorithm}</div>
          </div>
        </div>
        <div className="pt-2 border-t border-slate-700/50">
          <div className="text-slate-500 text-xs uppercase tracking-wider mb-2">Policies Checked</div>
          <div className="flex flex-wrap gap-2">
            {proof.policies.map((p, i) => (
              <span 
                key={i}
                className={`px-2 py-1 text-xs font-mono rounded ${
                  p.result === 'satisfied' 
                    ? 'bg-acpg-500/20 text-acpg-400' 
                    : 'bg-red-500/20 text-red-400'
                }`}
              >
                {p.id}
              </span>
            ))}
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
    <div className="glass rounded-2xl overflow-hidden border border-slate-700/50">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-700/20 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Info className="w-5 h-5 text-cyan-400" />
          <span className="font-medium text-slate-200">Policy Reference</span>
          <span className="px-2 py-0.5 text-xs font-medium bg-slate-700 text-slate-300 rounded-full">
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
        <div className="border-t border-slate-700/50 max-h-[250px] overflow-y-auto animate-fade-in">
          {policies.map((policy, index) => (
            <div 
              key={index}
              className="px-4 py-3 border-b border-slate-700/30 last:border-b-0 hover:bg-slate-700/10"
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm font-medium text-cyan-400">{policy.id}</span>
                <span className={`px-1.5 py-0.5 text-xs rounded ${
                  policy.type === 'strict' 
                    ? 'bg-red-500/20 text-red-400' 
                    : 'bg-amber-500/20 text-amber-400'
                }`}>
                  {policy.type}
                </span>
                <span className={`px-1.5 py-0.5 text-xs rounded ${
                  policy.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  policy.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  policy.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' :
                  'bg-slate-500/20 text-slate-400'
                }`}>
                  {policy.severity}
                </span>
              </div>
              <p className="text-sm text-slate-400">{policy.description}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

