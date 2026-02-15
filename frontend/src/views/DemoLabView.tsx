import { useState, useCallback, useEffect, useRef } from 'react';
import { Terminal } from 'lucide-react';
import type { SemanticsMode, ManagedTestCase } from '../types';

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
  const [proofGenCode, setProofGenCode] = useState(currentCode);
  const [proofGenLanguage, setProofGenLanguage] = useState('python');
  const [proofGenerating, setProofGenerating] = useState(false);

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

  const generateProof = useCallback(async () => {
    if (!proofGenCode.trim()) {
      setProofsError('Enter code to generate a proof for.');
      return;
    }
    setProofGenerating(true);
    setProofsError(null);
    try {
      const response = await fetch('/api/v1/proof/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: proofGenCode,
          language: proofGenLanguage,
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Proof generation failed');
      }
      await loadProofRegistry();
      const hash = payload.artifact?.hash as string | undefined;
      if (hash) {
        await loadProofBundle(hash);
      }
    } catch (err) {
      setProofsError(err instanceof Error ? err.message : 'Proof generation failed');
    } finally {
      setProofGenerating(false);
    }
  }, [loadProofBundle, loadProofRegistry, proofGenCode, proofGenLanguage]);

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
        <div className="space-y-4">
        <p className="text-sm text-slate-400">Simulate runtime events (tool execution, network calls, filesystem operations) and evaluate them against governance rules. Pick an event type, fill in the details, and click Evaluate to see the allow/deny decision.</p>
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
                <p className="text-sm text-slate-500">Configure an event above and click Evaluate to see the allow/deny decision with matched rule details here.</p>
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
                  {runtimeRules.length === 0 && <p className="text-sm text-slate-500">No runtime policy rules loaded. Click Refresh Rules to load from the policy configuration file.</p>}
                </div>
              )}
            </div>
          </div>
        </div>
        </div>
      )}

      {activeTab === 'batch' && (
        <div className="space-y-4">
        <p className="text-sm text-slate-400">Select stored test cases and run them through the analysis pipeline in bulk. Compare compliance outcomes, violation counts, and risk scores across multiple code samples at once.</p>
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
                  {batchCases.length === 0 && <p className="text-sm text-slate-500">No test cases stored yet. Add test cases from the main editor or import them via the API to run batch analysis.</p>}
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
              <p className="text-sm text-slate-500">Select test cases on the left and click Run Batch to compare compliance outcomes, violation counts, and risk scores here.</p>
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
        </div>
      )}

      {activeTab === 'graph' && (
        <div className="space-y-4">
        <p className="text-sm text-slate-400">Inspect the ACPG compliance workflow graph, paste code, and stream a live enforcement run. Watch agent events as the prosecutor, adjudicator, and generator loop executes in real time.</p>
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
                  <pre className="text-xs text-slate-400 font-mono bg-slate-900/70 border border-slate-700 rounded-lg p-4 overflow-x-auto mb-3 leading-relaxed">
                    {graphDefinition
                      ? graphDefinition.replace(/^\n+/, '').replace(/\n\s*$/, '')
                          .split('\n').map(l => l.startsWith('    ') ? l.slice(4) : l).join('\n')
                      : 'Graph definition unavailable. Click Refresh Graph to reload the ACPG workflow structure.'}
                  </pre>
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
                  <p className="text-sm text-slate-500">Paste code on the left and click Start Stream to watch prosecutor, adjudicator, and generator events execute here in real time.</p>
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
        </div>
      )}

      {activeTab === 'proofs' && (
        <div className="space-y-4">
        <p className="text-sm text-slate-400">Browse stored cryptographic proof bundles — signed compliance certificates generated after each analysis. Select any proof to inspect its full JSON payload including decision, signature, and evidence.</p>
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
                {proofs.length === 0 && <p className="text-sm text-slate-500">No compliance proofs stored yet. Use the form below to generate and store a cryptographically signed proof bundle.</p>}
              </div>
            )}

            <div className="border-t border-slate-700/60 pt-4 space-y-3">
              <h4 className="text-sm font-semibold text-white">Generate &amp; Store Proof</h4>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Language</label>
                <select
                  value={proofGenLanguage}
                  onChange={(e) => setProofGenLanguage(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-800/70 border border-slate-700 rounded-lg text-white"
                >
                  <option value="python">python</option>
                  <option value="javascript">javascript</option>
                  <option value="typescript">typescript</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Code</label>
                <textarea
                  value={proofGenCode}
                  onChange={(e) => setProofGenCode(e.target.value)}
                  className="w-full h-36 px-3 py-2 bg-slate-900/70 border border-slate-700 rounded-lg text-white font-mono text-xs"
                />
              </div>
              <button
                onClick={() => void generateProof()}
                disabled={proofGenerating}
                className="w-full py-2.5 bg-cyan-500/20 text-cyan-300 rounded-lg border border-cyan-500/30 hover:bg-cyan-500/30 disabled:opacity-50"
              >
                {proofGenerating ? 'Generating proof...' : 'Generate & Store Proof'}
              </button>
            </div>

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
              <p className="text-sm text-slate-500">Select a proof from the registry to inspect its signed bundle — including decision, evidence chain, argumentation, and ECDSA signature.</p>
            ) : (
              <pre className="text-xs text-slate-300 bg-slate-900/70 border border-slate-700 rounded-lg p-4 overflow-auto max-h-[34rem]">
                {JSON.stringify(selectedProof, null, 2)}
              </pre>
            )}
          </div>
        </div>
        </div>
      )}

      {activeTab === 'dynamic' && (
        <div className="space-y-4">
        <p className="text-sm text-slate-400">Browse dynamic analysis replay artifacts — runtime test executions captured during compliance analysis. Filter by suite, violation rule, or compliance status to find specific records.</p>
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
                <p className="text-sm text-slate-500">No replay artifacts match the current filters. Adjust the suite, rule, or status filters above, or click Refresh to reload.</p>
              )}
            </div>
          </div>
        </div>
        </div>
      )}
    </div>
  );
}

export default DemoLabView;
