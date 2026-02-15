import { useState, useCallback, useEffect, useRef } from 'react';
import {
  RefreshCw,
  AlertTriangle, CheckCircle2, XCircle, Info,
  Check,
  Bot,
  Plus, Edit2,
  Trash2
} from 'lucide-react';
import { MODEL_TEST_TIMEOUT_SECONDS, formatMsSeconds } from '../utils/formatting';

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

export default function ModelsConfigurationView() {
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
