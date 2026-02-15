import { useState, useEffect, useRef } from 'react';
import { DiffEditor } from '@monaco-editor/react';
import {
  RefreshCw, XCircle,
  Search, FileCheck, Sparkles,
  Clock, Upload, Download,
  Trash2, Eye,
  Plus, Edit2
} from 'lucide-react';
import type { PolicyRule, PolicyHistoryEntry, PolicyDiffResponse } from '../types';

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

export default 
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
