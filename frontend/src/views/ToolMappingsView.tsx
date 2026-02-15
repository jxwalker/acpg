import { useState, useCallback, useEffect } from 'react';
import {
  RefreshCw,
  AlertTriangle, CheckCircle2, Info,
  Plus, Edit2,
  Save,
  Trash2, List
} from 'lucide-react';

export default 
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
