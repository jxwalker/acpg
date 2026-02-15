import { useState, useEffect } from 'react';
import {
  RefreshCw,
  AlertTriangle,
  Link2, Plus
} from 'lucide-react';

export default 
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
