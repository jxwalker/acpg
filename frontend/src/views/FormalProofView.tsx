import { useState } from 'react';
import {
  ShieldCheck, ShieldAlert,
  ChevronDown, ChevronRight,
  Scale, BookOpen
} from 'lucide-react';
import type { ProofBundle } from '../types';
import { safeArray, safeObject, safeText, normalizeRuntimePolicyEvents, describeRuntimeAction } from '../utils/safe-helpers';

function ArgumentationGraphVisual({ proof }: { proof: ProofBundle }) {
  const argumentation = safeObject(proof?.argumentation);
  const args = safeArray<any>(argumentation.arguments);
  const attacks = safeArray<any>(argumentation.attacks);
  const groundedExtension = safeObject(argumentation.grounded_extension);
  const accepted = new Set(safeArray<string>(groundedExtension.accepted));

  if (args.length === 0 && attacks.length === 0) {
    return null;
  }

  // Group arguments by type
  const complianceArgs = args.filter((a: any) => a.type === 'compliance');
  const violationArgs = args.filter((a: any) => a.type === 'violation');
  const otherArgs = args.filter((a: any) => a.type !== 'compliance' && a.type !== 'violation');

  return (
    <div className="glass rounded-2xl p-6 border border-white/5">
      <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
        <Scale className="w-5 h-5 text-violet-400" />
        Argumentation Graph
      </h3>

      <div className="grid grid-cols-3 gap-6">
        {/* Compliance Arguments */}
        <div>
          <h4 className="text-sm font-semibold text-emerald-400 mb-3 uppercase tracking-wider">
            Compliance ({complianceArgs.length})
          </h4>
          <div className="space-y-2">
            {complianceArgs.map((arg: any, i: number) => (
              <div
                key={i}
                className={`p-3 rounded-lg border ${
                  accepted.has(arg.id)
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-slate-800/50 border-slate-700/50 opacity-60'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`font-mono text-sm ${
                    accepted.has(arg.id) ? 'text-emerald-400' : 'text-slate-500'
                  }`}>
                    {safeText(arg.id, '?')}
                  </span>
                  <span className={`text-xs ${
                    accepted.has(arg.id) ? 'text-emerald-300' : 'text-slate-500'
                  }`}>
                    {accepted.has(arg.id) ? 'accepted' : 'rejected'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 truncate">{safeText(arg.details, '')}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Relations */}
        <div>
          <h4 className="text-sm font-semibold text-orange-400 mb-3 uppercase tracking-wider">
            Attacks ({attacks.length})
          </h4>
          <div className="space-y-2">
            {attacks.map((attack: any, i: number) => (
              <div
                key={i}
                className={`p-3 rounded-lg border ${
                  attack.effective
                    ? 'bg-orange-500/10 border-orange-500/30'
                    : 'bg-slate-800/50 border-slate-700/50 opacity-60'
                }`}
              >
                <div className="flex items-center gap-2 text-sm">
                  <span className="font-mono text-slate-300">{safeText(attack.relation, '? -> ?')}</span>
                  <span className={`text-xs ${attack.effective ? 'text-orange-400' : 'text-slate-500'}`}>
                    {attack.effective ? 'effective' : 'blocked'}
                  </span>
                </div>
                {attack.explanation && (
                  <p className="text-xs text-slate-400 mt-1 truncate">{safeText(attack.explanation, '')}</p>
                )}
              </div>
            ))}
            {otherArgs.length > 0 && (
              <div className="mt-4">
                <h5 className="text-xs text-slate-500 uppercase tracking-wider mb-2">Other ({otherArgs.length})</h5>
                {otherArgs.map((arg: any, i: number) => (
                  <div key={i} className="p-2 bg-slate-800/50 rounded border border-slate-700/50 mb-1">
                    <span className="font-mono text-xs text-slate-400">{safeText(arg.id, '?')}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Violation Arguments */}
        <div>
          <h4 className="text-sm font-semibold text-red-400 mb-3 uppercase tracking-wider">
            Violations ({violationArgs.length})
          </h4>
          <div className="space-y-2">
            {violationArgs.map((arg: any, i: number) => (
              <div
                key={i}
                className={`p-3 rounded-lg border ${
                  accepted.has(arg.id)
                    ? 'bg-red-500/10 border-red-500/30'
                    : 'bg-slate-800/50 border-slate-700/50 opacity-60'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`font-mono text-sm ${
                    accepted.has(arg.id) ? 'text-red-400' : 'text-slate-500'
                  }`}>
                    {safeText(arg.id, '?')}
                  </span>
                  <span className={`text-xs ${
                    accepted.has(arg.id) ? 'text-red-300' : 'text-slate-500'
                  }`}>
                    {accepted.has(arg.id) ? 'accepted' : 'rejected'}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-1 truncate">{safeText(arg.details, '')}</p>
                {arg.evidence && (
                  <p className="text-xs text-slate-500 mt-1 truncate">Evidence: {safeText(arg.evidence, '')}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FormalProofView({ proof }: { proof: ProofBundle }) {
  const [expandedSteps, setExpandedSteps] = useState<Record<number, boolean>>({ 1: true, 5: true });
  const argumentation = safeObject(proof?.argumentation);

  const toggleStep = (step: number) => {
    setExpandedSteps(prev => ({ ...prev, [step]: !prev[step] }));
  };

  // Extract reasoning steps from the proof
  const reasoningTrace = safeArray<any>(argumentation.reasoning_trace);
  const reasoningSteps = reasoningTrace.filter((item: any) => item && item.step !== undefined);

  // Extract legacy format data
  const proofArguments = safeArray<any>(argumentation.arguments);
  const proofAttacks = safeArray<any>(argumentation.attacks);
  const groundedExtension = safeObject(argumentation.grounded_extension);
  const summary = safeObject(argumentation.summary);
  const groundedAccepted = safeArray<string>(groundedExtension.accepted);
  const groundedRejected = safeArray<string>(groundedExtension.rejected);
  const totalArguments = (
    typeof summary.total_arguments === 'number'
      ? summary.total_arguments
      : proofArguments.length
  );
  const hasFormalPayload = (
    reasoningSteps.length > 0
    || proofArguments.length > 0
    || proofAttacks.length > 0
    || groundedAccepted.length > 0
    || groundedRejected.length > 0
  );

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
            <div className="text-white font-semibold">{totalArguments}</div>
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

      {!hasFormalPayload && (
        <div className="glass rounded-2xl p-6 border border-amber-500/30 bg-amber-500/10">
          <div className="text-amber-300 font-semibold">Formal proof data is unavailable for this bundle.</div>
          <p className="text-sm text-slate-300 mt-2">
            The proof bundle is valid, but argumentation details were missing or in a legacy format.
          </p>
        </div>
      )}

      {/* Plain English Explanation */}
      {argumentation.explanation && (
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
            <p className="text-slate-200">
              {safeText(safeObject(argumentation.explanation).summary, 'No summary available.')}
            </p>
          </div>

          {/* What happened for each violation */}
          {safeArray<any>(safeObject(argumentation.explanation).what_happened).length > 0 && (
            <div className="space-y-3 mb-4">
              <h4 className="text-sm font-semibold text-slate-300">Policy And Runtime Evidence Explained:</h4>
              {safeArray<any>(safeObject(argumentation.explanation).what_happened).map((item: any, i: number) => (
                (() => {
                  const policyId = safeText(item.policy, 'unknown-policy');
                  const resultLabel = safeText(item.result, 'UNKNOWN');
                  const isRuntimePolicy = policyId === 'RUNTIME-POLICY';
                  const runtimeEvents = isRuntimePolicy ? normalizeRuntimePolicyEvents(item.evidence) : [];
                  const cardClass = isRuntimePolicy
                    ? 'p-4 bg-cyan-500/5 rounded-xl border border-cyan-500/20'
                    : 'p-4 bg-red-500/5 rounded-xl border border-red-500/20';
                  const badgeClass = isRuntimePolicy
                    ? 'px-2 py-1 bg-cyan-500/20 text-cyan-300 text-xs font-mono rounded'
                    : 'px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded';
                  const resultClass = isRuntimePolicy ? 'text-cyan-300 font-semibold' : 'text-red-400 font-semibold';

                  return (
                <div key={i} className={cardClass}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className={badgeClass}>
                      {policyId}
                    </span>
                    <span className={resultClass}>{resultLabel}</span>
                  </div>
                  <p className="text-sm text-slate-300 mb-2">{safeText(item.explanation, 'No explanation provided.')}</p>

                  {isRuntimePolicy && (
                    <div className="mb-2 p-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 text-xs text-slate-300">
                      <p>This is runtime governance evidence, not a direct static-code violation.</p>
                      <p className="mt-1">
                        It records policy decisions about tool execution (allow, deny, monitoring, approval) and is included in the proof for audit traceability.
                      </p>
                    </div>
                  )}

                  {isRuntimePolicy && runtimeEvents.length > 0 ? (
                    <div className="space-y-2">
                      {runtimeEvents.map((event, idx) => (
                        <div key={`${event.tool}-${event.action}-${idx}`} className="text-xs text-slate-300 bg-slate-900/50 px-3 py-2 rounded border border-cyan-500/20">
                          <div className="flex flex-wrap gap-2">
                            <span className="font-mono text-cyan-300">{event.tool}</span>
                            <span className="text-slate-500">•</span>
                            <span>{describeRuntimeAction(event.action)}</span>
                            {event.allowed !== undefined && (
                              <>
                                <span className="text-slate-500">•</span>
                                <span>{event.allowed ? 'execution permitted' : 'execution blocked'}</span>
                              </>
                            )}
                          </div>
                          {event.rule_id && (
                            <p className="mt-1 text-slate-400">Rule: <span className="font-mono">{event.rule_id}</span></p>
                          )}
                          {event.message && (
                            <p className="mt-1 text-slate-400">{event.message}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : item.evidence ? (
                    <div className="text-xs text-slate-400 font-mono bg-slate-900/50 px-3 py-2 rounded">
                      Evidence: {safeText(item.evidence, 'n/a')}
                    </div>
                  ) : null}
                </div>
                  );
                })()
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
              {Object.entries(safeObject(safeObject(argumentation.explanation).terminology)).map(([term, def]: [string, any]) => (
                <div key={term} className="p-2 bg-slate-800/50 rounded-lg">
                  <span className="font-mono text-cyan-400 text-sm">{term}</span>
                  <p className="text-xs text-slate-400 mt-1">{safeText(def, 'n/a')}</p>
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
                  <h3 className="text-lg font-semibold text-white">{safeText(step.title, `Step ${step.step}`)}</h3>
                  <p className="text-sm text-slate-400">{safeText(step.description, '')}</p>
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
                        {safeArray<string>(step.logic).map((rule: string, i: number) => (
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
                        {safeArray<string>(step.algorithm).map((line: string, i: number) => (
                          <div key={i} className="text-slate-300">{line}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Arguments by type */}
                  {step.arguments && (
                    <div className="mt-4 grid grid-cols-2 gap-4">
                      {safeArray<any>(safeObject(step.arguments).compliance).length > 0 && (
                        <div className="p-4 bg-emerald-500/5 rounded-xl border border-emerald-500/20">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Compliance Arguments ({safeArray<any>(safeObject(step.arguments).compliance).length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {safeArray<any>(safeObject(step.arguments).compliance).map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-emerald-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-emerald-400' : 'text-slate-500'
                                }`}>{safeText(arg.id, 'unknown')}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-emerald-300' : 'text-slate-500'
                                }`}>({safeText(arg.status, 'unknown')})</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {safeArray<any>(safeObject(step.arguments).violation).length > 0 && (
                        <div className="p-4 bg-red-500/5 rounded-xl border border-red-500/20">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violation Arguments ({safeArray<any>(safeObject(step.arguments).violation).length})
                          </div>
                          <div className="space-y-2 max-h-40 overflow-y-auto">
                            {safeArray<any>(safeObject(step.arguments).violation).map((arg: any, i: number) => (
                              <div key={i} className={`p-2 rounded-lg text-xs ${
                                arg.status === 'accepted' ? 'bg-red-500/10' : 'bg-slate-800/50'
                              }`}>
                                <span className={`font-mono font-semibold ${
                                  arg.status === 'accepted' ? 'text-red-400' : 'text-slate-500'
                                }`}>{safeText(arg.id, 'unknown')}</span>
                                <span className={`ml-2 ${
                                  arg.status === 'accepted' ? 'text-red-300' : 'text-slate-500'
                                }`}>({safeText(arg.status, 'unknown')})</span>
                                {arg.evidence && (
                                  <div className="mt-1 text-slate-400 truncate">Evidence: {safeText(arg.evidence, 'n/a')}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Attacks */}
                  {safeArray<any>(step.attacks).length > 0 && (
                    <div className="mt-4 p-4 bg-orange-500/5 rounded-xl border border-orange-500/20">
                      <div className="text-xs text-orange-400 uppercase tracking-wider mb-2">
                        Attack Relations ({safeArray<any>(step.attacks).length})
                      </div>
                      <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                        {safeArray<any>(step.attacks).map((attack: any, i: number) => (
                          <div key={i} className={`p-2 rounded-lg text-xs flex items-center gap-2 ${
                            attack.effective ? 'bg-orange-500/10' : 'bg-slate-800/50'
                          }`}>
                            <span className="font-mono text-slate-300">{safeText(attack.attacker, '?')}</span>
                            <span className={attack.effective ? 'text-orange-400' : 'text-slate-500'}>→</span>
                            <span className="font-mono text-slate-300">{safeText(attack.target, '?')}</span>
                            <span className={`ml-auto ${attack.effective ? 'text-orange-400' : 'text-slate-500'}`}>
                              {attack.effective ? '✓' : '✗'}
                            </span>
                          </div>
                        ))}
                      </div>
                      {safeArray<any>(step.attacks).some((a: any) => a.reason) && (
                        <div className="mt-3 pt-3 border-t border-orange-500/20">
                          {safeArray<any>(step.attacks).filter((a: any) => a.reason).slice(0, 3).map((attack: any, i: number) => (
                            <div key={i} className="text-xs text-slate-400 mb-1">
                              <span className="text-orange-400">
                                {safeText(attack.attacker, '?')} → {safeText(attack.target, '?')}:
                              </span>{' '}
                              {safeText(attack.reason, '')}
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
                          {safeArray<string>(safeObject(step.result).accepted).map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                              {safeText(id, '?')}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                        <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">
                          Rejected ({step.result.rejected_count})
                        </div>
                        <div className="flex flex-wrap gap-1 max-h-24 overflow-y-auto">
                          {safeArray<string>(safeObject(step.result).rejected).map((id: string, i: number) => (
                            <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                              {safeText(id, '?')}
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
                          {safeText(step.decision, 'UNKNOWN')}
                        </div>
                      </div>
                      <p className="text-sm text-slate-300">{safeText(step.reasoning, '')}</p>

                      {safeArray<string>(step.satisfied_policies).length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-emerald-400 uppercase tracking-wider mb-2">
                            Satisfied Policies ({safeArray<string>(step.satisfied_policies).length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {safeArray<string>(step.satisfied_policies).map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                                {safeText(id, '?')}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {safeArray<string>(step.violated_policies).length > 0 && (
                        <div className="mt-3 pt-3 border-t border-white/10">
                          <div className="text-xs text-red-400 uppercase tracking-wider mb-2">
                            Violated Policies ({safeArray<string>(step.violated_policies).length})
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {safeArray<string>(step.violated_policies).map((id: string, i: number) => (
                              <span key={i} className="px-2 py-1 bg-red-500/20 text-red-400 text-xs font-mono rounded">
                                {safeText(id, '?')}
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
                        {safeText(arg.id, 'unknown')}
                      </span>
                      <span className={`px-2 py-0.5 text-xs rounded ${
                        arg.type === 'compliance' ? 'bg-emerald-500/20 text-emerald-400' :
                        arg.type === 'violation' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {safeText(arg.type, 'unknown')}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 truncate">{safeText(arg.details, '')}</p>
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
                    <span className="font-mono text-slate-300">{safeText(attack.relation, '?')}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Grounded Extension */}
          {(groundedAccepted.length > 0 || groundedRejected.length > 0) && (
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-emerald-500/10 rounded-xl border border-emerald-500/30">
                <div className="text-xs text-emerald-300 uppercase tracking-wider mb-2">Accepted</div>
                <div className="flex flex-wrap gap-1">
                  {groundedAccepted.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-emerald-500/20 text-emerald-400 text-xs font-mono rounded">
                      {safeText(id, '?')}
                    </span>
                  ))}
                </div>
              </div>
              <div className="p-4 bg-slate-800/50 rounded-xl border border-slate-700/50">
                <div className="text-xs text-slate-400 uppercase tracking-wider mb-2">Rejected</div>
                <div className="flex flex-wrap gap-1">
                  {groundedRejected.map((id: string, i: number) => (
                    <span key={i} className="px-2 py-1 bg-slate-700 text-slate-400 text-xs font-mono rounded">
                      {safeText(id, '?')}
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
