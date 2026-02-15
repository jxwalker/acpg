import { useState, useRef } from 'react';
import {
  Shield, ShieldCheck, ShieldAlert,
  RefreshCw, FileCode,
  AlertTriangle,
  Upload, Download,
  Fingerprint
} from 'lucide-react';
import { api } from '../api';

export default function ProofVerifier() {
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

  const handleExportProof = async (format: string = 'json') => {
    if (!proofJson) return;
    try {
      const proofBundle = JSON.parse(proofJson);
      const response = await api.exportProof(proofBundle, format);
      const content = response.content;

      // Determine file extension and MIME type
      let extension = 'json';
      let mimeType = 'application/json';
      if (format === 'markdown') {
        extension = 'md';
        mimeType = 'text/markdown';
      } else if (format === 'html') {
        extension = 'html';
        mimeType = 'text/html';
      } else if (format === 'summary') {
        extension = 'txt';
        mimeType = 'text/plain';
      }

      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `proof_bundle.${extension}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Export failed:', error);
      setError('Export failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
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

              {/* Export Options */}
              <div className="p-4 bg-slate-800/50 rounded-xl">
                <h5 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                  <Download className="w-4 h-4" />
                  Export Proof Bundle
                </h5>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => handleExportProof('json')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    JSON
                  </button>
                  <button
                    onClick={() => handleExportProof('markdown')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Markdown
                  </button>
                  <button
                    onClick={() => handleExportProof('html')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    HTML
                  </button>
                  <button
                    onClick={() => handleExportProof('summary')}
                    disabled={!proofJson}
                    className="px-3 py-2 text-sm bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 flex items-center gap-2"
                  >
                    <Download className="w-4 h-4" />
                    Summary
                  </button>
                </div>
              </div>

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
