import React, { useState } from "react";
import {
  Lock,
  AlertTriangle,
  Play,
  RotateCw,
  Copy,
  Check,
  ShieldCheck,
  Key,
} from "lucide-react";
import { Finding, Target } from "../types";

interface TlsCryptographyViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const TlsCryptographyView: React.FC<TlsCryptographyViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [hostInput, setHostInput] = useState("");
  const [portInput, setPortInput] = useState("443");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [cryptoScore, setCryptoScore] = useState<number | null>(null);
  const [tlsVersion, setTlsVersion] = useState<string | null>(null);
  const [cipher, setCipher] = useState<any | null>(null);
  const [certificate, setCertificate] = useState<any | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleInspectTls = async () => {
    const targetHost = hostInput.trim() || selectedTarget.trim();
    if (!targetHost) {
      setErrorMsg("Please specify a target hostname or choose an authorized target.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setCryptoScore(null);
    setTlsVersion(null);
    setCipher(null);
    setCertificate(null);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("tls-cryptography", targetHost, {
        hostname: targetHost,
        port: parseInt(portInput, 10) || 443,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setCryptoScore(res.payload.crypto_score ?? 100);
          setTlsVersion(res.payload.tls_version || "Unknown");
          setCipher(res.payload.cipher || null);
          setCertificate(res.payload.certificate || null);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "TLS inspection rejected by Host.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute TLS cryptography inspection.");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800/50 text-emerald-400">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                TLS & Cryptography Inspector
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-900/40 text-emerald-400 border border-emerald-700/40">
                  CIPHER SUITES & CERTIFICATES
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Audit TLS protocol versions, active cipher suites, certificate chains, and weak cryptographic primitives.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Control Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Key className="w-4 h-4 text-emerald-400" />
          TLS Endpoint Parameters
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-5">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Hostname or Domain
            </label>
            <input
              type="text"
              value={hostInput}
              onChange={(e) => setHostInput(e.target.value)}
              placeholder="e.g. secure.domain.com"
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Port
            </label>
            <input
              type="number"
              value={portInput}
              onChange={(e) => setPortInput(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500 font-mono"
            />
          </div>

          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Or Choose Authorized Target
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
            >
              <option value="">-- Choose Target --</option>
              {authorizedTargets.map((t) => (
                <option key={t.id} value={t.target_value}>
                  {t.name} ({t.target_value})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2 flex items-end">
            <button
              onClick={handleInspectTls}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-medium px-4 py-2 rounded-lg transition-all shadow-md shadow-emerald-900/30 disabled:opacity-50 text-sm"
            >
              {loading ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Auditing...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Inspect TLS
                </>
              )}
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center gap-3 text-red-300 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Results */}
      {cryptoScore !== null && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Score Card */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Cryptographic Strength Score
              </span>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold px-3 py-1 rounded-lg border font-mono ${
                  cryptoScore >= 80
                    ? "text-emerald-400 bg-emerald-950/40 border-emerald-800/60"
                    : cryptoScore >= 50
                    ? "text-amber-400 bg-amber-950/40 border-amber-800/60"
                    : "text-red-400 bg-red-950/40 border-red-800/60"
                }`}>
                  {cryptoScore}
                </span>
                <span className="text-slate-400 text-sm font-mono">/ 100</span>
              </div>

              <div className="mt-4 space-y-2">
                <div className="text-xs text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg flex items-center justify-between">
                  <span className="text-slate-400">Negotiated Protocol:</span>
                  <span className="font-mono text-emerald-400 font-semibold">{tlsVersion}</span>
                </div>
                {cipher && (
                  <div className="text-xs text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg">
                    <span className="text-slate-400 block mb-1">Cipher Suite:</span>
                    <span className="font-mono text-slate-200 break-all">{cipher.name}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              NIST SP 800-52r2 Compliance Check
            </div>
          </div>

          {/* Certificate Card */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Key className="w-4 h-4 text-emerald-400" />
              X.509 Certificate Profile
            </h3>
            {certificate ? (
              <div className="space-y-3 font-mono text-xs">
                <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                  <span className="text-slate-400 block text-[10px] uppercase font-bold">Issuer Organization</span>
                  <span className="text-slate-200">{certificate.issuer?.organizationName || "Unknown / Self-Signed"}</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-bold">Valid From</span>
                    <span className="text-slate-300">{certificate.notBefore || "N/A"}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-bold">Expires On</span>
                    <span className="text-slate-300">{certificate.notAfter || "N/A"}</span>
                  </div>
                </div>
                {certificate.san && certificate.san.length > 0 && (
                  <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                    <span className="text-slate-400 block text-[10px] uppercase font-bold mb-1">Subject Alternative Names (SANs)</span>
                    <div className="flex flex-wrap gap-1.5">
                      {certificate.san.map((s: string, idx: number) => (
                        <span key={idx} className="bg-slate-800 px-2 py-0.5 rounded text-[11px] text-slate-300">
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic">No certificate details extracted.</p>
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Cryptographic Weaknesses ({findings.length})
          </h3>
          <div className="space-y-3">
            {findings.map((f, idx) => (
              <div
                key={f.id || idx}
                className="p-4 rounded-lg bg-[#0b0f19] border border-red-900/40 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-xs font-bold uppercase bg-red-950 text-red-400 border border-red-800">
                      {f.severity}
                    </span>
                    <h4 className="font-semibold text-sm text-white">{f.title}</h4>
                  </div>
                  {f.cwe && (
                    <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                      {f.cwe}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>
                {f.evidence && (
                  <div className="text-xs font-mono text-slate-400 bg-black/40 p-2 rounded border border-slate-800">
                    <strong>Evidence:</strong> {f.evidence}
                  </div>
                )}
                {f.remediation && (
                  <div className="text-xs text-emerald-400 bg-emerald-950/20 border border-emerald-900/30 p-2 rounded">
                    <strong>Remediation:</strong> {f.remediation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw Output */}
      {rawOutput && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">Raw TLS Handshake Log</span>
            <button
              onClick={() => copyToClipboard(rawOutput)}
              className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <pre className="bg-[#0b0f19] border border-slate-800 rounded p-3 text-xs font-mono text-slate-300 overflow-x-auto max-h-60">
            {rawOutput}
          </pre>
        </div>
      )}
    </div>
  );
};
