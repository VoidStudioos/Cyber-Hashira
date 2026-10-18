import React, { useState } from "react";
import {
  FileSearch,
  AlertTriangle,
  Play,
  RotateCw,
  Copy,
  Check,
  ShieldCheck,
  FileCode,
  Lock,
  Binary,
  Fingerprint,
} from "lucide-react";
import { Finding, Target } from "../types";

interface ForensicsViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const ForensicsView: React.FC<ForensicsViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [filePathInput, setFilePathInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [entropyThreshold, setEntropyThreshold] = useState("7.0");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [hashes, setHashes] = useState<any | null>(null);
  const [entropy, setEntropy] = useState<number | null>(null);
  const [isPacked, setIsPacked] = useState<boolean | null>(null);
  const [suspiciousIndicators, setSuspiciousIndicators] = useState<any[]>([]);
  const [chainOfCustody, setChainOfCustody] = useState<any | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleTriage = async () => {
    const targetFile = filePathInput.trim() || selectedTarget.trim();
    if (!targetFile) {
      setErrorMsg("Please specify a target file path or select an authorized target.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setHashes(null);
    setEntropy(null);
    setIsPacked(null);
    setSuspiciousIndicators([]);
    setChainOfCustody(null);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("digital-forensics", targetFile, {
        file_path: targetFile,
        entropy_threshold: parseFloat(entropyThreshold) || 7.0,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setHashes(res.payload.hashes || null);
          setEntropy(res.payload.entropy ?? 0);
          setIsPacked(res.payload.is_packed ?? false);
          setSuspiciousIndicators(res.payload.suspicious_indicators || []);
          setChainOfCustody(res.payload.chain_of_custody || null);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "Forensic triage failed.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute digital forensics task.");
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
            <div className="p-2.5 rounded-lg bg-indigo-950/60 border border-indigo-800/50 text-indigo-400">
              <FileSearch className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Digital Forensics & Malware Triage
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-indigo-900/40 text-indigo-400 border border-indigo-700/40">
                  SHANNON ENTROPY & INTEGRITY
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Cryptographic hashing, binary packing and obfuscation detection, suspicious string extraction, and immutable chain-of-custody.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Control Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Binary className="w-4 h-4 text-indigo-400" />
          Forensic Artifact Analysis
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-5">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Sample File Path
            </label>
            <input
              type="text"
              value={filePathInput}
              onChange={(e) => setFilePathInput(e.target.value)}
              placeholder="e.g. C:/evidence/malicious_payload.exe or /tmp/sample.bin"
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 font-mono"
            />
          </div>

          <div className="md:col-span-3">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Scope Target Target
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"
            >
              <option value="">-- Choose Target --</option>
              {authorizedTargets.map((t) => (
                <option key={t.id} value={t.target_value}>
                  {t.name} ({t.target_value})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Entropy Threshold
            </label>
            <input
              type="number"
              step="0.1"
              value={entropyThreshold}
              onChange={(e) => setEntropyThreshold(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 font-mono"
            />
          </div>

          <div className="md:col-span-2 flex items-end">
            <button
              onClick={handleTriage}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-500 hover:to-purple-500 text-white font-medium px-4 py-2 rounded-lg transition-all shadow-md shadow-indigo-900/30 disabled:opacity-50 text-sm"
            >
              {loading ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Triaging...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Analyze
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

      {/* Forensic Triage Results */}
      {entropy !== null && hashes && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Entropy & Packing Card */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Shannon Entropy Metric
              </span>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold px-3 py-1 rounded-lg border font-mono ${
                  entropy >= 7.0
                    ? "text-red-400 bg-red-950/40 border-red-800/60"
                    : "text-emerald-400 bg-emerald-950/40 border-emerald-800/60"
                }`}>
                  {entropy}
                </span>
                <span className="text-slate-400 text-sm font-mono">/ 8.0 bits/byte</span>
              </div>

              <div className="mt-4">
                <span className="text-xs text-slate-400 block mb-1">Binary Obfuscation Status</span>
                <div className={`p-3 rounded-lg border text-sm font-semibold flex items-center gap-2 ${
                  isPacked
                    ? "bg-red-950/30 border-red-800/50 text-red-300"
                    : "bg-emerald-950/30 border-emerald-800/50 text-emerald-300"
                }`}>
                  {isPacked ? (
                    <>
                      <Lock className="w-4 h-4 text-red-400 shrink-0" />
                      Packed / Encrypted Code Detected
                    </>
                  ) : (
                    <>
                      <FileCode className="w-4 h-4 text-emerald-400 shrink-0" />
                      Normal Unpacked Binary
                    </>
                  )}
                </div>
              </div>
            </div>

            {chainOfCustody && (
              <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                <div className="flex items-center gap-1.5 text-indigo-400 font-semibold mb-1">
                  <Fingerprint className="w-3.5 h-3.5" />
                  Chain of Custody Record
                </div>
                <div>ID: {chainOfCustody.custody_id.slice(0, 16)}...</div>
                <div>Acquired: {new Date(chainOfCustody.acquired_at).toLocaleTimeString()}</div>
              </div>
            )}
          </div>

          {/* Cryptographic Hashes Card */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-indigo-400" />
              Cryptographic Integrity Signatures
            </h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-bold">SHA-256</span>
                <span className="text-indigo-300 break-all">{hashes.sha256}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-bold">SHA-1</span>
                <span className="text-slate-300 break-all">{hashes.sha1}</span>
              </div>
              <div className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase font-bold">MD5</span>
                <span className="text-slate-300 break-all">{hashes.md5}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Suspicious Extracted Strings */}
      {suspiciousIndicators.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            Suspicious Indicators & Dynamic Primitives Discovered ({suspiciousIndicators.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {suspiciousIndicators.map((item, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800 hover:border-indigo-800 transition-colors"
              >
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/40 inline-block mb-1">
                  {item.category}
                </span>
                <div className="font-mono text-xs text-slate-200 break-all mt-1 bg-slate-900/60 p-2 rounded border border-slate-800/60">
                  {item.matched}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Forensic Findings ({findings.length})
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
            <span className="text-xs font-mono text-slate-400">Raw Forensic Triage Log</span>
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
