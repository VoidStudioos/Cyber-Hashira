import React, { useState } from "react";
import {
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCw,
  ExternalLink,
  Copy,
  Check,
  Layers,
} from "lucide-react";
import { Finding, Target } from "../types";

interface ThreatIntelligenceViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const ThreatIntelligenceView: React.FC<ThreatIntelligenceViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [iocInput, setIocInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [threatScore, setThreatScore] = useState<number | null>(null);
  const [reputation, setReputation] = useState<string | null>(null);
  const [mitreTechniques, setMitreTechniques] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleEnrich = async () => {
    const targetToAssess = iocInput.trim() || selectedTarget.trim();
    if (!targetToAssess) {
      setErrorMsg("Please specify an Indicator of Compromise (IOC) or select an authorized target.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setThreatScore(null);
    setReputation(null);
    setMitreTechniques([]);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("threat-intelligence", targetToAssess, {
        ioc: targetToAssess,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setThreatScore(res.payload.threat_score ?? 0);
          setReputation(res.payload.reputation || "Analyzed");
          setMitreTechniques(res.payload.mitre_techniques || []);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "Intelligence query rejected by Host.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute threat intelligence task.");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-red-400 bg-red-950/40 border-red-800/60";
    if (score >= 50) return "text-amber-400 bg-amber-950/40 border-amber-800/60";
    if (score >= 20) return "text-yellow-400 bg-yellow-950/40 border-yellow-800/60";
    return "text-emerald-400 bg-emerald-950/40 border-emerald-800/60";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
              <Radar className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Threat Intelligence & MITRE ATT&CK
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-400 border border-cyan-700/40">
                  ENTERPRISE v14
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                IOC enrichment, malicious file hash matching, domain reputation scoring, and ATT&CK tactic correlation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Query Control Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Search className="w-4 h-4 text-cyan-400" />
          Enrich Indicator of Compromise (IOC)
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-6">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Manual IOC Input (IP, Domain, MD5, SHA-256)
            </label>
            <input
              type="text"
              value={iocInput}
              onChange={(e) => setIocInput(e.target.value)}
              placeholder="e.g. 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="md:col-span-4">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Or Choose From Authorized Scope
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
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
              onClick={handleEnrich}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium px-4 py-2 rounded-lg transition-all shadow-md shadow-cyan-900/30 disabled:opacity-50 text-sm"
            >
              {loading ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Enriching...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Analyze IOC
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

      {/* Intelligence Assessment Results */}
      {threatScore !== null && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Reputation & Threat Score Card */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Threat Assessment Score
              </span>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold px-3 py-1 rounded-lg border font-mono ${getScoreColor(threatScore)}`}>
                  {threatScore}
                </span>
                <span className="text-slate-400 text-sm font-mono">/ 100</span>
              </div>
              <div className="mt-4">
                <span className="text-xs text-slate-400 block mb-1">Reputation Triage</span>
                <p className="text-sm font-semibold text-white bg-[#0b0f19] border border-slate-800 px-3 py-2 rounded-lg">
                  {reputation}
                </p>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              Verified with Cyber Hashira Offline Signatures
            </div>
          </div>

          {/* MITRE ATT&CK Matrix Techniques */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Correlated MITRE ATT&CK Techniques ({mitreTechniques.length})
            </h3>
            {mitreTechniques.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No specific ATT&CK technique triggered for this indicator.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {mitreTechniques.map((tech) => (
                  <div
                    key={tech.id}
                    className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800 hover:border-cyan-800 transition-colors"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
                        {tech.id}
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        Tactic: {tech.tactic}
                      </span>
                    </div>
                    <div className="text-sm font-medium text-white mt-1">
                      {tech.name}
                    </div>
                    {tech.url && (
                      <a
                        href={tech.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-cyan-400 hover:underline mt-2 inline-flex items-center gap-1"
                      >
                        MITRE ATT&CK Knowledgebase <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Discovered Security Findings */}
      {findings.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            Security Intelligence Findings ({findings.length})
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

      {/* Raw Intelligence Log */}
      {rawOutput && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">Raw Intelligence Output</span>
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
