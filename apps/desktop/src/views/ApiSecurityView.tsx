import React, { useState } from "react";
import {
  Code2,
  AlertTriangle,
  Play,
  RotateCw,
  Copy,
  Check,
  ShieldCheck,
  Layers,
  Braces,
} from "lucide-react";
import { Finding, Target } from "../types";

interface ApiSecurityViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const ApiSecurityView: React.FC<ApiSecurityViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [endpointInput, setEndpointInput] = useState("");
  const [selectedTarget, setSelectedTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [securityScore, setSecurityScore] = useState<number | null>(null);
  const [analyzedEndpoints, setAnalyzedEndpoints] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleScanApi = async () => {
    const targetEndpoint = endpointInput.trim() || selectedTarget.trim();
    if (!targetEndpoint) {
      setErrorMsg("Please specify an API endpoint or choose an authorized target.");
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setSecurityScore(null);
    setAnalyzedEndpoints([]);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("api-security", targetEndpoint, {
        endpoint: targetEndpoint,
        simulate_vulnerabilities: true,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setSecurityScore(res.payload.security_score ?? 100);
          setAnalyzedEndpoints(res.payload.endpoints_analyzed || []);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "API scan rejected by Host.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute API security scan.");
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
            <div className="p-2.5 rounded-lg bg-teal-950/60 border border-teal-800/50 text-teal-400">
              <Code2 className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                API Security & Schema Assessment
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-teal-900/40 text-teal-400 border border-teal-700/40">
                  REST / GRAPHQL / OPENAPI
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Automated discovery of Swagger/OpenAPI blueprints, GraphQL introspection exposure, and Broken Object Level Authorization (BOLA).
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Control Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
          <Braces className="w-4 h-4 text-teal-400" />
          API Target Configuration
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-6">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Base URL or API Endpoint
            </label>
            <input
              type="text"
              value={endpointInput}
              onChange={(e) => setEndpointInput(e.target.value)}
              placeholder="e.g. https://api.target.com or /api/v1"
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500 font-mono"
            />
          </div>

          <div className="md:col-span-4">
            <label className="block text-xs font-medium text-slate-400 mb-1">
              Or Choose Authorized Target
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500"
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
              onClick={handleScanApi}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-teal-600 to-cyan-600 hover:from-teal-500 hover:to-cyan-500 text-white font-medium px-4 py-2 rounded-lg transition-all shadow-md shadow-teal-900/30 disabled:opacity-50 text-sm"
            >
              {loading ? (
                <>
                  <RotateCw className="w-4 h-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Audit API
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
      {securityScore !== null && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Health Score Card */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                API Security Posture
              </span>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold px-3 py-1 rounded-lg border font-mono ${
                  securityScore >= 80
                    ? "text-emerald-400 bg-emerald-950/40 border-emerald-800/60"
                    : securityScore >= 50
                    ? "text-amber-400 bg-amber-950/40 border-amber-800/60"
                    : "text-red-400 bg-red-950/40 border-red-800/60"
                }`}>
                  {securityScore}
                </span>
                <span className="text-slate-400 text-sm font-mono">/ 100</span>
              </div>

              <div className="mt-4">
                <span className="text-xs text-slate-400 block mb-1">Assessment Standard</span>
                <p className="text-xs text-slate-300 bg-[#0b0f19] border border-slate-800 px-3 py-2 rounded-lg font-mono">
                  OWASP API Security Top 10 (2023)
                </p>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-teal-400" />
              Verified with ScopeGuard Authorization
            </div>
          </div>

          {/* Endpoints Checked */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-teal-400" />
              Schema & Documentation Endpoints Tested ({analyzedEndpoints.length})
            </h3>
            <div className="space-y-2 max-h-60 overflow-y-auto">
              {analyzedEndpoints.map((ep, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 text-xs font-mono"
                >
                  <span className="text-teal-300 font-semibold">{ep.path}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{ep.title}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      typeof ep.status === "number" && ep.status < 400
                        ? "bg-amber-950 text-amber-400 border border-amber-800"
                        : "bg-slate-800 text-slate-400"
                    }`}>
                      {ep.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            API Security Findings ({findings.length})
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
            <span className="text-xs font-mono text-slate-400">Raw API Audit Log</span>
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
