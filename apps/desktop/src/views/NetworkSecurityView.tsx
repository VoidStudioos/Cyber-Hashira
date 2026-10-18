import React, { useState } from "react";
import {
  Network,
  Play,
  RotateCw,
  Server,
  AlertTriangle,
  Bug,
  Shield,
  Activity,
} from "lucide-react";
import { Finding, Target } from "../types";

interface NetworkSecurityViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

export const NetworkSecurityView: React.FC<NetworkSecurityViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [selectedTarget, setSelectedTarget] = useState("");
  const [portProfile, setPortProfile] = useState("top-100");
  const [customPorts, setCustomPorts] = useState("21,22,23,80,443,445,3389,8080");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [discoveredPorts, setDiscoveredPorts] = useState<any[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleStartScan = async () => {
    if (!selectedTarget) {
      setErrorMsg("Please select an authorized target.");
      return;
    }
    setLoading(true);
    setErrorMsg(null);
    setDiscoveredPorts([]);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("network-security", selectedTarget, {
        port_profile: portProfile,
        custom_ports: customPorts,
      });

      if (res && res.payload) {
        setRawOutput(res.payload.raw_output);
        if (res.payload.discovered_ports) {
          setDiscoveredPorts(res.payload.discovered_ports);
        }
        if (res.payload.findings) {
          setFindings(res.payload.findings);
        }
      }
      if (onRefreshFindings) onRefreshFindings();
    } catch (e: any) {
      setErrorMsg(e?.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e293b]">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" />
            <span>Network & Port Reconnaissance</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Authorized port discovery, service versioning, and insecure protocol detection with Nmap adapter.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-[#0f1626] border border-[#1e293b] px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span>Scanner Engine: Ready</span>
        </div>
      </div>

      {errorMsg && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Target & Scan Config Controls */}
      <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 space-y-4">
        <h3 className="text-base font-semibold text-white flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Scan Parameters & Scope Verification</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Authorized Target
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
            >
              <option value="">-- Choose Target --</option>
              {authorizedTargets.map((t) => (
                <option key={t.id} value={t.target_value}>
                  {t.name} ({t.target_value})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Port Discovery Profile
            </label>
            <select
              value={portProfile}
              onChange={(e) => setPortProfile(e.target.value)}
              className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="top-20">Quick Probe (Top 20 Critical Ports)</option>
              <option value="top-100">Standard Audit (Top 100 Common Ports)</option>
              <option value="custom">Custom Port Range</option>
            </select>
          </div>

          {portProfile === "custom" && (
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Custom Ports (comma-separated)
              </label>
              <input
                type="text"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
                placeholder="e.g. 21,22,80,443,3389"
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          )}
        </div>

        <div className="pt-2">
          <button
            disabled={loading}
            onClick={handleStartScan}
            className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-bold text-sm rounded-xl flex items-center gap-2 transition shadow-lg shadow-cyan-500/20"
          >
            {loading ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            <span>{loading ? "Probing Ports..." : "Launch Port Scan"}</span>
          </button>
        </div>
      </div>

      {/* Results View */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Discovered Ports Table */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[460px]">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Open Ports Discovered</span>
            </h3>
            <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded">
              {discoveredPorts.length} Open
            </span>
          </div>

          {discoveredPorts.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">
              {loading ? "Scanning target host..." : "No scan results. Select a target and launch scan."}
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-[#0b0f19] text-slate-400 border-b border-[#1e293b] sticky top-0">
                  <tr>
                    <th className="py-2.5 px-3">Port</th>
                    <th className="py-2.5 px-3">State</th>
                    <th className="py-2.5 px-3">Service</th>
                    <th className="py-2.5 px-3">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e293b]">
                  {discoveredPorts.map((p, i) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      <td className="py-2 px-3 font-bold text-cyan-400">{p.port}/tcp</td>
                      <td className="py-2 px-3">
                        <span className="text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded text-[10px]">
                          {p.state}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-slate-200">{p.service}</td>
                      <td className="py-2 px-3 text-slate-500">{p.latency_ms} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Security Findings & Raw Log */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col h-[460px] space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Bug className="w-4 h-4 text-amber-400" />
              <span>Identified Protocol Risks</span>
            </h3>
            {findings.length > 0 && (
              <span className="text-xs font-semibold bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded-full">
                {findings.length} Findings
              </span>
            )}
          </div>

          {findings.length === 0 ? (
            <div className="flex-1 overflow-y-auto">
              {rawOutput ? (
                <pre className="p-3 bg-[#0a0e1a] rounded-xl text-xs font-mono text-slate-300 whitespace-pre-wrap">
                  {rawOutput}
                </pre>
              ) : (
                <div className="h-full flex items-center justify-center text-slate-500 text-sm">
                  Run a scan to generate network findings
                </div>
              )}
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-2">
              {findings.map((f, i) => (
                <div
                  key={i}
                  className="p-3 bg-[#0a0e1a] border border-[#1e293b] rounded-xl space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-slate-200">{f.title}</span>
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        f.severity === "High"
                          ? "bg-red-500/20 text-red-400"
                          : f.severity === "Medium"
                          ? "bg-amber-500/20 text-amber-400"
                          : "bg-blue-500/20 text-blue-400"
                      }`}
                    >
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{f.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
