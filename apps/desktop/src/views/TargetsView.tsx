import React, { useState } from "react";
import {
  Crosshair,
  Plus,
  ShieldCheck,
  ShieldAlert,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { Project, Target } from "../types";

interface TargetsViewProps {
  activeProject: Project | null;
  targets: Target[];
  onAddTarget: (
    name: string,
    targetValue: string,
    targetType: string,
    authorized: boolean,
    authorizedBy?: string
  ) => Promise<void>;
  onValidateScope: (target: string) => Promise<boolean>;
}

export const TargetsView: React.FC<TargetsViewProps> = ({
  activeProject,
  targets,
  onAddTarget,
  onValidateScope,
}) => {
  const [name, setName] = useState("");
  const [targetValue, setTargetValue] = useState("");
  const [targetType, setTargetType] = useState("domain");
  const [authorized, setAuthorized] = useState(true);
  const [authorizedBy, setAuthorizedBy] = useState("Security Officer");

  const [testTarget, setTestTarget] = useState("");
  const [testResult, setTestResult] = useState<{
    tested: boolean;
    allowed: boolean;
    message: string;
  } | null>(null);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !targetValue.trim()) return;
    await onAddTarget(name, targetValue, targetType, authorized, authorizedBy);
    setName("");
    setTargetValue("");
  };

  const handleTestScope = async () => {
    if (!testTarget.trim()) return;
    try {
      const allowed = await onValidateScope(testTarget.trim());
      setTestResult({
        tested: true,
        allowed,
        message: `Target '${testTarget}' is authorized by current project scope rules.`,
      });
    } catch (e: any) {
      setTestResult({
        tested: true,
        allowed: false,
        message: e?.message || `Target '${testTarget}' is outside authorized scope.`,
      });
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)]">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Crosshair className="w-6 h-6 text-cyan-400" />
          <span>Targets & Scope Boundary</span>
        </h2>
        <p className="text-slate-400 text-sm mt-1">
          Cyber Hashira strictly enforces explicit target authorization. Scanning or reconnaissance tools cannot execute against targets outside this allowlist.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Add Target Form */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
          <h3 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
            <Plus className="w-4 h-4 text-cyan-400" />
            <span>Add Authorized Target</span>
          </h3>

          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Target Name / Label
              </label>
              <input
                type="text"
                placeholder="e.g. Production API Gateway"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Target Type
              </label>
              <select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value)}
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
              >
                <option value="domain">Exact Domain (example.com)</option>
                <option value="wildcard">Wildcard Subdomains (*.example.com)</option>
                <option value="ip">Single IP (192.168.1.1)</option>
                <option value="cidr">CIDR Subnet (192.168.1.0/24)</option>
                <option value="url">URL Prefix (https://example.com/api)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Target Value / Pattern
              </label>
              <input
                type="text"
                placeholder="e.g. example.com or 10.0.0.0/24"
                value={targetValue}
                onChange={(e) => setTargetValue(e.target.value)}
                required
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                Authorized By (Legal Stakeholder)
              </label>
              <input
                type="text"
                placeholder="e.g. Security Lead / Client Signoff"
                value={authorizedBy}
                onChange={(e) => setAuthorizedBy(e.target.value)}
                className="w-full bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2 pt-2">
              <input
                type="checkbox"
                id="authCheck"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="rounded border-[#1e293b] text-cyan-500 focus:ring-0"
              />
              <label htmlFor="authCheck" className="text-xs text-slate-300">
                Authorized for testing under current scope rules
              </label>
            </div>

            <button
              type="submit"
              className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-semibold text-sm rounded-xl transition shadow-lg shadow-cyan-500/20"
            >
              Save Target & Add Scope Rule
            </button>
          </form>
        </div>

        {/* Right: Targets List & Scope Tester */}
        <div className="lg:col-span-2 space-y-6">
          {/* Interactive Scope Guard Tester */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
            <h3 className="text-base font-semibold text-white mb-2 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Scope Guard Live Verification Test</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Test any hostname, URL, or IP address against the ScopeGuard engine before launching assessments.
            </p>

            <div className="flex items-center gap-3">
              <input
                type="text"
                placeholder="Enter test target (e.g. test.example.com or 192.168.1.5)..."
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                className="flex-1 bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={handleTestScope}
                className="px-4 py-2 bg-[#1e293b] hover:bg-[#334155] text-slate-200 font-medium text-sm rounded-xl transition"
              >
                Validate Scope
              </button>
            </div>

            {testResult && (
              <div
                className={`mt-4 p-3 rounded-xl border flex items-center gap-3 text-xs ${
                  testResult.allowed
                    ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                    : "bg-red-500/10 border-red-500/30 text-red-400"
                }`}
              >
                {testResult.allowed ? (
                  <CheckCircle className="w-4 h-4 shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 shrink-0" />
                )}
                <span>{testResult.message}</span>
              </div>
            )}
          </div>

          {/* Defined Targets Table */}
          <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
            <h3 className="text-base font-semibold text-white mb-4">
              Active Targets for: {activeProject?.name || "Current Project"}
            </h3>

            {targets.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-sm">
                No targets added yet. Add an authorized domain or CIDR block to begin.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0b0f19] text-slate-400 border-b border-[#1e293b]">
                    <tr>
                      <th className="py-3 px-4">Name</th>
                      <th className="py-3 px-4">Pattern / Value</th>
                      <th className="py-3 px-4">Type</th>
                      <th className="py-3 px-4">Authorization</th>
                      <th className="py-3 px-4">Signoff</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e293b]">
                    {targets.map((t) => (
                      <tr key={t.id} className="hover:bg-slate-800/30">
                        <td className="py-3 px-4 font-medium text-slate-200">{t.name}</td>
                        <td className="py-3 px-4 font-mono text-cyan-400">{t.target_value}</td>
                        <td className="py-3 px-4 uppercase font-semibold text-[10px] text-slate-400">
                          {t.target_type}
                        </td>
                        <td className="py-3 px-4">
                          {t.authorized ? (
                            <span className="inline-flex items-center gap-1 text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded-full font-medium">
                              <ShieldCheck className="w-3 h-3" />
                              <span>Authorized</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded-full font-medium">
                              <ShieldAlert className="w-3 h-3" />
                              <span>Unauthorized</span>
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          {t.authorized_by || "Unassigned"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
