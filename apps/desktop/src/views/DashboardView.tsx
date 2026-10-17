import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Boxes,
  Target as TargetIcon,
  AlertTriangle,
  Info,
  ArrowUpRight,
  Cpu,
  Layers,
} from "lucide-react";
import { Finding, InstalledModuleInfo, Project, Target } from "../types";

interface DashboardViewProps {
  activeProject: Project | null;
  targets: Target[];
  installedModules: InstalledModuleInfo[];
  findings: Finding[];
  onNavigate: (view: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  activeProject,
  targets,
  installedModules,
  findings,
  onNavigate,
}) => {
  const criticalCount = findings.filter((f) => f.severity === "Critical").length;
  const highCount = findings.filter((f) => f.severity === "High").length;
  const medCount = findings.filter((f) => f.severity === "Medium").length;
  const lowCount = findings.filter((f) => f.severity === "Low").length;
  const infoCount = findings.filter((f) => f.severity === "Informational").length;

  const enabledModules = installedModules.filter((m) => m.status === "enabled");
  const authorizedTargets = targets.filter((t) => t.authorized);

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Welcome Banner */}
      <div className="bg-gradient-to-r from-cyan-950/40 via-[#0f172a] to-[#0b0f19] border border-cyan-500/20 rounded-2xl p-6 relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-gradient-to-l from-cyan-500/5 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-2">
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Modular Host Architecture Active</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight">
              {activeProject ? activeProject.name : "Cyber Hashira Workstation"}
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Lightweight Host running isolated on-demand cybersecurity modules. All target operations are strictly governed by active scope verification contracts.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onNavigate("module-store")}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-semibold text-sm rounded-xl flex items-center gap-2 transition shadow-lg shadow-cyan-500/20"
            >
              <Boxes className="w-4 h-4" />
              <span>Open Module Store</span>
            </button>
            <button
              onClick={() => onNavigate("targets")}
              className="px-4 py-2 bg-[#1e293b] hover:bg-[#334155] text-slate-200 font-medium text-sm rounded-xl flex items-center gap-2 transition"
            >
              <TargetIcon className="w-4 h-4" />
              <span>Manage Scope</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              Authorized Targets
            </span>
            <TargetIcon className="w-5 h-5 text-emerald-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">
              {authorizedTargets.length}
            </span>
            <span className="text-xs text-slate-400">of {targets.length} defined</span>
          </div>
          <div className="mt-2 text-xs text-emerald-400 font-medium flex items-center gap-1">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Strict scope guard enforced</span>
          </div>
        </div>

        {/* Metric 2 */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              Installed Modules
            </span>
            <Boxes className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">
              {installedModules.length}
            </span>
            <span className="text-xs text-slate-400">({enabledModules.length} enabled)</span>
          </div>
          <div className="mt-2 text-xs text-cyan-400 font-medium flex items-center gap-1">
            <Layers className="w-3.5 h-3.5" />
            <span>Lightweight Host (zero bloat)</span>
          </div>
        </div>

        {/* Metric 3 */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              Critical & High Risks
            </span>
            <ShieldAlert className="w-5 h-5 text-red-500" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">
              {criticalCount + highCount}
            </span>
            <span className="text-xs text-slate-400">vulnerabilities</span>
          </div>
          <div className="mt-2 text-xs text-red-400 font-medium flex items-center gap-1">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>{criticalCount} Critical, {highCount} High</span>
          </div>
        </div>

        {/* Metric 4 */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-xl p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
              Total Findings
            </span>
            <Info className="w-5 h-5 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-white">
              {findings.length}
            </span>
            <span className="text-xs text-slate-400">recorded</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-medium flex items-center gap-1">
            <span>{medCount} Med, {lowCount} Low, {infoCount} Info</span>
          </div>
        </div>
      </div>

      {/* Two Column Layout: Recent Findings & Architecture Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Recent Findings */}
        <div className="lg:col-span-2 bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-semibold text-white">Unified Security Findings</h3>
              <p className="text-xs text-slate-400">
                Normalized telemetry collected across authorized modules
              </p>
            </div>
            <button
              onClick={() => onNavigate("findings")}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {findings.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              No findings recorded yet. Run an authorized scan module to inspect targets.
            </div>
          ) : (
            <div className="space-y-3">
              {findings.slice(0, 5).map((f) => (
                <div
                  key={f.id}
                  className="p-3 bg-[#0a0e1a] border border-[#1e293b] rounded-xl flex items-center justify-between gap-4"
                >
                  <div className="flex items-center gap-3">
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono font-semibold ${
                        f.severity === "Critical"
                          ? "bg-red-500/20 text-red-400 border border-red-500/40"
                          : f.severity === "High"
                          ? "bg-orange-500/20 text-orange-400 border border-orange-500/40"
                          : f.severity === "Medium"
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/40"
                          : f.severity === "Low"
                          ? "bg-blue-500/20 text-blue-400 border border-blue-500/40"
                          : "bg-slate-700/30 text-slate-300 border border-slate-600"
                      }`}
                    >
                      {f.severity}
                    </span>
                    <div>
                      <h4 className="text-sm font-medium text-slate-200">{f.title}</h4>
                      <span className="text-xs text-slate-400">Module: {f.module_id}</span>
                    </div>
                  </div>
                  <span className="text-xs text-slate-500 font-mono">
                    {new Date(f.timestamp).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Architecture & Security Controls */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 space-y-4">
          <h3 className="text-base font-semibold text-white">Non-Negotiable Architecture</h3>

          <div className="space-y-3 text-xs text-slate-300">
            <div className="p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b] space-y-1">
              <div className="flex items-center gap-2 font-semibold text-cyan-400">
                <Layers className="w-4 h-4" />
                <span>Layer A — Lightweight Host</span>
              </div>
              <p className="text-slate-400">
                Contains desktop shell, project manager, scope boundary, SQLite findings DB, and Module Manager. Never bloated with heavy third-party binaries.
              </p>
            </div>

            <div className="p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b] space-y-1">
              <div className="flex items-center gap-2 font-semibold text-emerald-400">
                <Boxes className="w-4 h-4" />
                <span>Layer B — On-Demand Modules</span>
              </div>
              <p className="text-slate-400">
                Independent packages (DNS, Web, Nmap, Nuclei, AI) installed on demand, checked for SHA-256 integrity, executed in isolated sub-processes.
              </p>
            </div>

            <div className="p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b] space-y-1">
              <div className="flex items-center gap-2 font-semibold text-blue-400">
                <Cpu className="w-4 h-4" />
                <span>Layer C — GitHub Registry</span>
              </div>
              <p className="text-slate-400">
                Versioned JSON metadata, checksum validation, automated CI/CD distribution via releases.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
