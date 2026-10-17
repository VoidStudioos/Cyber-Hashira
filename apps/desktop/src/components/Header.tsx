import React from "react";
import { ShieldCheck, Database, Languages } from "lucide-react";
import { HostInfo, Project } from "../types";

interface HeaderProps {
  hostInfo: HostInfo | null;
  projects: Project[];
  activeProject: Project | null;
  onSelectProject: (p: Project) => void;
  isRtl: boolean;
  onToggleRtl: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  hostInfo,
  projects,
  activeProject,
  onSelectProject,
  isRtl,
  onToggleRtl,
}) => {
  return (
    <header className="h-16 bg-[#0b0f19] border-b border-[#1e293b] flex items-center justify-between px-6 z-10">
      {/* Left: Project Selector & Status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
            Project:
          </span>
          <select
            value={activeProject?.id || ""}
            onChange={(e) => {
              const p = projects.find((proj) => proj.id === e.target.value);
              if (p) onSelectProject(p);
            }}
            className="bg-[#101726] border border-[#1e293b] text-slate-200 text-sm rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>

        {/* Scope Boundary Pill */}
        <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs px-2.5 py-1 rounded-full">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span className="font-medium">Target Scope Guard Active</span>
        </div>
      </div>

      {/* Right: Host Environment, Database, RTL switch */}
      <div className="flex items-center gap-4">
        {hostInfo && (
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-[#0f1626] border border-[#1e293b] px-3 py-1.5 rounded-lg">
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>{hostInfo.database}</span>
            <span className="text-slate-600">|</span>
            <span className="text-slate-300">{hostInfo.os}</span>
          </div>
        )}

        <button
          onClick={onToggleRtl}
          className="flex items-center gap-1.5 text-xs text-slate-300 hover:text-cyan-400 bg-[#101726] hover:bg-slate-800 border border-[#1e293b] px-3 py-1.5 rounded-lg transition"
          title="Toggle Language / RTL (English / فارسی)"
        >
          <Languages className="w-3.5 h-3.5" />
          <span>{isRtl ? "فارسی (RTL)" : "EN (LTR)"}</span>
        </button>
      </div>
    </header>
  );
};
