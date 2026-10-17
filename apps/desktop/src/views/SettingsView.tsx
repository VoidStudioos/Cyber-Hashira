import React from "react";
import { Settings as SettingsIcon, Shield, Database, Lock, EyeOff, Info } from "lucide-react";
import { HostInfo } from "../types";

interface SettingsViewProps {
  hostInfo: HostInfo | null;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ hostInfo }) => {
  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)]">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <SettingsIcon className="w-6 h-6 text-cyan-400" />
          <span>Host Settings & Governance</span>
        </h2>
        <p className="text-slate-400 text-sm mt-1">
          Cyber Hashira operates offline-first with zero unauthorized external telemetry or unvetted code execution.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Core Security Controls */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span>Strict Security Principles</span>
          </h3>

          <div className="space-y-3 text-xs">
            <div className="flex items-start gap-3 p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b]">
              <Lock className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">
                  Mandatory Scope Validation
                </span>
                <span className="text-slate-400">
                  Every active scan request is strictly inspected by ScopeGuard before subprocess invocation.
                </span>
              </div>
            </div>

            <div className="flex items-start gap-3 p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b]">
              <EyeOff className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">
                  Zero Telemetry / Offline-First
                </span>
                <span className="text-slate-400">
                  No scan targets, findings, credentials, or analyst evidence are sent to any remote telemetry servers.
                </span>
              </div>
            </div>

            <div className="flex items-start gap-3 p-3 bg-[#0a0e1a] rounded-xl border border-[#1e293b]">
              <Database className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200 block">
                  Encrypted Local SQLite Database
                </span>
                <span className="text-slate-400">
                  Stand-alone storage located strictly on local disk with WAL journal mode.
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Host Runtime Information */}
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 space-y-4">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            <span>Host Environment Information</span>
          </h3>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex justify-between py-2 border-b border-[#1e293b]">
              <span className="text-slate-400">Host Application:</span>
              <span className="text-cyan-400">{hostInfo?.name || "Cyber Hashira Host"}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-[#1e293b]">
              <span className="text-slate-400">Host Version:</span>
              <span className="text-slate-200">{hostInfo?.version || "0.1.0"}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-[#1e293b]">
              <span className="text-slate-400">Operating System:</span>
              <span className="text-slate-200">{hostInfo?.os || "Windows / Linux"}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-[#1e293b]">
              <span className="text-slate-400">Architecture:</span>
              <span className="text-slate-200">{hostInfo?.arch || "x86_64"}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-[#1e293b]">
              <span className="text-slate-400">Database Engine:</span>
              <span className="text-emerald-400">{hostInfo?.database || "SQLite (Local)"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
