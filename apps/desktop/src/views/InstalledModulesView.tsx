import React, { useState } from "react";
import {
  Boxes,
  Play,
  AlertCircle,
  Terminal,
  Shield,
  Loader2,
} from "lucide-react";
import { InstalledModuleInfo, Target } from "../types";

interface InstalledModulesViewProps {
  installedModules: InstalledModuleInfo[];
  targets: Target[];
  activeProject?: any;
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
}

export const InstalledModulesView: React.FC<InstalledModulesViewProps> = ({
  installedModules,
  targets,
  onRunTask,
}) => {
  const [selectedTarget, setSelectedTarget] = useState("");
  const [runningModuleId, setRunningModuleId] = useState<string | null>(null);
  const [taskOutput, setTaskOutput] = useState<any | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleExecute = async (moduleId: string) => {
    if (!selectedTarget) {
      setErrorMsg("Please select an authorized target first.");
      return;
    }
    try {
      setErrorMsg(null);
      setTaskOutput(null);
      setRunningModuleId(moduleId);
      const res = await onRunTask(moduleId, selectedTarget, {});
      setTaskOutput(res);
    } catch (e: any) {
      setErrorMsg(e?.message || String(e));
    } finally {
      setRunningModuleId(null);
    }
  };

  return (
    <div className="p-8 space-y-8 overflow-y-auto max-h-[calc(100vh-4rem)]">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <Boxes className="w-6 h-6 text-cyan-400" />
          <span>Installed Security Modules</span>
        </h2>
        <p className="text-slate-400 text-sm mt-1">
          Active toolchain workers executing in isolated sub-processes.
        </p>
      </div>

      {errorMsg && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Target Selector for Module Execution */}
      <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
        <h3 className="text-base font-semibold text-white mb-2 flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Select Assessment Target</span>
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          All module runs require an authorized target from the active project.
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            className="flex-1 bg-[#0b0f19] border border-[#1e293b] text-slate-200 text-sm rounded-xl px-4 py-2.5 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">-- Choose an Authorized Target --</option>
            {authorizedTargets.map((t) => (
              <option key={t.id} value={t.target_value}>
                {t.name} ({t.target_value})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Modules List */}
      {installedModules.length === 0 ? (
        <div className="py-16 text-center text-slate-500 text-sm bg-[#0f1626] border border-[#1e293b] rounded-2xl">
          <Boxes className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <p className="font-medium text-slate-400">No modules currently installed.</p>
          <p className="text-xs text-slate-500 mt-1">
            Visit the Module Store to download and activate tools on-demand.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {installedModules.map((m) => {
            const isRunning = runningModuleId === m.id;

            return (
              <div
                key={m.id}
                className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 flex flex-col md:flex-row md:items-center justify-between gap-6"
              >
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <h3 className="text-lg font-bold text-white">{m.name}</h3>
                    <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2 py-0.5 rounded">
                      v{m.version}
                    </span>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full capitalize ${
                        m.status === "enabled"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : "bg-slate-700/30 text-slate-400"
                      }`}
                    >
                      {m.status}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 font-mono">
                    Install Path: {m.install_path}
                  </p>

                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider font-semibold">
                      Permissions:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {m.permissions.map((p) => (
                        <span
                          key={p}
                          className="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded"
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Run Button */}
                <div>
                  <button
                    disabled={isRunning || m.status !== "enabled"}
                    onClick={() => handleExecute(m.id)}
                    className={`px-5 py-2.5 rounded-xl font-semibold text-xs flex items-center gap-2 transition shadow-lg ${
                      m.status === "enabled"
                        ? "bg-cyan-500 hover:bg-cyan-400 text-[#090d16] shadow-cyan-500/20"
                        : "bg-slate-800 text-slate-500 cursor-not-allowed"
                    }`}
                  >
                    {isRunning ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4" />
                    )}
                    <span>{isRunning ? "Executing Worker..." : "Launch Assessment"}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Real-time Execution Output Terminal */}
      {taskOutput && (
        <div className="bg-[#0b0f19] border border-cyan-500/30 rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-cyan-400 flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              <span>Module Worker Telemetry & Findings</span>
            </h3>
            <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
              SUCCESS
            </span>
          </div>

          {taskOutput.payload?.raw_output && (
            <pre className="p-4 bg-[#080b12] rounded-xl text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap border border-slate-800">
              {taskOutput.payload.raw_output}
            </pre>
          )}

          {taskOutput.payload?.findings && taskOutput.payload.findings.length > 0 && (
            <div className="space-y-2">
              <span className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
                Generated Findings ({taskOutput.payload.findings.length}):
              </span>
              <div className="space-y-2">
                {taskOutput.payload.findings.map((f: any, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-[#0f1626] border border-[#1e293b] rounded-xl flex items-center justify-between"
                  >
                    <div>
                      <h4 className="text-sm font-medium text-slate-200">{f.title}</h4>
                      <p className="text-xs text-slate-400">{f.description}</p>
                    </div>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">
                      {f.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
