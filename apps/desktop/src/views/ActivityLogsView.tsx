import React from "react";
import { ScrollText } from "lucide-react";
import { AuditLogEntry } from "../types";

interface ActivityLogsViewProps {
  logs: AuditLogEntry[];
}

export const ActivityLogsView: React.FC<ActivityLogsViewProps> = ({ logs }) => {
  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      <div>
        <h2 className="text-2xl font-bold text-white flex items-center gap-2">
          <ScrollText className="w-6 h-6 text-cyan-400" />
          <span>Audit & Activity Trails</span>
        </h2>
        <p className="text-slate-400 text-sm mt-1">
          Cryptographically signed, tamper-evident audit log of all operator actions, scope validations, and module executions.
        </p>
      </div>

      <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6">
        {logs.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No activity logged yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0b0f19] text-slate-400 border-b border-[#1e293b]">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Target / Module</th>
                  <th className="py-3 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e293b]">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 text-slate-400">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-semibold text-cyan-400">{log.actor}</td>
                    <td className="py-3 px-4 text-slate-200">{log.action}</td>
                    <td className="py-3 px-4 text-slate-400">
                      {log.target || log.module_id || "Host Core"}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.status === "SUCCESS"
                            ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                            : "bg-red-500/10 text-red-400 border border-red-500/30"
                        }`}
                      >
                        {log.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
