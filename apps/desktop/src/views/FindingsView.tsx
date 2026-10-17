import React, { useState } from "react";
import {
  Bug,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  FileCode,
  CheckCircle,
} from "lucide-react";
import { Finding, Severity } from "../types";

interface FindingsViewProps {
  findings: Finding[];
}

export const FindingsView: React.FC<FindingsViewProps> = ({ findings }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("All");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = findings.filter((f) => {
    const matchSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.module_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchSev = severityFilter === "All" || f.severity === severityFilter;
    return matchSearch && matchSev;
  });

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case "Critical":
        return "bg-red-500/20 text-red-400 border-red-500/40";
      case "High":
        return "bg-orange-500/20 text-orange-400 border-orange-500/40";
      case "Medium":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40";
      case "Low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/40";
      default:
        return "bg-slate-700/30 text-slate-300 border-slate-600";
    }
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Bug className="w-6 h-6 text-cyan-400" />
            <span>Unified Findings Database</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Aggregated, normalized vulnerability records mapped with CVSS, CVE, CWE, and remediation guidance.
          </p>
        </div>

        {/* Search & Severity Filter */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-4 py-2 w-64 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="relative">
            <Filter className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-sm rounded-xl pl-9 pr-4 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="All">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Informational">Informational</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table / Accordion */}
      {filtered.length === 0 ? (
        <div className="py-16 text-center text-slate-500 text-sm bg-[#0f1626] border border-[#1e293b] rounded-2xl">
          <Bug className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <p className="font-medium text-slate-400">No findings matching your criteria.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((f) => {
            const isExpanded = expandedId === f.id;

            return (
              <div
                key={f.id}
                className="bg-[#0f1626] border border-[#1e293b] hover:border-slate-700 rounded-2xl transition overflow-hidden"
              >
                <div
                  onClick={() => toggleExpand(f.id)}
                  className="p-5 flex items-center justify-between cursor-pointer select-none"
                >
                  <div className="flex items-center gap-4">
                    <span
                      className={`text-xs px-2.5 py-1 rounded-lg font-mono font-bold border ${getSeverityBadge(
                        f.severity
                      )}`}
                    >
                      {f.severity}
                    </span>

                    <div>
                      <h3 className="text-base font-semibold text-white">{f.title}</h3>
                      <div className="flex items-center gap-3 text-xs text-slate-400 mt-1 font-mono">
                        <span>Module: {f.module_id}</span>
                        {f.cve && <span className="text-cyan-400">CVE: {f.cve}</span>}
                        {f.cwe && <span className="text-amber-400">CWE: {f.cwe}</span>}
                        {f.cvss_v3 && (
                          <span className="text-red-400">CVSS: {f.cvss_v3}</span>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <span className="text-xs text-slate-500 font-mono">
                      {new Date(f.timestamp).toLocaleString()}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-5 h-5 text-slate-400" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-6 bg-[#0a0e1a] border-t border-[#1e293b] space-y-4">
                    <div>
                      <h4 className="text-xs font-semibold uppercase text-slate-400 tracking-wider mb-1">
                        Description
                      </h4>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {f.description}
                      </p>
                    </div>

                    {f.evidence && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Evidence / Raw Probe Output</span>
                        </h4>
                        <pre className="p-3 bg-[#080b12] rounded-xl text-xs font-mono text-cyan-300 border border-slate-800 overflow-x-auto whitespace-pre-wrap">
                          {f.evidence}
                        </pre>
                      </div>
                    )}

                    {f.remediation && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase text-slate-400 tracking-wider mb-1 flex items-center gap-1.5">
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                          <span>Remediation Guidance</span>
                        </h4>
                        <p className="text-xs text-emerald-300/90 leading-relaxed bg-emerald-950/20 p-3 rounded-xl border border-emerald-900/30">
                          {f.remediation}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
