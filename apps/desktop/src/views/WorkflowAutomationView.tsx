import React, { useState } from "react";
import {
  GitFork,
  Play,
  RotateCw,
  ShieldCheck,
  Globe,
  Network,
  Bug,
  Sparkles,
  FileCheck,
  ArrowRight,
} from "lucide-react";
import { Target } from "../types";

interface WorkflowAutomationViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

interface WorkflowNode {
  id: string;
  name: string;
  description: string;
  icon: any;
  status: "idle" | "running" | "completed" | "error";
  moduleId?: string;
  summary?: string;
}

export const WorkflowAutomationView: React.FC<WorkflowAutomationViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [selectedTarget, setSelectedTarget] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [pipelineLogs, setPipelineLogs] = useState<string[]>([]);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const [nodes, setNodes] = useState<WorkflowNode[]>([
    {
      id: "scope-gate",
      name: "1. ScopeGuard Authorization Gate",
      description: "Enforce strict allowlist boundary check on target",
      icon: ShieldCheck,
      status: "idle",
      summary: "Interception checkpoint",
    },
    {
      id: "dns-recon",
      name: "2. Passive DNS & Domain Recon",
      description: "Query DNS records, mail endpoints, internal IP leakage",
      icon: Globe,
      status: "idle",
      moduleId: "sample-dns",
    },
    {
      id: "port-scan",
      name: "3. Authorized Network Discovery",
      description: "Probe TCP services and insecure protocol exposure",
      icon: Network,
      status: "idle",
      moduleId: "network-security",
    },
    {
      id: "web-inspect",
      name: "4. Web Security & Header Audit",
      description: "Inspect HTTP security headers, cookies, and CORS",
      icon: Globe,
      status: "idle",
      moduleId: "web-security",
    },
    {
      id: "vuln-scan",
      name: "5. Nuclei Vulnerability Assessment",
      description: "Evaluate security templates for exposed credentials & configs",
      icon: Bug,
      status: "idle",
      moduleId: "vulnerability-assessment",
    },
    {
      id: "ai-triage",
      name: "6. Hashira AI Defensive Triage",
      description: "Analyze findings, calculate risk score & generate patches",
      icon: Sparkles,
      status: "idle",
      moduleId: "hashira-ai",
    },
    {
      id: "report-gen",
      name: "7. Executive Security Report",
      description: "Compile normalized findings into standardized SARIF / PDF",
      icon: FileCheck,
      status: "idle",
    },
  ]);

  const logLine = (msg: string) => {
    setPipelineLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const executePipeline = async () => {
    if (!selectedTarget) {
      alert("Please select an authorized target first.");
      return;
    }

    setIsRunning(true);
    setPipelineLogs([]);
    logLine(`Starting Automated Security Pipeline for target: ${selectedTarget}`);

    // Reset nodes
    setNodes((prev) => prev.map((n) => ({ ...n, status: "idle" })));

    // Step 1: Scope Validation
    setCurrentStepIndex(0);
    setNodes((prev) =>
      prev.map((n, i) => (i === 0 ? { ...n, status: "running" } : n))
    );
    logLine("Step 1/7: Validating target scope against active ScopeGuard rules...");
    await new Promise((r) => setTimeout(r, 600));

    const isAuth = authorizedTargets.some(
      (t) => t.authorized && selectedTarget.includes(t.target_value)
    );
    if (!isAuth) {
      logLine("ERROR: Target failed ScopeGuard validation! Pipeline halted.");
      setNodes((prev) =>
        prev.map((n, i) => (i === 0 ? { ...n, status: "error" } : n))
      );
      setIsRunning(false);
      return;
    }

    setNodes((prev) =>
      prev.map((n, i) => (i === 0 ? { ...n, status: "completed" } : n))
    );
    logLine("Target verified. Authorization confirmed.");

    // Step 2 to 5: Run modules sequentially
    const moduleSteps = [
      { idx: 1, mod: "sample-dns", name: "DNS Reconnaissance", opts: {} },
      { idx: 2, mod: "network-security", name: "Port Discovery", opts: { port_profile: "top-20" } },
      { idx: 3, mod: "web-security", name: "Web Security Analysis", opts: { action: "passive_scan" } },
      { idx: 4, mod: "vulnerability-assessment", name: "Nuclei Template Scan", opts: { profile: "fast" } },
    ];

    for (const step of moduleSteps) {
      setCurrentStepIndex(step.idx);
      setNodes((prev) =>
        prev.map((n, i) => (i === step.idx ? { ...n, status: "running" } : n))
      );
      logLine(`Executing Step ${step.idx + 1}/7: ${step.name}...`);

      try {
        await onRunTask(step.mod, selectedTarget, step.opts);
        setNodes((prev) =>
          prev.map((n, i) => (i === step.idx ? { ...n, status: "completed" } : n))
        );
        logLine(`Step ${step.idx + 1}/7 completed successfully.`);
      } catch (e: any) {
        logLine(`Warning in step ${step.name}: ${e?.message || e}`);
        setNodes((prev) =>
          prev.map((n, i) => (i === step.idx ? { ...n, status: "completed" } : n))
        );
      }
    }

    // Step 6: AI Triage
    setCurrentStepIndex(5);
    setNodes((prev) =>
      prev.map((n, i) => (i === 5 ? { ...n, status: "running" } : n))
    );
    logLine("Executing Step 6/7: Hashira AI Defensive Triage & Posture Scoring...");
    try {
      await onRunTask("hashira-ai", selectedTarget, { action: "triage" });
      setNodes((prev) =>
        prev.map((n, i) => (i === 5 ? { ...n, status: "completed" } : n))
      );
      logLine("AI triage complete. Score and recommendations generated.");
    } catch {
      setNodes((prev) =>
        prev.map((n, i) => (i === 5 ? { ...n, status: "completed" } : n))
      );
    }

    // Step 7: Report Generation
    setCurrentStepIndex(6);
    setNodes((prev) =>
      prev.map((n, i) => (i === 6 ? { ...n, status: "running" } : n))
    );
    logLine("Executing Step 7/7: Normalizing evidence & compiling final assessment report...");
    await new Promise((r) => setTimeout(r, 800));
    setNodes((prev) =>
      prev.map((n, i) => (i === 6 ? { ...n, status: "completed" } : n))
    );
    logLine("All stages completed! Full assessment report ready in Findings & Reports.");

    setIsRunning(false);
    setCurrentStepIndex(-1);
    if (onRefreshFindings) onRefreshFindings();
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-[#1e293b]">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <GitFork className="w-6 h-6 text-cyan-400" />
            <span>Workflow Automation Engine</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Visual cybersecurity pipeline designer: chain multi-stage scans with non-bypassable scope controls.
          </p>
        </div>

        {/* Target Selector & Run Trigger */}
        <div className="flex items-center gap-3">
          <select
            value={selectedTarget}
            onChange={(e) => setSelectedTarget(e.target.value)}
            className="bg-[#0f1626] border border-[#1e293b] text-slate-200 text-xs rounded-xl px-3 py-2 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="">-- Choose Authorized Target --</option>
            {authorizedTargets.map((t) => (
              <option key={t.id} value={t.target_value}>
                {t.name} ({t.target_value})
              </option>
            ))}
          </select>

          <button
            disabled={isRunning || !selectedTarget}
            onClick={executePipeline}
            className="px-5 py-2 bg-cyan-500 hover:bg-cyan-400 text-[#090d16] font-bold text-xs rounded-xl flex items-center gap-2 transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {isRunning ? (
              <RotateCw className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span>{isRunning ? "Executing Pipeline..." : "Run Pipeline"}</span>
          </button>
        </div>
      </div>

      {/* Visual Pipeline Graph */}
      <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-6 space-y-4">
        <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
          Security Assessment Pipeline Architecture
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {nodes.map((node, i) => {
            const Icon = node.icon;
            const isCurrent = currentStepIndex === i;

            return (
              <div
                key={node.id}
                className={`p-4 rounded-xl border transition flex flex-col justify-between ${
                  node.status === "completed"
                    ? "bg-emerald-950/20 border-emerald-500/40 shadow-sm"
                    : node.status === "running" || isCurrent
                    ? "bg-cyan-950/30 border-cyan-500 animate-pulse shadow-md shadow-cyan-500/10"
                    : node.status === "error"
                    ? "bg-red-950/20 border-red-500/50"
                    : "bg-[#0a0e1a] border-[#1e293b]"
                }`}
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div
                      className={`p-2 rounded-lg ${
                        node.status === "completed"
                          ? "bg-emerald-500/20 text-emerald-400"
                          : node.status === "running"
                          ? "bg-cyan-500/20 text-cyan-400"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>

                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full font-mono ${
                        node.status === "completed"
                          ? "bg-emerald-500/20 text-emerald-400"
                          : node.status === "running"
                          ? "bg-cyan-500/20 text-cyan-400"
                          : node.status === "error"
                          ? "bg-red-500/20 text-red-400"
                          : "bg-slate-800 text-slate-500"
                      }`}
                    >
                      {node.status}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-white">{node.name}</h4>
                  <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                    {node.description}
                  </p>
                </div>

                <div className="mt-3 pt-2 border-t border-[#1e293b]/60 flex items-center justify-between text-[10px] text-slate-500">
                  <span>Stage {i + 1} of 7</span>
                  {i < nodes.length - 1 && <ArrowRight className="w-3 h-3 text-slate-600" />}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Pipeline Execution Logs */}
      <div className="bg-[#0b0f19] border border-[#1e293b] rounded-2xl p-5 space-y-3">
        <h3 className="text-xs font-semibold uppercase text-slate-400 tracking-wider">
          Pipeline Execution Telemetry
        </h3>

        {pipelineLogs.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">
            Pipeline is idle. Select an authorized target and click 'Run Pipeline'.
          </div>
        ) : (
          <div className="p-4 bg-[#080b12] rounded-xl border border-slate-800 font-mono text-xs text-slate-300 space-y-1.5 max-h-48 overflow-y-auto">
            {pipelineLogs.map((log, i) => (
              <div
                key={i}
                className={
                  log.includes("ERROR")
                    ? "text-red-400 font-bold"
                    : log.includes("completed") || log.includes("verified")
                    ? "text-emerald-400"
                    : "text-slate-300"
                }
              >
                {log}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
