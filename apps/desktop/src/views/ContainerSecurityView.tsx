import React, { useState } from "react";
import {
  Boxes,
  AlertTriangle,
  Play,
  RotateCw,
  Copy,
  Check,
  ShieldCheck,
  FileCode,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { Finding, Target } from "../types";

interface ContainerSecurityViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

const DEFAULT_SAMPLE_DOCKERFILE = `# Insecure Dockerfile Sample
FROM python:latest
EXPOSE 22

# Sensitive environment variables in layer history
ENV DB_PASSWORD='super_secret_production_password'

# Mounting Docker socket directly into container
VOLUME /var/run/docker.sock

CMD ["python", "app.py"]
`;

export const ContainerSecurityView: React.FC<ContainerSecurityViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [dockerfileContent, setDockerfileContent] = useState(DEFAULT_SAMPLE_DOCKERFILE);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [securityScore, setSecurityScore] = useState<number | null>(null);
  const [rulesEvaluated, setRulesEvaluated] = useState<number>(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleAudit = async () => {
    const targetImage = selectedTarget || "docker.io/sample/image";
    setLoading(true);
    setErrorMsg(null);
    setSecurityScore(null);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("container-security", targetImage, {
        dockerfile_content: dockerfileContent,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setSecurityScore(res.payload.security_score ?? 100);
          setRulesEvaluated(res.payload.rules_evaluated ?? 10);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "Dockerfile audit rejected by Host.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute container security audit.");
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
            <div className="p-2.5 rounded-lg bg-blue-950/60 border border-blue-800/50 text-blue-400">
              <Boxes className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                Container & Dockerfile Security Inspector
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-900/40 text-blue-400 border border-blue-700/40">
                  CIS DOCKER BENCHMARK
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Audit Dockerfiles for root execution, unpinned base images, sensitive socket exposure, and secret leaks.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Editor & Scope Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Target Dockerfile Definition
            </h3>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-blue-500"
            >
              <option value="">-- Associate Scope Target --</option>
              {authorizedTargets.map((t) => (
                <option key={t.id} value={t.target_value}>
                  {t.name} ({t.target_value})
                </option>
              ))}
            </select>

            <button
              onClick={handleAudit}
              disabled={loading}
              className="flex items-center justify-center gap-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-medium px-4 py-1.5 rounded-lg transition-all shadow-md shadow-blue-900/30 disabled:opacity-50 text-xs shrink-0"
            >
              {loading ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  Auditing...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  Inspect Container
                </>
              )}
            </button>
          </div>
        </div>

        <textarea
          rows={12}
          value={dockerfileContent}
          onChange={(e) => setDockerfileContent(e.target.value)}
          className="w-full bg-[#080c14] border border-slate-800 rounded-lg p-3 text-xs font-mono text-blue-200 focus:outline-none focus:border-blue-500 leading-relaxed"
          placeholder="Paste Dockerfile contents here..."
        />

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
          {/* Posture Score */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                CIS Container Benchmark Score
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

              <div className="mt-4 space-y-2 text-xs">
                <div className="text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg flex items-center justify-between">
                  <span className="text-slate-400">Benchmark Rules Evaluated:</span>
                  <span className="font-mono text-blue-400 font-semibold">{rulesEvaluated}</span>
                </div>
                <div className="text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg flex items-center justify-between">
                  <span className="text-slate-400">Security Violations:</span>
                  <span className="font-mono text-red-400 font-semibold">{findings.length}</span>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-blue-400" />
              CIS Docker Benchmark v1.6.0 Compliance
            </div>
          </div>

          {/* CIS Controls Checklist */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Lock className="w-4 h-4 text-blue-400" />
              Core Container Hardening Controls
            </h3>
            <div className="space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Enforce Non-Root Dedicated User (CIS 4.3)</span>
                {findings.some((f) => f.title.includes("Root") || f.title.includes("Missing USER")) ? (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> FAILED
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                  </span>
                )}
              </div>
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Avoid Mutable Floating Base Images (:latest) (CIS 4.1)</span>
                {findings.some((f) => f.title.includes("Unpinned")) ? (
                  <span className="text-amber-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> MUTABLE TAG
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> PINNED
                  </span>
                )}
              </div>
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Forbid Sensitive Daemon Socket Mounts (/var/run/docker.sock)</span>
                {findings.some((f) => f.title.includes("Sensitive Host Path")) ? (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> ESCAPE RISK
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> SAFE
                  </span>
                )}
              </div>
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>No Secrets in Intermediate Layer Metadata (ENV / ARG) (CIS 4.7)</span>
                {findings.some((f) => f.title.includes("Hardcoded Secret")) ? (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> EXPOSED
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> CLEAN
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            Detected Container Security Violations ({findings.length})
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
                  <div className="text-xs font-mono text-blue-300 bg-black/40 p-2 rounded border border-slate-800">
                    <strong>Evidence:</strong> {f.evidence}
                  </div>
                )}
                {f.remediation && (
                  <div className="text-xs text-emerald-400 bg-emerald-950/20 border border-emerald-900/30 p-2 rounded">
                    <strong>CIS Hardening Remediation:</strong> {f.remediation}
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
            <span className="text-xs font-mono text-slate-400">Raw Inspector Output</span>
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
