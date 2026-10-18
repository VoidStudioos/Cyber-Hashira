import React, { useState } from "react";
import {
  Github,
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

interface GitHubActionsSecurityViewProps {
  targets: Target[];
  onRunTask: (moduleId: string, target: string, options: any) => Promise<any>;
  onRefreshFindings?: () => void;
}

const DEFAULT_SAMPLE_WORKFLOW = `name: CI Pipeline Security Audit
on:
  pull_request_target:
permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Flaw 1: Action not pinned to immutable commit SHA
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      # Flaw 2: Critical script injection via PR title
      - name: Greet Contributor
        run: echo "\${{ github.event.pull_request.title }}"

      # Flaw 3: Hardcoded secret leak
      - name: Notify Slack
        run: curl -X POST -H 'Content-type: application/json' --data '{"text":"Build finished"}' https://hooks.slack.com/services/T0000/B0000/MOCKTOKEN
`;

export const GitHubActionsSecurityView: React.FC<GitHubActionsSecurityViewProps> = ({
  targets,
  onRunTask,
  onRefreshFindings,
}) => {
  const [workflowContent, setWorkflowContent] = useState(DEFAULT_SAMPLE_WORKFLOW);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [complianceScore, setComplianceScore] = useState<number | null>(null);
  const [workflowsScanned, setWorkflowsScanned] = useState<number>(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [rawOutput, setRawOutput] = useState<string | null>(null);

  const authorizedTargets = targets.filter((t) => t.authorized);

  const handleAudit = async () => {
    const targetRepo = selectedTarget || "github.com/repository/ci";
    setLoading(true);
    setErrorMsg(null);
    setComplianceScore(null);
    setFindings([]);
    setRawOutput(null);

    try {
      const res = await onRunTask("github-actions-security", targetRepo, {
        workflow_content: workflowContent,
      });

      if (res && res.payload) {
        if (res.payload.success) {
          setComplianceScore(res.payload.compliance_score ?? 100);
          setWorkflowsScanned(res.payload.workflows_scanned ?? 1);
          setFindings(res.payload.findings || []);
          setRawOutput(res.payload.raw_output || "");
          if (onRefreshFindings) onRefreshFindings();
        } else {
          setErrorMsg(res.payload.error || "Workflow audit rejected by Host.");
        }
      }
    } catch (err: any) {
      setErrorMsg(err?.message || "Failed to execute GitHub Actions audit.");
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
            <div className="p-2.5 rounded-lg bg-purple-950/60 border border-purple-800/50 text-purple-400">
              <Github className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                GitHub Actions & CI/CD Security Auditor
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-purple-900/40 text-purple-400 border border-purple-700/40">
                  WIZ CODE & OWASP CI/CD TOP 10
                </span>
              </h2>
              <p className="text-sm text-slate-400">
                Audit GitHub Actions workflows for command injection, unpinned dependencies, dangerous triggers, and overprivileged tokens.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Editor & Scope Panel */}
      <div className="bg-[#111827] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-slate-200">
              Workflow YAML Definition (.github/workflows/*.yml)
            </h3>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto">
            <select
              value={selectedTarget}
              onChange={(e) => setSelectedTarget(e.target.value)}
              className="bg-[#0b0f19] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white focus:outline-none focus:border-purple-500"
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
              className="flex items-center justify-center gap-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium px-4 py-1.5 rounded-lg transition-all shadow-md shadow-purple-900/30 disabled:opacity-50 text-xs shrink-0"
            >
              {loading ? (
                <>
                  <RotateCw className="w-3.5 h-3.5 animate-spin" />
                  Auditing...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  Audit Workflow
                </>
              )}
            </button>
          </div>
        </div>

        <textarea
          rows={12}
          value={workflowContent}
          onChange={(e) => setWorkflowContent(e.target.value)}
          className="w-full bg-[#080c14] border border-slate-800 rounded-lg p-3 text-xs font-mono text-purple-200 focus:outline-none focus:border-purple-500 leading-relaxed"
          placeholder="Paste .github/workflows/build.yml content here..."
        />

        {errorMsg && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center gap-3 text-red-300 text-sm">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Results */}
      {complianceScore !== null && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Posture Score */}
          <div className="md:col-span-4 bg-[#111827] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
            <div>
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">
                OWASP CI/CD Compliance Score
              </span>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold px-3 py-1 rounded-lg border font-mono ${
                  complianceScore >= 80
                    ? "text-emerald-400 bg-emerald-950/40 border-emerald-800/60"
                    : complianceScore >= 50
                    ? "text-amber-400 bg-amber-950/40 border-amber-800/60"
                    : "text-red-400 bg-red-950/40 border-red-800/60"
                }`}>
                  {complianceScore}
                </span>
                <span className="text-slate-400 text-sm font-mono">/ 100</span>
              </div>

              <div className="mt-4 space-y-2 text-xs">
                <div className="text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg flex items-center justify-between">
                  <span className="text-slate-400">Workflows Audited:</span>
                  <span className="font-mono text-purple-400 font-semibold">{workflowsScanned}</span>
                </div>
                <div className="text-slate-300 bg-[#0b0f19] border border-slate-800 p-2.5 rounded-lg flex items-center justify-between">
                  <span className="text-slate-400">Total Vulnerabilities:</span>
                  <span className="font-mono text-red-400 font-semibold">{findings.length}</span>
                </div>
              </div>
            </div>

            <div className="mt-6 pt-4 border-t border-slate-800 text-xs text-slate-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-purple-400" />
              Verified with Wiz Code Security Guidelines
            </div>
          </div>

          {/* Guidelines Checklist */}
          <div className="md:col-span-8 bg-[#111827] border border-slate-800 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <Lock className="w-4 h-4 text-purple-400" />
              CI/CD Pipeline Security Controls
            </h3>
            <div className="space-y-2 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Prevent Shell Injection via Intermediate Env Variables</span>
                {findings.some((f) => f.title.includes("Script Injection")) ? (
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
                <span>Pin 3rd-Party Actions to Immutable 40-char Commit SHA</span>
                {findings.some((f) => f.title.includes("Not Pinned")) ? (
                  <span className="text-amber-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> MUTABLE TAGS
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> PINNED
                  </span>
                )}
              </div>
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Enforce Least Privilege (Avoid 'permissions: write-all')</span>
                {findings.some((f) => f.title.includes("write-all")) ? (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> OVERPRIVILEGED
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> SECURE
                  </span>
                )}
              </div>
              <div className="p-2.5 rounded-lg bg-[#0b0f19] border border-slate-800 flex items-center justify-between">
                <span>Segregate Untrusted Fork Runs (pull_request_target)</span>
                {findings.some((f) => f.title.includes("pull_request_target")) ? (
                  <span className="text-red-400 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> HIGH RISK
                  </span>
                ) : (
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> ISOLATED
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
            Detected CI/CD Pipeline Vulnerabilities ({findings.length})
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
                  <div className="text-xs font-mono text-purple-300 bg-black/40 p-2 rounded border border-slate-800">
                    <strong>Evidence:</strong> {f.evidence}
                  </div>
                )}
                {f.remediation && (
                  <div className="text-xs text-emerald-400 bg-emerald-950/20 border border-emerald-900/30 p-2 rounded">
                    <strong>Wiz / OWASP Remediation:</strong> {f.remediation}
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
            <span className="text-xs font-mono text-slate-400">Raw Audit Output</span>
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
