import React, { useState } from "react";
import { Cloud, Play, CheckCircle, AlertTriangle, Layers, FileCode } from "lucide-react";

export const CloudIacSecurityView: React.FC = () => {
  const [templateType, setTemplateType] = useState<"terraform" | "kubernetes">("terraform");
  const [isAuditing, setIsAuditing] = useState(false);
  const [auditResult, setAuditResult] = useState<any>(null);

  const [terraformContent, setTerraformContent] = useState<string>(`resource "aws_s3_bucket" "prod_data" {
  bucket = "company-financial-data-2026"
  acl    = "public-read" # Critical: Public S3 bucket
}

resource "aws_security_group" "web_ingress" {
  name = "allow_all_admin"
  ingress {
    from_port   = 22 # High: SSH open to 0.0.0.0/0
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  allocated_storage = 50
  engine            = "postgres"
  storage_encrypted = false # Medium: Unencrypted database storage
}
`);

  const [kubernetesContent, setKubernetesContent] = useState<string>(`apiVersion: v1
kind: Pod
metadata:
  name: privileged-webapp
spec:
  hostPID: true # High: Shared host process namespace
  containers:
  - name: web
    image: nginx:latest
    securityContext:
      privileged: true # Critical: Container with host root capabilities
      runAsNonRoot: false
`);

  const currentContent = templateType === "terraform" ? terraformContent : kubernetesContent;
  const setCurrentContent = (val: string) => {
    if (templateType === "terraform") {
      setTerraformContent(val);
    } else {
      setKubernetesContent(val);
    }
  };

  const runIacAudit = () => {
    setIsAuditing(true);
    setTimeout(() => {
      const issues: any[] = [];
      const content = currentContent;

      if (templateType === "terraform") {
        if (/acl\s*=\s*["']public-read/i.test(content)) {
          issues.push({
            id: "CIS-AWS-2.1.5",
            title: "Public S3 Bucket ACL Discovered (CIS AWS 2.1.5)",
            severity: "Critical",
            cvss: 9.1,
            description: "S3 bucket is configured with public-read ACL, exposing stored objects to anyone on the internet.",
            remediation: "Set acl = 'private' and provision aws_s3_bucket_public_access_block.",
          });
        }
        if (/0\.0\.0\.0\/0/.test(content) && /(?:from_port|to_port)\s*=\s*(?:22|3389)/.test(content)) {
          issues.push({
            id: "CIS-AWS-4.1",
            title: "Security Group Allows Unrestricted Ingress to Port 22/3389 (CIS AWS 4.1)",
            severity: "High",
            cvss: 8.5,
            description: "Administration ports (SSH 22 or RDP 3389) permit ingress traffic from any internet IP (0.0.0.0/0).",
            remediation: "Restrict ingress CIDR to corporate VPN or private bastion subnets.",
          });
        }
        if (/(?:storage_encrypted|encrypted)\s*=\s*false/i.test(content)) {
          issues.push({
            id: "CIS-AWS-2.2.1",
            title: "Database / Block Storage Encryption Disabled (CIS AWS 2.2.1)",
            severity: "Medium",
            cvss: 6.5,
            description: "EBS volume or RDS database instance explicitly disables encryption at rest.",
            remediation: "Set storage_encrypted = true and specify kms_key_id.",
          });
        }
      } else {
        if (/privileged:\s*true/i.test(content)) {
          issues.push({
            id: "CIS-K8S-5.2.1",
            title: "Kubernetes Container Runs in Privileged Mode (CIS K8s 5.2.1)",
            severity: "Critical",
            cvss: 9.6,
            description: "Container has privileged: true, allowing breakout into the underlying worker node kernel.",
            remediation: "Remove privileged: true and assign specific Linux capabilities only if strictly required.",
          });
        }
        if (/hostPID:\s*true/i.test(content) || /hostNetwork:\s*true/i.test(content)) {
          issues.push({
            id: "CIS-K8S-5.2.2",
            title: "Pod Shares Host Process / Network Namespace (CIS K8s 5.2.2)",
            severity: "High",
            cvss: 8.2,
            description: "Pod shares host process namespace, permitting inspection of host node processes and container escape.",
            remediation: "Set hostPID: false and hostNetwork: false in pod specification.",
          });
        }
      }

      const score = Math.max(0, 100 - issues.length * 30);
      setAuditResult({
        score,
        totalIssues: issues.length,
        issues,
        timestamp: new Date().toLocaleTimeString(),
      });
      setIsAuditing(false);
    }, 500);
  };

  return (
    <div className="p-8 space-y-6 overflow-y-auto max-h-[calc(100vh-4rem)]">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cloud className="w-6 h-6 text-cyan-400" />
            <span>Cloud & Infrastructure as Code (IaC) Security</span>
          </h2>
          <p className="text-slate-400 text-sm mt-1">
            Automated CIS Cloud Benchmarks auditor for Terraform HCL, Kubernetes YAML, and CloudFormation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex bg-[#0f1626] border border-[#1e293b] p-1 rounded-xl">
            <button
              onClick={() => {
                setTemplateType("terraform");
                setAuditResult(null);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                templateType === "terraform" ? "bg-cyan-600 text-white shadow" : "text-slate-400 hover:text-white"
              }`}
            >
              Terraform (HCL)
            </button>
            <button
              onClick={() => {
                setTemplateType("kubernetes");
                setAuditResult(null);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                templateType === "kubernetes" ? "bg-cyan-600 text-white shadow" : "text-slate-400 hover:text-white"
              }`}
            >
              Kubernetes (YAML)
            </button>
          </div>

          <button
            onClick={runIacAudit}
            disabled={isAuditing}
            className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded-xl text-sm shadow-lg shadow-cyan-900/30 transition disabled:opacity-50"
          >
            <Play className={`w-4 h-4 ${isAuditing ? "animate-spin" : ""}`} />
            <span>{isAuditing ? "Evaluating Rules..." : "Audit IaC Policy"}</span>
          </button>
        </div>
      </div>

      {/* Grid: Template Editor + Audit Results */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-3 pb-2 border-b border-[#1e293b]">
            <span className="text-xs font-semibold text-slate-400 flex items-center gap-1.5 font-mono">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>{templateType === "terraform" ? "main.tf (HCL)" : "deployment.yaml (K8s)"}</span>
            </span>
            <span className="text-xs text-slate-500 font-mono">CIS Compliance Target</span>
          </div>
          <textarea
            value={currentContent}
            onChange={(e) => setCurrentContent(e.target.value)}
            rows={18}
            className="w-full bg-[#080c14] border border-[#1a2333] rounded-xl p-4 font-mono text-xs text-cyan-200 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
            spellCheck={false}
          />
        </div>

        <div className="space-y-4">
          {auditResult ? (
            <>
              {/* Score Card */}
              <div className="bg-[#0f1626] border border-[#1e293b] rounded-2xl p-5 flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    CIS Benchmark Compliance
                  </div>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span
                      className={`text-3xl font-extrabold ${
                        auditResult.score > 80
                          ? "text-emerald-400"
                          : auditResult.score > 50
                          ? "text-amber-400"
                          : "text-red-400"
                      }`}
                    >
                      {auditResult.score}%
                    </span>
                    <span className="text-xs text-slate-400">Pass Rate</span>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-xs text-slate-400">Misconfigurations</div>
                  <div className="text-xl font-bold text-red-400 font-mono mt-0.5">
                    {auditResult.totalIssues} Violations
                  </div>
                </div>
              </div>

              {/* Issues List */}
              <div className="space-y-3">
                {auditResult.issues.length === 0 ? (
                  <div className="p-8 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-emerald-400 text-sm">
                    <CheckCircle className="w-10 h-10 mx-auto mb-2 text-emerald-400" />
                    <span>No CIS cloud benchmark misconfigurations found.</span>
                  </div>
                ) : (
                  auditResult.issues.map((issue: any) => (
                    <div
                      key={issue.id}
                      className="p-4 bg-[#0f1626] border border-red-500/30 rounded-xl space-y-2 hover:border-red-500/60 transition"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="font-semibold text-sm text-white flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                          <span>{issue.title}</span>
                        </div>
                        <span className="text-xs font-mono font-bold px-2 py-0.5 bg-red-500/20 text-red-300 rounded border border-red-500/40">
                          {issue.id}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">{issue.description}</p>
                      <div className="text-xs text-slate-300 bg-slate-900/40 p-2.5 rounded-lg border border-slate-800">
                        <strong className="text-emerald-400">Remediation: </strong>
                        {issue.remediation}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center bg-[#0f1626] border border-[#1e293b] rounded-2xl text-slate-500 text-sm">
              <Layers className="w-12 h-12 text-slate-600 mx-auto mb-3" />
              <p className="font-medium text-slate-400">Ready to audit cloud infrastructure manifests.</p>
              <p className="text-xs text-slate-500 mt-1">
                Select your template format and click "Audit IaC Policy" to evaluate CIS compliance.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
