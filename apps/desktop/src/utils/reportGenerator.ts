import { Finding } from "../types";

export interface ReportMetadata {
  projectName?: string;
  targetScope?: string;
  generatedBy?: string;
  language?: "en" | "fa";
}

export const generateSarifReport = (findings: Finding[]): string => {
  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Cyber Hashira Security Workstation",
            version: "1.0.0",
            informationUri: "https://github.com/VoidStudioos/Cyber-Hashira",
            rules: findings.map((f) => ({
              id: f.id,
              name: f.title,
              shortDescription: { text: f.title },
              fullDescription: { text: f.description },
              help: { text: f.remediation || "Review and patch affected systems." },
              properties: {
                severity: f.severity.toLowerCase(),
                cvss: f.cvss_v3 || 0,
                cve: f.cve || "",
                cwe: f.cwe || "",
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.id,
          message: { text: f.description },
          level:
            f.severity === "Critical" || f.severity === "High"
              ? "error"
              : f.severity === "Medium"
              ? "warning"
              : "note",
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.module_id },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
};

export const generateMarkdownReport = (
  findings: Finding[],
  metadata: ReportMetadata = {}
): string => {
  const dateStr = new Date().toISOString().split("T")[0];
  const critCount = findings.filter((f) => f.severity === "Critical").length;
  const highCount = findings.filter((f) => f.severity === "High").length;
  const medCount = findings.filter((f) => f.severity === "Medium").length;
  const lowCount = findings.filter((f) => f.severity === "Low").length;

  let md = `# Cyber Hashira — Executive Cybersecurity Audit Report\n\n`;
  md += `**Date:** ${dateStr}  \n`;
  md += `**Project:** ${metadata.projectName || "General Security Audit"}  \n`;
  md += `**Target Scope:** ${metadata.targetScope || "All Authorized Assets"}  \n`;
  md += `**Auditor Engine:** ${metadata.generatedBy || "Cyber Hashira Station v1.0.0"}  \n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `A comprehensive security assessment was conducted using the unified Cyber Hashira workstation.\n`;
  md += `A total of **${findings.length} findings** were identified and normalized.\n\n`;

  md += `| Severity | Count | Risk Action |\n`;
  md += `|:---|:---:|:---|\n`;
  md += `| 🔴 **Critical** | ${critCount} | Immediate Hotfix Required |\n`;
  md += `| 🟠 **High** | ${highCount} | Remediate within 48 hours |\n`;
  md += `| 🟡 **Medium** | ${medCount} | Schedule in current sprint |\n`;
  md += `| 🔵 **Low** | ${lowCount} | Best Practice / Hardening |\n\n`;

  md += `## 2. Detailed Findings & Remediation\n\n`;

  findings.forEach((f, idx) => {
    md += `### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **Module:** \`${f.module_id}\`\n`;
    if (f.cve) md += `- **CVE:** \`${f.cve}\`\n`;
    if (f.cwe) md += `- **CWE:** \`${f.cwe}\`\n`;
    if (f.cvss_v3) md += `- **CVSS v3.1:** \`${f.cvss_v3}\`\n`;
    md += `\n**Description:**  \n${f.description}\n\n`;

    if (f.evidence) {
      md += `**Technical Evidence:**\n\`\`\`text\n${f.evidence}\n\`\`\`\n\n`;
    }

    if (f.remediation) {
      md += `**Recommended Remediation:**  \n> ${f.remediation}\n\n`;
    }
    md += `---\n\n`;
  });

  return md;
};

export const generateHtmlReport = (
  findings: Finding[],
  metadata: ReportMetadata = {}
): string => {
  const dateStr = new Date().toLocaleDateString();
  const critCount = findings.filter((f) => f.severity === "Critical").length;
  const highCount = findings.filter((f) => f.severity === "High").length;
  const medCount = findings.filter((f) => f.severity === "Medium").length;
  const lowCount = findings.filter((f) => f.severity === "Low").length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cyber Hashira — Executive Security Audit Report</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
    :root {
      --bg: #090d16;
      --card-bg: #0f172a;
      --border: #1e293b;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --accent: #06b6d4;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #f59e0b;
      --low: #3b82f6;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 40px;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    .header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 24px;
      margin-bottom: 32px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .header h1 { font-size: 28px; font-weight: 800; color: #fff; letter-spacing: -0.5px; }
    .header .subtitle { color: var(--accent); font-size: 14px; font-weight: 600; margin-top: 4px; }
    .meta-box {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 20px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }
    .meta-item .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }
    .meta-item .val { font-size: 14px; font-weight: 600; color: #fff; margin-top: 4px; }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 40px;
    }
    .summary-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 20px;
      text-align: center;
    }
    .summary-card.critical { border-top: 4px solid var(--critical); }
    .summary-card.high { border-top: 4px solid var(--high); }
    .summary-card.medium { border-top: 4px solid var(--medium); }
    .summary-card.low { border-top: 4px solid var(--low); }
    .summary-count { font-size: 36px; font-weight: 800; }
    .summary-label { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-top: 4px; }
    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 20px;
      page-break-inside: avoid;
    }
    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }
    .finding-title { font-size: 18px; font-weight: 700; color: #fff; }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 8px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      font-family: 'JetBrains Mono', monospace;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }
    .badge-medium { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }
    .finding-meta { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-muted); margin-bottom: 16px; }
    .finding-meta span { margin-right: 16px; }
    .desc { font-size: 14px; color: #cbd5e1; margin-bottom: 16px; }
    pre {
      background: #060911;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #67e8f9;
      overflow-x: auto;
      margin-bottom: 16px;
      white-space: pre-wrap;
    }
    .remediation-box {
      background: rgba(16, 185, 129, 0.08);
      border: 1px solid rgba(16, 185, 129, 0.25);
      border-radius: 12px;
      padding: 14px;
      font-size: 13px;
      color: #6ee7b7;
    }
    .print-btn {
      background: var(--accent);
      color: #000;
      font-weight: 700;
      border: none;
      padding: 10px 20px;
      border-radius: 10px;
      cursor: pointer;
      font-size: 13px;
    }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .print-btn { display: none; }
      .meta-box, .finding-card, .summary-card { background: #fff; border-color: #e2e8f0; color: #000; }
      .finding-title, .header h1, .meta-item .val { color: #000 !important; }
      .desc { color: #334155; }
      pre { background: #f8fafc; color: #0f172a; border-color: #cbd5e1; }
      .remediation-box { background: #f0fdf4; border-color: #86efac; color: #166534; }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Cyber Hashira Audit Report</h1>
        <div class="subtitle">Unified Cybersecurity Station & Penetration Testing Triage</div>
      </div>
      <button class="print-btn" onclick="window.print()">Print to PDF</button>
    </div>

    <div class="meta-box">
      <div class="meta-item">
        <div class="label">Date Generated</div>
        <div class="val">${dateStr}</div>
      </div>
      <div class="meta-item">
        <div class="label">Project Workspace</div>
        <div class="val">${metadata.projectName || "General Security Audit"}</div>
      </div>
      <div class="meta-item">
        <div class="label">Scope Policy</div>
        <div class="val">${metadata.targetScope || "ScopeGuard Enforced"}</div>
      </div>
      <div class="meta-item">
        <div class="label">Total Findings</div>
        <div class="val">${findings.length} Records</div>
      </div>
    </div>

    <div class="summary-grid">
      <div class="summary-card critical">
        <div class="summary-count" style="color: var(--critical)">${critCount}</div>
        <div class="summary-label">Critical</div>
      </div>
      <div class="summary-card high">
        <div class="summary-count" style="color: var(--high)">${highCount}</div>
        <div class="summary-label">High</div>
      </div>
      <div class="summary-card medium">
        <div class="summary-count" style="color: var(--medium)">${medCount}</div>
        <div class="summary-label">Medium</div>
      </div>
      <div class="summary-card low">
        <div class="summary-count" style="color: var(--low)">${lowCount}</div>
        <div class="summary-label">Low / Info</div>
      </div>
    </div>

    <h2 style="font-size: 20px; font-weight: 700; margin-bottom: 20px;">Vulnerability Findings</h2>

    ${findings
      .map(
        (f) => `
      <div class="finding-card">
        <div class="finding-header">
          <div class="finding-title">${f.title}</div>
          <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
        </div>
        <div class="finding-meta">
          <span>Module: ${f.module_id}</span>
          ${f.cvss_v3 ? `<span>CVSS: ${f.cvss_v3}</span>` : ""}
          ${f.cve ? `<span>CVE: ${f.cve}</span>` : ""}
          ${f.cwe ? `<span>CWE: ${f.cwe}</span>` : ""}
        </div>
        <div class="desc">${f.description}</div>
        ${f.evidence ? `<pre>${f.evidence}</pre>` : ""}
        ${
          f.remediation
            ? `<div class="remediation-box"><strong>Remediation:</strong> ${f.remediation}</div>`
            : ""
        }
      </div>
    `
      )
      .join("")}
  </div>
</body>
</html>`;
};

export const downloadBlob = (content: string, filename: string, mime: string) => {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};
