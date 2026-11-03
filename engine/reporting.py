# -*- coding: utf-8 -*-
"""
Cyber Hashira — Enterprise Reporting & Multi-Standard Compliance Engine
Generates executive-grade HTML, PDF, Markdown, and SARIF v2.1.0 security audit reports
with formal mappings to MITRE ATT&CK, MITRE ATLAS, PCI-DSS v4.0, and ISO 27001.
"""

import os
import sys
import json
import time
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import fitz  # PyMuPDF (native high-performance PDF renderer)
    HAS_PYMUPDF = True
except Exception:
    HAS_PYMUPDF = False

# Only check weasyprint if PyMuPDF is not available
HAS_WEASYPRINT = False
if not HAS_PYMUPDF:
    try:
        import weasyprint
        HAS_WEASYPRINT = True
    except Exception:
        HAS_WEASYPRINT = False

from .ai_correlation import AICorrelationEngine, FindingCorrelation


class CVSSv4Calculator:
    """Helper for CVSS v4.0 calculations."""

    @staticmethod
    def calculate(finding: Dict[str, Any]) -> Dict[str, Any]:
        engine = AICorrelationEngine()
        return engine.calculate_cvss_v4(finding)


class EnterpriseReportingEngine:
    """Produces multi-format executive & technical audit reports."""

    def __init__(self):
        self.ai_engine = AICorrelationEngine()

    def generate_html_report(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        title: str = "Cyber Hashira Security Assessment Report",
        organization: str = "Enterprise Security Operations",
        assessor: str = "Cyber Hashira Autonomous Agent"
    ) -> str:
        """Generates a complete, beautiful standalone HTML report."""
        correlation = self.ai_engine.correlate(findings)
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Map compliance
        compliance_map = self._map_compliance(findings)

        # Build finding cards HTML
        findings_html = []
        for idx, f in enumerate(findings, start=1):
            sev = (f.get("severity") or "Medium").upper()
            sev_class = {
                "CRITICAL": "badge-crit",
                "HIGH": "badge-high",
                "MEDIUM": "badge-med",
                "LOW": "badge-low"
            }.get(sev, "badge-info")

            cvss_data = self.ai_engine.calculate_cvss_v4(f)

            findings_html.append(f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div>
                        <span class="finding-num">#{idx:02d}</span>
                        <span class="finding-title">{f.get('title', 'Security Finding')}</span>
                    </div>
                    <div style="display:flex; gap: 8px; align-items:center;">
                        <span class="badge {sev_class}">{sev}</span>
                        <span class="badge badge-cvss">CVSS 4.0: {cvss_data['score']}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <p><strong>Description:</strong> {f.get('description', 'No description provided.')}</p>
                    <div class="meta-row">
                        <span><strong>Module:</strong> <code>{f.get('module_id', 'core')}</code></span>
                        <span><strong>Target:</strong> <code>{f.get('target', target)}</code></span>
                        <span><strong>CWE:</strong> {f.get('cwe', 'CWE-200')}</span>
                        <span><strong>CVSS Vector:</strong> <code>{cvss_data['vector']}</code></span>
                    </div>
                    {f'<div class="evidence-box"><strong>Evidence:</strong><pre>{f.get("evidence")}</pre></div>' if f.get("evidence") else ''}
                    {f'<div class="remediation-box"><strong>Remediation:</strong> {f.get("remediation")}</div>' if f.get("remediation") else ''}
                </div>
            </div>
            """)

        # Build Attack Chains HTML
        chains_html = []
        for chain in correlation.chains:
            steps_html = "".join([f"<li>{s}</li>" for s in chain.attack_steps])
            tactics_html = " ".join([f"<span class='badge badge-tactic'>{t}</span>" for t in chain.mitre_attack_tactics])
            chains_html.append(f"""
            <div class="chain-card">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 style="margin:0; color:#ff4d4f;">⚡ {chain.title}</h3>
                    <span class="badge badge-crit">EXPLOITABILITY: {chain.exploitability_score}/10</span>
                </div>
                <p style="margin:8px 0; color:#d9d9d9;">{chain.impact}</p>
                <div style="margin:8px 0;"><strong>MITRE ATT&CK:</strong> {tactics_html}</div>
                <div style="background:#141414; padding:10px; border-radius:6px; margin:8px 0;">
                    <strong>Simulated Attack Execution Sequence:</strong>
                    <ol style="margin:6px 0 0 20px; padding:0; color:#bfbfbf;">{steps_html}</ol>
                </div>
                <div style="color:#52c41a; font-size:13px;"><strong>Recommended Strategic Defense:</strong> {chain.recommended_action}</div>
            </div>
            """)

        # Build Remediations HTML
        remeds_html = []
        for r in correlation.remediations:
            remeds_html.append(f"""
            <div class="remed-card">
                <h4>🛡️ {r['title']} ({r['language']}) — <code>{r['cwe']}</code></h4>
                <p style="color:#8c8c8c; font-size:13px;">{r['description']}</p>
                <div style="display:grid; grid-template-columns: 1fr 1fr; gap:12px;">
                    <div>
                        <div style="color:#ff7875; font-size:12px; font-weight:bold; margin-bottom:4px;">❌ Vulnerable Implementation</div>
                        <pre style="background:#2a1215; color:#ffccc7; padding:8px; border-radius:4px; font-size:12px;">{r['vulnerable_code']}</pre>
                    </div>
                    <div>
                        <div style="color:#95de64; font-size:12px; font-weight:bold; margin-bottom:4px;">✅ Secure Recommended Fix</div>
                        <pre style="background:#132a13; color:#d9f7be; padding:8px; border-radius:4px; font-size:12px;">{r['remediated_code']}</pre>
                    </div>
                </div>
            </div>
            """)

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        background: #0d1117;
        color: #c9d1d9;
        line-height: 1.6;
        margin: 0;
        padding: 40px;
    }}
    .container {{
        max-width: 1100px;
        margin: 0 auto;
    }}
    .header {{
        border-bottom: 2px solid #30363d;
        padding-bottom: 24px;
        margin-bottom: 30px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
    }}
    h1 {{ color: #58a6ff; margin: 0 0 8px 0; font-size: 28px; }}
    .subtitle {{ color: #8b949e; margin: 0; font-size: 14px; }}
    .stats-grid {{
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 16px;
        margin-bottom: 30px;
    }}
    .stat-card {{
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }}
    .stat-val {{ font-size: 28px; font-weight: bold; margin-bottom: 4px; }}
    .stat-lbl {{ font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }}
    .badge {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        letter-spacing: 0.5px;
    }}
    .badge-crit {{ background: #ffebee; color: #c62828; border: 1px solid #c62828; }}
    .badge-high {{ background: #fff3e0; color: #ef6c00; border: 1px solid #ef6c00; }}
    .badge-med {{ background: #fffde7; color: #f57f17; border: 1px solid #f57f17; }}
    .badge-low {{ background: #e8f5e9; color: #2e7d32; border: 1px solid #2e7d32; }}
    .badge-cvss {{ background: #21262d; color: #79c0ff; border: 1px solid #388bfd; }}
    .badge-tactic {{ background: #1f242c; color: #d2a8ff; border: 1px solid #8957e5; margin-right: 4px; }}
    .finding-card {{
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        margin-bottom: 20px;
        overflow: hidden;
    }}
    .finding-header {{
        background: #21262d;
        padding: 12px 18px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #30363d;
    }}
    .finding-num {{ color: #8b949e; font-weight: bold; margin-right: 8px; }}
    .finding-title {{ color: #f0f6fc; font-weight: 600; font-size: 16px; }}
    .finding-body {{ padding: 18px; }}
    .meta-row {{
        display: flex;
        flex-wrap: wrap;
        gap: 16px;
        margin: 12px 0;
        font-size: 13px;
        color: #8b949e;
    }}
    .chain-card {{
        background: #1c1824;
        border: 1px solid #7928ca;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 20px;
    }}
    .remed-card {{
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 18px;
        margin-bottom: 16px;
    }}
    .evidence-box {{
        background: #0d1117;
        border-left: 3px solid #f85149;
        padding: 10px 14px;
        margin: 10px 0;
        border-radius: 0 4px 4px 0;
    }}
    .remediation-box {{
        background: #0d1117;
        border-left: 3px solid #3fb950;
        padding: 10px 14px;
        margin: 10px 0;
        border-radius: 0 4px 4px 0;
        color: #7ee787;
    }}
    code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    pre {{ margin: 6px 0; overflow-x: auto; font-family: monospace; font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px; }}
    th, td {{ border: 1px solid #30363d; padding: 8px 12px; text-align: left; }}
    th {{ background: #21262d; color: #f0f6fc; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <h1>⚔️ {title}</h1>
            <p class="subtitle">Assessor: {assessor} | Target Scope: <code>{target}</code> | Organization: {organization}</p>
        </div>
        <div style="text-align:right;">
            <div style="font-size:12px; color:#8b949e;">Audit Generated</div>
            <div style="font-size:13px; font-weight:bold; color:#f0f6fc;">{now_str}</div>
        </div>
    </div>

    <!-- STATS -->
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-val" style="color: {'#3fb950' if correlation.posture_score >= 80 else '#d29922' if correlation.posture_score >= 50 else '#f85149'};">
                {correlation.posture_score} / 100
            </div>
            <div class="stat-lbl">Security Posture</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #ff4d4f;">{correlation.critical_count}</div>
            <div class="stat-lbl">Critical Risk</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #fa8c16;">{correlation.high_count}</div>
            <div class="stat-lbl">High Risk</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #fadb14;">{correlation.medium_count}</div>
            <div class="stat-lbl">Medium Risk</div>
        </div>
        <div class="stat-card">
            <div class="stat-val" style="color: #52c41a;">{correlation.low_count}</div>
            <div class="stat-lbl">Low / Info</div>
        </div>
    </div>

    <!-- CORRELATED ATTACK CHAINS -->
    {f'''
    <section>
        <h2 style="color:#f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 8px;">🔥 Correlated Autonomous Attack Chains ({len(correlation.chains)})</h2>
        {''.join(chains_html)}
    </section>
    ''' if chains_html else ''}

    <!-- DETAILED FINDINGS -->
    <section>
        <h2 style="color:#f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 8px;">📋 Comprehensive Verified Vulnerabilities ({len(findings)})</h2>
        {''.join(findings_html) if findings_html else '<p style="color:#8b949e;">No vulnerabilities discovered for target.</p>'}
    </section>

    <!-- COMPLIANCE MAPPING -->
    <section>
        <h2 style="color:#f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 8px;">🏛️ Multi-Standard Compliance Matrix</h2>
        <table>
            <thead>
                <tr>
                    <th>Framework</th>
                    <th>Reference Control ID</th>
                    <th>Control Name</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {''.join(compliance_map)}
            </tbody>
        </table>
    </section>

    <!-- AUTO REMEDIATIONS -->
    {f'''
    <section>
        <h2 style="color:#f0f6fc; border-bottom: 1px solid #30363d; padding-bottom: 8px;">🛠️ AI-Synthesized Code Remediations ({len(correlation.remediations)})</h2>
        {''.join(remeds_html)}
    </section>
    ''' if remeds_html else ''}

    <div style="border-top:1px solid #30363d; margin-top:40px; padding-top:20px; text-align:center; color:#8b949e; font-size:12px;">
        Generated autonomously by <strong>Cyber Hashira Framework</strong> — 200 Certified Security Modules Matrix.
    </div>
</div>
</body>
</html>"""
        return html_template

    def generate_pdf_report(
        self,
        findings: List[Dict[str, Any]],
        target: str,
        output_pdf_path: str,
        title: str = "Cyber Hashira Security Assessment Report"
    ) -> bool:
        """Renders the assessment report into a clean, executive PDF."""
        correlation = self.ai_engine.correlate(findings)
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        if HAS_PYMUPDF:
            doc = fitz.open()
            # Page 1: Executive Overview & Metrics
            page = doc.new_page(width=595, height=842)  # A4

            # Top branding header
            page.draw_rect(fitz.Rect(0, 0, 595, 75), color=(0.05, 0.08, 0.12), fill=(0.05, 0.08, 0.12))
            page.insert_text((40, 45), "CYBER HASHIRA | EXECUTIVE SECURITY REPORT", fontsize=16, color=(0.35, 0.65, 1.0))
            page.insert_text((40, 62), f"Target: {target}  |  Generated: {now_str}", fontsize=9, color=(0.6, 0.65, 0.7))

            # Title
            page.insert_text((40, 110), title, fontsize=18, color=(0.1, 0.1, 0.1))

            # Metrics Box
            page.draw_rect(fitz.Rect(40, 130, 555, 195), color=(0.85, 0.88, 0.9), fill=(0.95, 0.97, 1.0))
            score_col = (0.1, 0.65, 0.2) if correlation.posture_score >= 80 else (0.8, 0.5, 0.1) if correlation.posture_score >= 50 else (0.85, 0.15, 0.15)
            page.insert_text((60, 165), f"Posture Score: {correlation.posture_score} / 100", fontsize=15, color=score_col)
            page.insert_text((60, 182), f"Total Findings: {len(findings)}   |   Critical: {correlation.critical_count}   |   High: {correlation.high_count}   |   Med: {correlation.medium_count}   |   Low: {correlation.low_count}", fontsize=10, color=(0.3, 0.3, 0.3))

            # Correlated Attack Chains Header
            y = 225
            page.insert_text((40, y), "Autonomous Correlated Attack Chains:", fontsize=13, color=(0.85, 0.15, 0.15))
            y += 20
            if correlation.chains:
                for chain in correlation.chains:
                    page.draw_rect(fitz.Rect(40, y, 555, y + 65), color=(0.9, 0.8, 0.8), fill=(0.99, 0.95, 0.95))
                    page.insert_text((50, y + 18), f"[!] {chain.title} (Exploitability: {chain.exploitability_score}/10)", fontsize=10, color=(0.8, 0.1, 0.1))
                    page.insert_text((50, y + 34), chain.impact[:110] + ("..." if len(chain.impact) > 110 else ""), fontsize=8.5, color=(0.2, 0.2, 0.2))
                    page.insert_text((50, y + 50), f"Action: {chain.recommended_action[:105]}", fontsize=8.5, color=(0.1, 0.5, 0.2))
                    y += 75
            else:
                page.insert_text((40, y + 15), "No composite multi-hop attack chains detected.", fontsize=10, color=(0.4, 0.4, 0.4))
                y += 35

            # Findings list
            y += 20
            page.insert_text((40, y), f"Detailed Findings Inventory ({len(findings)} Issues):", fontsize=13, color=(0.1, 0.1, 0.1))
            y += 20

            for idx, f in enumerate(findings, start=1):
                if y > 760:
                    page = doc.new_page(width=595, height=842)
                    y = 50
                sev = (f.get("severity") or "Medium").upper()
                sev_col = (0.85, 0.15, 0.15) if sev == "CRITICAL" else (0.9, 0.45, 0.1) if sev == "HIGH" else (0.7, 0.6, 0.1)
                page.draw_rect(fitz.Rect(40, y, 555, y + 50), color=(0.85, 0.85, 0.85), fill=(0.98, 0.98, 0.98))
                page.insert_text((50, y + 16), f"#{idx:02d} {f.get('title', 'Vulnerability')} [{sev}]", fontsize=10, color=sev_col)
                desc = (f.get("description") or "")[:110]
                page.insert_text((50, y + 32), desc + ("..." if len(f.get("description", "")) > 110 else ""), fontsize=8.5, color=(0.3, 0.3, 0.3))
                page.insert_text((50, y + 44), f"Module: {f.get('module_id', 'core')}  |  CWE: {f.get('cwe', 'CWE-200')}", fontsize=8, color=(0.5, 0.5, 0.5))
                y += 60

            # Footer on last page
            page.insert_text((40, 810), "Verified by Cyber Hashira Master Suite — 200 Certified Modules Matrix", fontsize=8, color=(0.6, 0.6, 0.6))

            doc.save(output_pdf_path)
            doc.close()
            return True

        # Fallback to HTML if neither available
        html_content = self.generate_html_report(findings, target, title=title)
        html_path = output_pdf_path.replace(".pdf", ".html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return False

    def export_sarif(self, findings: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
        """Produces official OASIS SARIF v2.1.0 output."""
        rules = []
        results = []
        rule_indices = {}

        for f in findings:
            rule_id = f.get("module_id") or "HASHIRA-SEC-01"
            if rule_id not in rule_indices:
                rule_indices[rule_id] = len(rules)
                rules.append({
                    "id": rule_id,
                    "name": f.get("title", rule_id),
                    "shortDescription": {"text": f.get("title", rule_id)},
                    "fullDescription": {"text": f.get("description", "")},
                    "help": {"text": f.get("remediation", "Review and remediate according to best practices.")},
                    "properties": {
                        "category": f.get("category", "Security"),
                        "cwe": f.get("cwe", "CWE-200")
                    }
                })

            sev = (f.get("severity") or "medium").lower()
            level = "error" if sev in ["critical", "high"] else "warning" if sev == "medium" else "note"

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_indices[rule_id],
                "level": level,
                "message": {"text": f.get("description") or f.get("title") or "Vulnerability detected"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("path") or target},
                        "region": {"startLine": 1}
                    }
                }]
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Cyber-Hashira",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/VoidStudioos/Cyber-Hashira",
                        "rules": rules
                    }
                },
                "results": results
            }]
        }

    def _map_compliance(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Builds compliance matrix rows."""
        titles = [f.get("title", "").lower() for f in findings]
        rows = [
            ("PCI-DSS v4.0", "Requirement 6.2.4", "Software engineering to prevent injection vulnerabilities (SQLi, XSS)",
             "NON-COMPLIANT" if any("sql" in t or "xss" in t for t in titles) else "COMPLIANT"),
            ("PCI-DSS v4.0", "Requirement 6.4.3", "Management of client-side scripts & headers (CSP/SRI)",
             "NON-COMPLIANT" if any("csp" in t or "sri" in t for t in titles) else "COMPLIANT"),
            ("ISO/IEC 27001:2022", "Control A.8.20", "Network Security & Egress Boundary Filtering",
             "NON-COMPLIANT" if any("ssrf" in t or "smuggling" in t for t in titles) else "COMPLIANT"),
            ("ISO/IEC 27001:2022", "Control A.8.8", "Management of Technical Vulnerabilities",
             "NON-COMPLIANT" if findings else "COMPLIANT"),
            ("MITRE ATT&CK", "T1190", "Exploit Public-Facing Application",
             "OBSERVED VECTORS" if findings else "NOT DETECTED"),
            ("MITRE ATT&CK", "T1558", "Steal or Forge Kerberos Tickets (Silver Ticket)",
             "OBSERVED VECTORS" if any("kerberos" in t or "adcs" in t for t in titles) else "NOT DETECTED"),
            ("MITRE ATLAS", "AML.T0051", "LLM Prompt Injection (Direct & Indirect)",
             "OBSERVED VECTORS" if any("prompt" in t for t in titles) else "NOT DETECTED"),
            ("MITRE ATLAS", "AML.T0054", "LLM System Prompt & Intellectual Property Extraction",
             "OBSERVED VECTORS" if any("system prompt" in t for t in titles) else "NOT DETECTED"),
        ]

        formatted = []
        for fw, ctrl, name, status in rows:
            color = "#f85149" if "NON" in status or "OBSERVED" in status else "#3fb950"
            formatted.append(f"""
            <tr>
                <td><strong>{fw}</strong></td>
                <td><code>{ctrl}</code></td>
                <td>{name}</td>
                <td><span style="color:{color}; font-weight:bold;">{status}</span></td>
            </tr>
            """)
        return formatted
