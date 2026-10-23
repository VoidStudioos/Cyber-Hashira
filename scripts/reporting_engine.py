#!/usr/bin/env python3
"""
Cyber Hashira — Evidence, Normalization, Deduplication & Reporting Pipeline
Implements Phase 1 specifications from CYBER_HASHIRA_MODULE_AUDIT_AND_ROADMAP.md:
  1. Secret Redaction (Auto-masks tokens, passwords, private keys, and cloud credentials)
  2. Cross-Module Finding Deduplication & Correlation Engine
  3. OASIS SARIF v2.1.0 Export (GitHub Code Scanning & DefectDojo compatible)
  4. Enterprise Executive & Technical Assessment Report (HTML & PDF printable)
  5. Machine-readable Structured Audit JSON Export
"""

import os
import sys
import json
import re
import hashlib
import uuid
import datetime
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional

# ==============================================================================
# 1. SECRET & CREDENTIAL REDACTION ENGINE
# ==============================================================================

REDACTION_PATTERNS = [
    # Private Keys (RSA, EC, OpenSSH, PGP)
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    
    # AWS Access Keys & Secret Keys
    (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "[REDACTED_AWS_KEY]"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "aws_secret_access_key=[REDACTED_AWS_SECRET]"),
    
    # Bearer & Authorization Headers
    (r"(?i)Bearer\s+[a-zA-Z0-9_\-\.]{16,}", "Bearer [REDACTED_BEARER_TOKEN]"),
    (r"(?i)Basic\s+[a-zA-Z0-9+/=]{16,}", "Basic [REDACTED_BASIC_AUTH]"),
    
    # JWT Tokens (eyJ...)
    (r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED_JWT_TOKEN]"),
    
    # Password in URLs / Connection strings
    (r"(https?|postgres|mysql|mongodb|redis)://([^:]+):([^@]+)@", r"\1://\2:[REDACTED_PASSWORD]@"),
    
    # Common API Keys, Passwords, Tokens in Key-Value pairs
    (r"(?i)(api[_-]?key|secret|password|passwd|token|auth_token|client_secret)\s*[:=]\s*['\"]?([^\s'\",;&]{8,})['\"]?", r"\1=[REDACTED_SECRET]")
]

def redact_sensitive_data(text: Optional[str]) -> str:
    """Sanitizes text by masking API keys, credentials, and cryptographic secrets."""
    if not text:
        return ""
    sanitized = str(text)
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = re.sub(pattern, replacement, sanitized)
    return sanitized

# ==============================================================================
# 2. CROSS-MODULE FINDING NORMALIZATION & DEDUPLICATION
# ==============================================================================

SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1
}

def normalize_severity(sev: Optional[str]) -> str:
    s = (sev or "Medium").strip().lower()
    if s == "info":
        return "Informational"
    return s.capitalize()

def generate_canonical_key(f: Dict[str, Any]) -> str:
    """
    Computes a canonical signature for finding correlation.
    Groups duplicate reports of the same issue from multiple modules on the same target.
    """
    raw_target = (f.get("target_id") or f.get("target") or "").strip().lower()
    if "://" in raw_target:
        try:
            parsed = urllib.parse.urlparse(raw_target)
            target = f"{parsed.scheme}://{parsed.netloc}"
            target_path = parsed.path.rstrip("/")
        except Exception:
            target = raw_target
            target_path = ""
    else:
        target = raw_target
        target_path = ""

    path = (f.get("path") or f.get("endpoint") or "").strip().lower()
    if not path:
        path = target_path

    cwe = (f.get("cwe") or "").strip().upper()
    cve = (f.get("cve") or "").strip().upper()

    if cwe or cve:
        raw_signature = f"{target}|{path}|{cwe}|{cve}"
    else:
        title = (f.get("title") or "").strip().lower()
        clean_title = re.sub(r"\[.*?\]", "", title)
        words = sorted(set(re.findall(r"\b[a-z]{3,}\b", clean_title)))
        words_sig = "-".join(words[:5])
        raw_signature = f"{target}|{path}|||{words_sig}"

    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups duplicate findings discovered across multiple modules,
    preserving contributing module IDs and consolidating evidence cleanly.
    """
    grouped: Dict[str, Dict[str, Any]] = {}

    for raw_f in findings:
        f = dict(raw_f)
        # Apply secret redaction to description and evidence
        f["description"] = redact_sensitive_data(f.get("description", ""))
        f["evidence"] = redact_sensitive_data(f.get("evidence", ""))
        f["remediation"] = redact_sensitive_data(f.get("remediation", ""))
        f["severity"] = normalize_severity(f.get("severity"))

        c_key = generate_canonical_key(f)
        module_id = f.get("module_id", "generic")

        if c_key not in grouped:
            f["canonical_key"] = c_key
            f["discovered_by_modules"] = [module_id] if module_id else []
            f["duplicate_count"] = 1
            f["confidence"] = f.get("confidence", "Confirmed")
            grouped[c_key] = f
        else:
            existing = grouped[c_key]
            existing["duplicate_count"] += 1
            if module_id and module_id not in existing["discovered_by_modules"]:
                existing["discovered_by_modules"].append(module_id)

            # Keep higher severity if conflicting
            curr_weight = SEVERITY_WEIGHT.get(f["severity"].lower(), 3)
            ex_weight = SEVERITY_WEIGHT.get(existing["severity"].lower(), 3)
            if curr_weight > ex_weight:
                existing["severity"] = f["severity"]
                existing["cvss_v3"] = f.get("cvss_v3") or existing.get("cvss_v3")

            # Consolidate evidence if new information provided
            if f.get("evidence") and f["evidence"] not in existing.get("evidence", ""):
                existing["evidence"] = f"{existing.get('evidence', '')}\n[Also observed by {module_id}]: {f['evidence']}".strip()

    # Sort deduplicated list by severity weight descending
    deduped_list = list(grouped.values())
    deduped_list.sort(key=lambda x: SEVERITY_WEIGHT.get(x["severity"].lower(), 0), reverse=True)
    return deduped_list

# ==============================================================================
# 3. SARIF v2.1.0 EXPORTER (OASIS Standard)
# ==============================================================================

def export_sarif(findings: List[Dict[str, Any]], scan_metadata: Optional[Dict[str, Any]] = None) -> str:
    """Generates an OASIS SARIF 2.1.0 JSON document from findings."""
    if scan_metadata is None:
        scan_metadata = {}
    rules_dict: Dict[str, Any] = {}
    results_list: List[Dict[str, Any]] = []

    for f in findings:
        rule_id = f.get("cwe") or f.get("cve") or f.get("id") or "HASHIRA-SEC-001"
        severity = f.get("severity", "Medium").lower()

        # Map to SARIF level
        if severity in ["critical", "high"]:
            level = "error"
        elif severity == "medium":
            level = "warning"
        else:
            level = "note"

        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": f.get("title", "Security Vulnerability"),
                "shortDescription": {"text": f.get("title", "")},
                "fullDescription": {"text": f.get("description", "")},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": [
                        "security",
                        "vulnerability",
                        f.get("cwe", "CWE-Unspecified"),
                        f.get("module_id", "cyber-hashira")
                    ],
                    "precision": "high"
                }
            }
            if f.get("remediation"):
                rules_dict[rule_id]["help"] = {"text": f["remediation"]}

        target = f.get("target_id") or f.get("target") or "target-system"
        res_entry = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{f.get('title')}: {f.get('description')}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target
                        }
                    }
                }
            ],
            "properties": {
                "severity": f.get("severity"),
                "cvssV3": f.get("cvss_v3"),
                "confidence": f.get("confidence", "Confirmed"),
                "evidence": f.get("evidence"),
                "discoveredBy": f.get("discovered_by_modules", [f.get("module_id")]),
                "duplicateCount": f.get("duplicate_count", 1)
            }
        }
        results_list.append(res_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Cyber Hashira Security Assessment Workstation",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/VoidStudioos/Cyber-Hashira",
                        "rules": list(rules_dict.values())
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_metadata.get("start_time", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                        "endTimeUtc": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    }
                ],
                "results": results_list
            }
        ]
    }
    return json.dumps(sarif_doc, indent=2)

# ==============================================================================
# 4. EXECUTIVE & TECHNICAL HTML / PDF REPORT GENERATOR
# ==============================================================================

def calculate_security_score(findings: List[Dict[str, Any]]) -> Tuple[int, str]:
    """Calculates overall 0-100 security score and posture grade."""
    penalty = 0
    for f in findings:
        sev = f.get("severity", "Medium").lower()
        if sev == "critical":
            penalty += 25
        elif sev == "high":
            penalty += 15
        elif sev == "medium":
            penalty += 6
        elif sev == "low":
            penalty += 2

    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A (Robust)"
    elif score >= 75:
        grade = "B (Moderate Risk)"
    elif score >= 60:
        grade = "C (High Risk)"
    elif score >= 40:
        grade = "D (Critical Risk)"
    else:
        grade = "F (Compromised / Highly Vulnerable)"
    return score, grade

def export_html_report(findings: List[Dict[str, Any]], scan_metadata: Dict[str, Any]) -> str:
    """Generates an executive-ready, printable HTML/PDF report."""
    deduped = deduplicate_findings(findings)
    score, grade = calculate_security_score(deduped)
    
    crit_count = sum(1 for f in deduped if f["severity"].lower() == "critical")
    high_count = sum(1 for f in deduped if f["severity"].lower() == "high")
    med_count  = sum(1 for f in deduped if f["severity"].lower() == "medium")
    low_count  = sum(1 for f in deduped if f["severity"].lower() == "low")
    info_count = sum(1 for f in deduped if f["severity"].lower() in ["informational", "info"])

    project_name = scan_metadata.get("project_name", "Enterprise Security Assessment")
    target_name = scan_metadata.get("target", "Authorized Attack Surface")
    gen_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Render findings rows
    findings_html = ""
    for idx, f in enumerate(deduped, start=1):
        sev = f["severity"]
        sev_color = {
            "Critical": "#EF4444",
            "High": "#F97316",
            "Medium": "#F59E0B",
            "Low": "#10B981",
            "Informational": "#3B82F6"
        }.get(sev, "#6B7280")

        cwe_badge = f"<span class='badge cwe'>{f['cwe']}</span>" if f.get("cwe") else ""
        cve_badge = f"<span class='badge cve'>{f['cve']}</span>" if f.get("cve") else ""
        cvss_str = f"CVSS {f['cvss_v3']}" if f.get("cvss_v3") else ""
        modules_str = ", ".join(f.get("discovered_by_modules", [])) or f.get("module_id", "cyber-hashira")

        evidence_block = ""
        if f.get("evidence"):
            evidence_block = f"""
            <div class="evidence-box">
                <div class="field-title">TECHNICAL EVIDENCE &amp; REDACTED PROOF OF CONCEPT:</div>
                <pre><code>{f['evidence']}</code></pre>
            </div>
            """

        remediation_block = ""
        if f.get("remediation"):
            remediation_block = f"""
            <div class="remediation-box">
                <div class="field-title">REMEDIATION GUIDANCE:</div>
                <p>{f['remediation']}</p>
            </div>
            """

        findings_html += f"""
        <div class="finding-card border-{sev.lower()}">
            <div class="finding-header">
                <div class="finding-title-wrap">
                    <span class="finding-index">#{idx}</span>
                    <span class="badge sev-badge" style="background-color: {sev_color};">{sev.upper()}</span>
                    <strong class="finding-title">{f['title']}</strong>
                </div>
                <div class="badges-row">
                    {cwe_badge} {cve_badge}
                    <span class="badge mono">{cvss_str}</span>
                </div>
            </div>
            <div class="finding-body">
                <p class="description">{f['description']}</p>
                <div class="meta-grid">
                    <div><strong>Discovered By:</strong> <code>{modules_str}</code></div>
                    <div><strong>Duplicate Merges:</strong> {f.get('duplicate_count', 1)} instance(s)</div>
                    <div><strong>Confidence:</strong> {f.get('confidence', 'Confirmed')}</div>
                </div>
                {evidence_block}
                {remediation_block}
            </div>
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cyber Hashira — Security Audit &amp; Penetration Test Report</title>
    <style>
        :root {{
            --bg: #0F172A;
            --surface: #1E293B;
            --surface-hover: #334155;
            --border: #334155;
            --text-main: #F8FAFC;
            --text-muted: #94A3B8;
            --brand: #38BDF8;
            --crit: #EF4444;
            --high: #F97316;
            --med: #F59E0B;
            --low: #10B981;
            --info: #3B82F6;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #F8FAFC;
            color: #0F172A;
            margin: 0;
            padding: 32px 20px;
            line-height: 1.5;
        }}
        .report-wrap {{
            max-width: 960px;
            margin: 0 auto;
            background: #FFFFFF;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
            padding: 40px;
            border: 1px solid #E2E8F0;
        }}
        .header {{
            border-bottom: 2px solid #E2E8F0;
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .brand-title {{
            font-size: 26px;
            font-weight: 800;
            color: #0F172A;
            letter-spacing: -0.5px;
        }}
        .brand-subtitle {{
            font-size: 14px;
            color: #64748B;
            margin-top: 4px;
        }}
        .exec-grid {{
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 24px;
            background: #F1F5F9;
            padding: 24px;
            border-radius: 10px;
            margin-bottom: 32px;
        }}
        .score-box {{
            text-align: center;
            border-right: 2px solid #CBD5E1;
            padding-right: 24px;
        }}
        .score-num {{
            font-size: 48px;
            font-weight: 900;
            color: #0284C7;
            font-family: monospace;
        }}
        .score-grade {{
            font-size: 13px;
            font-weight: bold;
            color: #334155;
            margin-top: 4px;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            text-align: center;
        }}
        .stat-card {{
            background: #FFFFFF;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid #E2E8F0;
        }}
        .stat-val {{
            font-size: 22px;
            font-weight: bold;
            font-family: monospace;
        }}
        .stat-lbl {{
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
            color: #64748B;
            margin-top: 2px;
        }}
        .finding-card {{
            background: #FFFFFF;
            border: 1px solid #E2E8F0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            border-left-width: 5px;
        }}
        .border-critical {{ border-left-color: var(--crit); }}
        .border-high {{ border-left-color: var(--high); }}
        .border-medium {{ border-left-color: var(--med); }}
        .border-low {{ border-left-color: var(--low); }}
        .border-informational {{ border-left-color: var(--info); }}

        .finding-header {{
            background: #F8FAFC;
            padding: 12px 18px;
            border-bottom: 1px solid #E2E8F0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .finding-title-wrap {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding-index {{
            font-weight: bold;
            color: #94A3B8;
        }}
        .finding-title {{
            font-size: 16px;
            color: #0F172A;
        }}
        .finding-body {{
            padding: 18px;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            color: #FFFFFF;
        }}
        .badge.cwe {{ background: #475569; }}
        .badge.cve {{ background: #0284C7; }}
        .badge.mono {{ background: #E2E8F0; color: #1E293B; font-family: monospace; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            background: #F8FAFC;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 12px;
            margin: 14px 0;
            border: 1px solid #E2E8F0;
        }}
        .evidence-box, .remediation-box {{
            margin-top: 12px;
            padding: 12px 14px;
            border-radius: 6px;
            font-size: 12.5px;
        }}
        .evidence-box {{
            background: #0F172A;
            color: #38BDF8;
            border: 1px solid #1E293B;
        }}
        .evidence-box pre {{
            margin: 6px 0 0;
            white-space: pre-wrap;
            word-break: break-all;
            font-family: monospace;
            font-size: 11.5px;
        }}
        .remediation-box {{
            background: #ECFDF5;
            color: #065F46;
            border: 1px solid #A7F3D0;
        }}
        .field-title {{
            font-size: 10.5px;
            font-weight: 800;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .btn-print {{
            background: #0284C7;
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
        }}
        @media print {{
            body {{ padding: 0; background: #fff; }}
            .report-wrap {{ box-shadow: none; border: none; padding: 0; max-width: 100%; }}
            .btn-print {{ display: none; }}
            .finding-card {{ break-inside: avoid; page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="report-wrap">
        <div class="header">
            <div>
                <div class="brand-title">CYBER HASHIRA \u2014 SECURITY ASSESSMENT REPORT</div>
                <div class="brand-subtitle">Automated Modular Cybersecurity Audit &amp; Penetration Testing</div>
                <div style="font-size: 12px; color: #64748B; margin-top: 6px;">
                    <strong>Project:</strong> {project_name} &bull; 
                    <strong>Target:</strong> {target_name} &bull; 
                    <strong>Date:</strong> {gen_time}
                </div>
            </div>
            <div>
                <button class="btn-print" onclick="window.print()">Print / Export PDF</button>
            </div>
        </div>

        <div class="exec-grid">
            <div class="score-box">
                <div class="score-num">{score}</div>
                <div style="font-size:11px; text-transform:uppercase; color:#64748B; font-weight:700;">Security Score / 100</div>
                <div class="score-grade">{grade}</div>
            </div>
            <div>
                <div style="font-size:13px; font-weight:700; margin-bottom:12px; color:#334155;">VULNERABILITY EXPOSURE BY SEVERITY</div>
                <div class="stat-grid">
                    <div class="stat-card" style="border-top: 3px solid var(--crit);">
                        <div class="stat-val" style="color:var(--crit);">{crit_count}</div>
                        <div class="stat-lbl">Critical</div>
                    </div>
                    <div class="stat-card" style="border-top: 3px solid var(--high);">
                        <div class="stat-val" style="color:var(--high);">{high_count}</div>
                        <div class="stat-lbl">High</div>
                    </div>
                    <div class="stat-card" style="border-top: 3px solid var(--med);">
                        <div class="stat-val" style="color:var(--med);">{med_count}</div>
                        <div class="stat-lbl">Medium</div>
                    </div>
                    <div class="stat-card" style="border-top: 3px solid var(--low);">
                        <div class="stat-val" style="color:var(--low);">{low_count}</div>
                        <div class="stat-lbl">Low</div>
                    </div>
                    <div class="stat-card" style="border-top: 3px solid var(--info);">
                        <div class="stat-val" style="color:var(--info);">{info_count}</div>
                        <div class="stat-lbl">Info</div>
                    </div>
                </div>
            </div>
        </div>

        <h3 style="margin-top: 32px; border-bottom: 2px solid #E2E8F0; padding-bottom: 8px;">
            DETAILED TECHNICAL FINDINGS &amp; EVIDENCE ({len(deduped)} Unique Findings)
        </h3>

        {findings_html}

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #E2E8F0; font-size: 11px; color: #94A3B8; text-align: center;">
            Generated by Cyber Hashira &bull; Secret Redaction Active &bull; ScopeGuard Verified Audit
        </div>
    </div>
</body>
</html>"""
    return html

# ==============================================================================
# 5. CLI & RUNNER INTERFACE
# ==============================================================================

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Cyber Hashira Evidence & Reporting Engine")
    parser.add_argument("--input-json", required=True, help="Path to raw JSON findings file")
    parser.add_argument("--format", choices=["sarif", "html", "json", "deduped"], default="html", help="Report export format")
    parser.add_argument("--output", required=True, help="Destination report output file")
    parser.add_argument("--project-name", default="Perimeter Security Assessment", help="Project label in report")
    parser.add_argument("--target", default="Authorized Target Surface", help="Target label in report")

    args = parser.parse_args()

    if not os.path.isfile(args.input_json):
        print(f"[!] Error: Input file not found: {args.input_json}")
        sys.exit(1)

    with open(args.input_json, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Accept either list of findings or object with findings key
    if isinstance(data, list):
        raw_findings = data
    else:
        raw_findings = data.get("findings", [])

    meta = {
        "project_name": args.project_name,
        "target": args.target,
        "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    if args.format == "sarif":
        deduped = deduplicate_findings(raw_findings)
        content = export_sarif(deduped, meta)
    elif args.format == "html":
        content = export_html_report(raw_findings, meta)
    elif args.format == "deduped":
        deduped = deduplicate_findings(raw_findings)
        content = json.dumps({"findings": deduped, "total": len(deduped)}, indent=2)
    else:
        # Standard JSON export with summary
        deduped = deduplicate_findings(raw_findings)
        score, grade = calculate_security_score(deduped)
        content = json.dumps({
            "metadata": meta,
            "security_score": score,
            "grade": grade,
            "total_findings": len(deduped),
            "findings": deduped
        }, indent=2)

    with open(args.output, "w", encoding="utf-8") as out_f:
        out_f.write(content)

    print(f"[+] Successfully generated {args.format.upper()} report -> {args.output}")

if __name__ == "__main__":
    main()
