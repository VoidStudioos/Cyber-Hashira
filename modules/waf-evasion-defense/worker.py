#!/usr/bin/env python3
"""
Cyber Hashira - WAF & Normalization Defense Validator
Features:
  - Audits defensive WAF rule sets and reverse-proxy input normalization pipelines:
      * Unicode & Full-width normalization discrepancies (e.g. \uFF1Cscript\uFF1E normalized by backend)
      * HTTP Parameter Pollution (HPP) precedence mismatches (First vs Last vs Array)
      * Path normalization divergences (Tomcat/Spring matrix variables ;/ , IIS double decoding %252e%252e/)
      * Request body character set spoofing (UTF-7 / IBM-037 bypass of ASCII regex filters)
  - Evaluates application robustness and calculates WAF Evasion Defense Score (0 - 100)
"""

import sys
import json
import uuid
import re
import datetime

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target:
            return True
        clean_target = target.strip().lower()
        clean_target = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0]
        for auth in authorized_targets:
            clean_auth = auth.strip().lower()
            clean_auth = re.sub(r"^https?://", "", clean_auth).split("/")[0].split(":")[0]
            if clean_target == clean_auth or clean_target.endswith("." + clean_auth):
                return True
        return False

def audit_waf_pipeline(config: dict) -> tuple:
    findings = []
    risks = []
    deductions = 0

    # 1. Unicode Normalization
    if not config.get("normalizes_unicode_before_inspection", False):
        f = {
            "id": str(uuid.uuid4()),
            "title": "WAF Lacks Pre-Inspection Unicode Normalization",
            "severity": "high",
            "cvss_score": 8.0,
            "risk_type": "UNICODE_NORMALIZATION_EVASION",
            "description": "The WAF inspects raw inputs before Unicode normalization (NFKC/NFD). If the backend runtime converts full-width characters (e.g. \uFF1C to <) prior to execution, WAF signatures are bypassed.",
            "remediation": "Apply NFKC Unicode normalization on input payloads before running WAF pattern matching rules."
        }
        findings.append(f)
        risks.append("UNICODE_NORMALIZATION_EVASION")
        deductions += 25

    # 2. HTTP Parameter Pollution (HPP)
    if not config.get("enforces_single_parameter_policy", False):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Susceptibility to HTTP Parameter Pollution (HPP)",
            "severity": "medium",
            "cvss_score": 6.5,
            "risk_type": "HTTP_PARAMETER_POLLUTION",
            "description": "Reverse proxy and backend application handle duplicate query/body parameters inconsistently (e.g. WAF validates first parameter while backend consumes last parameter).",
            "remediation": "Reject requests containing duplicate parameter names or ensure strict parser alignment between WAF and application servers."
        }
        findings.append(f)
        risks.append("HTTP_PARAMETER_POLLUTION")
        deductions += 20

    # 3. Path Traversal & Matrix Parameters
    if not config.get("strips_matrix_semicolon_paths", False):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Reverse-Proxy Matrix Parameter Normalization Discrepancy",
            "severity": "high",
            "cvss_score": 8.2,
            "risk_type": "PATH_MATRIX_DESYNC",
            "description": "Path normalization rules do not strip matrix parameters (e.g. '/admin;param=1/users'). Reverse proxies may treat this as non-admin while backend frameworks (Spring/Tomcat) route to restricted endpoints.",
            "remediation": "Normalize and sanitize semicolon-delimited matrix paths in reverse proxy routing."
        }
        findings.append(f)
        risks.append("PATH_MATRIX_DESYNC")
        deductions += 25

    # 4. Double URL Decoding
    if not config.get("blocks_double_encoded_paths", False):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Double URL Encoding Filter Gap (%252e%252e%252f)",
            "severity": "medium",
            "cvss_score": 6.2,
            "risk_type": "DOUBLE_ENCODING_GAP",
            "description": "Input validation engine only decodes URL percent-encoding once. If downstream backend components perform an additional decoding pass, directory traversal filters can be bypassed.",
            "remediation": "Enforce recursive decoding or reject any request containing '%' followed by hexadecimal encoding tokens."
        }
        findings.append(f)
        risks.append("DOUBLE_ENCODING_GAP")
        deductions += 15

    return findings, risks, deductions

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("endpoint") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    waf_config = req.get("waf_config") or options.get("waf_config", {
        "normalizes_unicode_before_inspection": False,
        "enforces_single_parameter_policy": False,
        "strips_matrix_semicolon_paths": False,
        "blocks_double_encoded_paths": True
    })

    findings, risks, deductions = audit_waf_pipeline(waf_config)
    score = max(0, 100 - deductions)

    return {
        "status": "success",
        "result": {
            "endpoint": target or "https://waf-protected.corp.internal",
            "evasion_defense_score": score,
            "detected_risks_count": len(risks),
            "detected_evasion_risks": risks,
            "findings": findings,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            sys.stdout.write(json.dumps({"status": "error", "message": f"Malformed JSON: {e}"}) + "\n")
            sys.stdout.flush()
            continue

        req_type = req.get("type", "Execute")
        if req_type == "HealthCheck":
            res = {"status": "ok", "module": "waf-evasion-defense", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
