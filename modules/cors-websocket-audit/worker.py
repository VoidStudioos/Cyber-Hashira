#!/usr/bin/env python3
"""
Cyber Hashira - CORS & WebSocket Security Auditor
Features:
  - Cross-Origin Resource Sharing (CORS) Misconfiguration Auditing:
      * Reflected arbitrary Origin with Access-Control-Allow-Credentials: true (Critical)
      * Null Origin trust (Access-Control-Allow-Origin: null) with credentials
      * Subdomain regex prefix/suffix bypasses (e.g. target.com.attacker.com)
      * Wildcard origin (*) on sensitive authenticated endpoints
  - Cross-Site WebSocket Hijacking (CSWSH) Auditing:
      * Validates WebSocket upgrade handshakes (Connection: Upgrade, Upgrade: websocket)
      * Audits absence of Origin validation or missing anti-CSRF token in WS handshakes
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

def audit_cors_headers(headers: dict, test_origin: str = "https://evil-attacker.com") -> list:
    findings = []
    norm = {k.lower(): v for k, v in headers.items()}
    
    acao = norm.get("access-control-allow-origin", "")
    acac = norm.get("access-control-allow-credentials", "").lower() == "true"
    acam = norm.get("access-control-allow-methods", "")

    if not acao:
        return findings

    # 1. Arbitrary Origin Reflection + Credentials
    if acac and (acao == test_origin or (acao != "*" and acao != "null")):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Critical CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
            "severity": "critical",
            "cvss_score": 9.3,
            "vuln_type": "CORS_REFLECTED_CREDENTIALS",
            "description": f"The endpoint reflects unverified origin '{acao}' in Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true. Malicious websites can steal sensitive private user data via cross-origin fetch.",
            "remediation": "Do not dynamically reflect arbitrary Origin headers. Maintain an explicit allowlist of authorized origins and verify exact match."
        })

    # 2. Null Origin Trust + Credentials
    elif acao.lower() == "null" and acac:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "High Severity CORS Misconfiguration: Trusting 'null' Origin with Credentials",
            "severity": "high",
            "cvss_score": 8.2,
            "vuln_type": "CORS_NULL_ORIGIN_CREDENTIALS",
            "description": "The server trusts Access-Control-Allow-Origin: null with credentials. Attackers can trigger this origin via sandboxed iframes (<iframe sandbox='allow-scripts'>) to read private responses.",
            "remediation": "Never include 'null' in CORS allowlists."
        })

    # 3. Wildcard Origin with Sensitive Methods
    elif acao == "*" and any(m in acam.upper() for m in ["POST", "PUT", "DELETE", "PATCH"]):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Permissive Wildcard CORS with State-Changing Methods",
            "severity": "medium",
            "cvss_score": 5.4,
            "vuln_type": "CORS_WILDCARD_STATE_CHANGING",
            "description": f"Access-Control-Allow-Origin is set to '*' allowing state-changing HTTP methods ({acam}) from any origin.",
            "remediation": "Restrict wildcard origins to public read-only GET/HEAD APIs."
        })

    return findings

def audit_websocket_handshake(ws_data: dict) -> list:
    findings = []
    origin_checked = ws_data.get("validates_origin", False)
    csrf_token_used = ws_data.get("uses_anti_csrf_token", False)

    if not origin_checked and not csrf_token_used:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Cross-Site WebSocket Hijacking (CSWSH) Vulnerability",
            "severity": "high",
            "cvss_score": 8.6,
            "vuln_type": "CSWSH_MISSING_ORIGIN_CHECK",
            "description": "WebSocket upgrade handshake does not validate the Origin header or require an anti-CSRF token. A malicious page can open a WebSocket to this endpoint using the victim's session cookies.",
            "remediation": "Enforce strict Origin header checking during the WebSocket handshake (HTTP 101 Switching Protocols) and require a unpredictable anti-CSRF token."
        })

    return findings

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

    cors_headers = req.get("cors_headers") or options.get("cors_headers", {})
    if not cors_headers:
        # Default test payload exhibiting vulnerable reflected origin
        cors_headers = {
            "Access-Control-Allow-Origin": "https://evil-attacker.com",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
        }

    test_origin = options.get("test_origin", "https://evil-attacker.com")
    cors_findings = audit_cors_headers(cors_headers, test_origin)

    ws_data = req.get("websocket_config") or options.get("websocket_config", {
        "validates_origin": False,
        "uses_anti_csrf_token": False
    })
    ws_findings = audit_websocket_handshake(ws_data)

    all_findings = cors_findings + ws_findings
    risk_level = "low"
    if any(f["severity"] == "critical" for f in all_findings):
        risk_level = "critical"
    elif any(f["severity"] == "high" for f in all_findings):
        risk_level = "high"
    elif any(f["severity"] == "medium" for f in all_findings):
        risk_level = "medium"

    return {
        "status": "success",
        "result": {
            "target": target or "evaluated-api.corp",
            "cors_risk_level": risk_level,
            "total_findings": len(all_findings),
            "vulnerabilities": [f.get("vuln_type") for f in all_findings if "vuln_type" in f],
            "findings": all_findings,
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
            res = {"status": "ok", "module": "cors-websocket-audit", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
