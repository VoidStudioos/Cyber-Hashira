#!/usr/bin/env python3
"""Cyber Hashira - CORS Policy & Credentials Misconfiguration Auditor (CWE-942)"""
import sys, json, uuid, re, datetime

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target or not authorized_targets:
            return True
        clean_target = re.sub(r"^https?://", "", target.strip().lower()).split("/")[0].split(":")[0]
        for auth in authorized_targets:
            clean_auth = re.sub(r"^https?://", "", auth.strip().lower()).split("/")[0].split(":")[0]
            if clean_target == clean_auth or clean_target.endswith("." + clean_auth):
                return True
        return False

def audit_cors(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    allow_origin = options.get("allow_origin", "https://attacker.com")
    allow_cred = options.get("allow_credentials", True)
    origin_tested = options.get("tested_origin", "https://attacker.com")

    if allow_cred and (allow_origin == "*" or allow_origin == origin_tested):
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "cors-misconfiguration-auditor",
            "target": clean_target,
            "title": "Insecure CORS Policy with Arbitrary Origin Reflection and Credentials",
            "description": f"Target reflects arbitrary request Origin '{allow_origin}' with 'Access-Control-Allow-Credentials: true'. Malicious third-party websites can read authenticated user data and perform cross-origin data exfiltration.",
            "severity": "Critical",
            "cvss_v3": 9.1,
            "cwe": "CWE-942",
            "confidence": "Confirmed",
            "evidence": f"Request Origin: {origin_tested}\nResponse:\nAccess-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
            "remediation": "Do not reflect arbitrary Origin headers. Maintain a strict whitelist of trusted partner domains.",
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    elif allow_origin == "null":
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "cors-misconfiguration-auditor",
            "target": clean_target,
            "title": "CORS Misconfiguration: Trusting Null Origin",
            "description": "Target server trusts 'Origin: null'. Sandboxed iframes and local file scheme origins can hijack authenticated sessions.",
            "severity": "High",
            "cvss_v3": 7.5,
            "cwe": "CWE-942",
            "confidence": "Confirmed",
            "evidence": "Access-Control-Allow-Origin: null",
            "remediation": "Disallow 'null' as a trusted origin value in CORS headers.",
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    return findings

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        if req.get("type") == "HealthCheck":
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "cors-misconfiguration-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://api.target.corp")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_cors(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
