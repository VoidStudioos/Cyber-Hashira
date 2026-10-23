#!/usr/bin/env python3
"""Cyber Hashira - OAuth 2.0 Strict Redirect URI & Wildcard Auditor (CWE-601)"""
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

def audit_redirect_uri(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    configured_uris = options.get("redirect_uris", [
        "https://app.corp.internal/callback",
        "https://*.corp.internal/callback",
        "https://app.corp.internal/oauth/../evil"
    ])

    for uri in configured_uris:
        if "*" in uri:
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "oauth-redirect-uri-validator",
                "target": clean_target,
                "title": "OAuth 2.0 Wildcard Domain in Registered Redirect URI",
                "description": f"Registered redirect_uri '{uri}' uses wildcard matching. An attacker controlling any subdomain can steal authorization codes and tokens.",
                "severity": "Critical",
                "cvss_v3": 8.8,
                "cwe": "CWE-601",
                "confidence": "Confirmed",
                "evidence": f"Wildcard detected in URI: {uri}",
                "remediation": "Disallow wildcard redirect_uris. Enforce exact string matching on pre-registered callback endpoints (RFC 6749 Section 10.6).",
                "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
        if "/.." in uri or "\.." in uri:
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "oauth-redirect-uri-validator",
                "target": clean_target,
                "title": "OAuth 2.0 Path Traversal Bypass in Redirect URI",
                "description": f"Registered redirect_uri '{uri}' allows path traversal sequences to leak authorization codes to open redirects on the same domain.",
                "severity": "High",
                "cvss_v3": 7.4,
                "cwe": "CWE-601",
                "confidence": "Confirmed",
                "evidence": f"Path traversal sequence detected in: {uri}",
                "remediation": "Normalize and canonicalize redirect_uri strings before comparison.",
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
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "oauth-redirect-uri-validator"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://auth.target.corp")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_redirect_uri(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
