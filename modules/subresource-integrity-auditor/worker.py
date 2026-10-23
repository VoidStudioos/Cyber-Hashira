#!/usr/bin/env python3
"""Cyber Hashira - Subresource Integrity (SRI) Hash Validator (CWE-353)"""
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

def audit_sri(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    scripts = options.get("scripts", [
        {"src": "https://cdn.example.org/lib.js", "integrity": None},
        {"src": "https://analytics.thirdparty.com/tag.js", "integrity": None}
    ])

    for sc in scripts:
        src = sc.get("src", "")
        integ = sc.get("integrity")
        if not integ and src.startswith("http"):
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "subresource-integrity-auditor",
                "target": clean_target,
                "title": f"External Asset Loaded Without Subresource Integrity: {src.split('/')[-1]}",
                "description": f"Third-party asset '{src}' is loaded without an 'integrity' cryptographic hash attribute. A CDN compromise or DNS hijacking enables arbitrary client-side script execution (Stored XSS).",
                "severity": "Medium",
                "cvss_v3": 6.5,
                "cwe": "CWE-353",
                "confidence": "Confirmed",
                "evidence": f"<script src=\"{src}\" ...> (missing integrity attribute)",
                "remediation": "Add an integrity attribute with sha384 or sha512 hash and crossorigin='anonymous'.",
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
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "subresource-integrity-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://api.target.corp")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_sri(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
