#!/usr/bin/env python3
"""Cyber Hashira - HSTS Preload & Transport Security Auditor (RFC 6797)"""
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

def audit_hsts(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    header_val = options.get("hsts_header", "")

    if not header_val:
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "hsts-preload-auditor",
            "target": clean_target,
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "description": f"The endpoint '{clean_target}' does not serve the Strict-Transport-Security header, allowing man-in-the-middle attackers to perform SSL-stripping.",
            "severity": "High",
            "cvss_v3": 7.4,
            "cwe": "CWE-319",
            "confidence": "Confirmed",
            "evidence": "Response headers lacked 'Strict-Transport-Security'.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", header_val, re.IGNORECASE)
        max_age = int(m.group(1)) if m else 0
        if max_age < 31536000:
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "hsts-preload-auditor",
                "target": clean_target,
                "title": "Insufficient HSTS max-age Directive",
                "description": f"HSTS max-age ({max_age}s) is less than the 1-year requirement (31536000s) for HSTS preload list eligibility.",
                "severity": "Medium",
                "cvss_v3": 4.8,
                "cwe": "CWE-319",
                "confidence": "Confirmed",
                "evidence": f"Strict-Transport-Security: {header_val}",
                "remediation": "Increase max-age to at least 31536000 seconds (1 year).",
                "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            })
        if "includesubdomains" not in header_val.lower():
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "hsts-preload-auditor",
                "target": clean_target,
                "title": "HSTS Missing includeSubDomains Directive",
                "description": "Subdomains of this host are vulnerable to plain-text HTTP downgrade attacks because 'includeSubDomains' is omitted.",
                "severity": "Low",
                "cvss_v3": 3.7,
                "cwe": "CWE-319",
                "confidence": "Confirmed",
                "evidence": f"Strict-Transport-Security: {header_val}",
                "remediation": "Append 'includeSubDomains' to the Strict-Transport-Security header.",
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
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "hsts-preload-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://api.target.corp")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_hsts(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
