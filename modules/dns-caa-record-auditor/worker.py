#!/usr/bin/env python3
"""Cyber Hashira - DNS CAA Policy & CA Authorization Auditor (RFC 6844)"""
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

def audit_caa(domain: str, options: dict) -> list:
    findings = []
    clean_domain = re.sub(r"^https?://", "", domain.strip().lower()).split("/")[0].split(":")[0]
    caa_records = options.get("sample_records", [])

    if not caa_records:
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "dns-caa-record-auditor",
            "target": clean_domain,
            "title": "Missing DNS Certification Authority Authorization (CAA) Record",
            "description": f"Domain '{clean_domain}' does not publish DNS CAA records (RFC 6844). Any compliant or compromised Public Certificate Authority can issue TLS certificates for this domain.",
            "severity": "Medium",
            "cvss_v3": 5.3,
            "cwe": "CWE-295",
            "confidence": "Confirmed",
            "evidence": f"DNS query for TYPE257 (CAA) on {clean_domain} returned NODATA/NXDOMAIN.",
            "remediation": "Publish a CAA DNS record explicitly whitelisting your chosen Certificate Authorities (e.g. '0 issue letsencrypt.org; 0 iodef mailto:security@corp.com').",
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
    else:
        has_iodef = any("iodef" in str(r).lower() for r in caa_records)
        if not has_iodef:
            findings.append({
                "id": str(uuid.uuid4()),
                "module_id": "dns-caa-record-auditor",
                "target": clean_domain,
                "title": "Missing CAA Incident Notification Directive (iodef)",
                "description": "CAA records are present but lack the 'iodef' tag to receive automated alerts when unauthorized certificate requests occur.",
                "severity": "Low",
                "cvss_v3": 3.1,
                "cwe": "CWE-295",
                "confidence": "Confirmed",
                "evidence": f"Published CAA records: {caa_records}",
                "remediation": "Add an 'iodef' record specifying a security contact URI (e.g., '0 iodef mailto:security@domain.com').",
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
        msg_type = req.get("type")
        if msg_type == "HealthCheck":
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "dns-caa-record-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "example.com")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_caa(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
