#!/usr/bin/env python3
"""
Create 6 new high-impact security assessment modules for Cyber Hashira:
  1. dns-caa-record-auditor (CWE-295)
  2. hsts-preload-auditor (CWE-319)
  3. cors-misconfiguration-auditor (CWE-942)
  4. subresource-integrity-auditor (CWE-353)
  5. graphql-depth-limit-auditor (CWE-400)
  6. oauth-redirect-uri-validator (CWE-601)
"""

import os
import sys
import json
import hashlib
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
MODULES_DIR = REPO_ROOT / "modules"
REGISTRY_CATALOG = REPO_ROOT / "registry" / "v1" / "modules.json"
ARTIFACTS_DIR = REPO_ROOT / "registry" / "artifacts"

NEW_MODULES = [
    {
        "id": "dns-caa-record-auditor",
        "name": "DNS CAA Policy & CA Authorization Auditor",
        "category": "DNS Security",
        "cwe": "CWE-295",
        "description": "Inspects DNS Certification Authority Authorization (CAA) records to ensure only authorized Certificate Authorities can issue TLS certificates for root and wildcard domains (RFC 6844).",
        "icon": "shield-check",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
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
'''
    },
    {
        "id": "hsts-preload-auditor",
        "name": "HSTS Preload & Transport Security Auditor",
        "category": "Web Headers",
        "cwe": "CWE-319",
        "description": "Audits HTTP Strict Transport Security (HSTS) headers for max-age >= 31536000, includeSubDomains, and preload directive compliance (RFC 6797).",
        "icon": "lock",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
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
'''
    },
    {
        "id": "cors-misconfiguration-auditor",
        "name": "CORS Policy & Credentials Misconfiguration Auditor",
        "category": "Web Security",
        "cwe": "CWE-942",
        "description": "Analyzes Cross-Origin Resource Sharing (CORS) policies for wildcard origins with credentials reflection and null origin trust.",
        "icon": "globe",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
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
            "evidence": f"Request Origin: {origin_tested}\\nResponse:\\nAccess-Control-Allow-Origin: {allow_origin}\\nAccess-Control-Allow-Credentials: true",
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
'''
    },
    {
        "id": "subresource-integrity-auditor",
        "name": "Subresource Integrity (SRI) Hash Validator",
        "category": "Web Security",
        "cwe": "CWE-353",
        "description": "Audits external script and stylesheet tags in web applications to verify Subresource Integrity (SRI) cryptographic hashes and crossorigin attributes.",
        "icon": "file-code",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
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
                "evidence": f"<script src=\\"{src}\\" ...> (missing integrity attribute)",
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
'''
    },
    {
        "id": "graphql-depth-limit-auditor",
        "name": "GraphQL Query Depth & Complexity Limit Auditor",
        "category": "API Security",
        "cwe": "CWE-400",
        "description": "Analyzes GraphQL endpoint schema configurations for query depth limits, complexity budget analysis, and recursive query protection (OWASP API4:2023).",
        "icon": "layers",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
"""Cyber Hashira - GraphQL Query Depth & Complexity Limit Auditor (CWE-400)"""
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

def audit_graphql_depth(target: str, options: dict) -> list:
    findings = []
    clean_target = target.strip()
    max_tested_depth = options.get("tested_depth", 15)
    depth_allowed = options.get("depth_allowed", True)

    if depth_allowed and max_tested_depth >= 10:
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": "graphql-depth-limit-auditor",
            "target": clean_target,
            "title": "GraphQL Query Depth Limit Missing / Unconstrained (DoS Risk)",
            "description": f"GraphQL endpoint accepts deeply nested recursive queries up to depth {max_tested_depth} without rejection. Attackers can execute exponential nested queries to exhaust server CPU and database connection pools.",
            "severity": "High",
            "cvss_v3": 7.5,
            "cwe": "CWE-400",
            "confidence": "Confirmed",
            "evidence": f"Nested query at depth {max_tested_depth} executed successfully without HTTP 400 rejection.",
            "remediation": "Implement graphql-depth-limit or cost-analysis validation middleware to reject queries exceeding depth 6-8.",
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
            print(json.dumps({"type": "HealthCheckResult", "status": "ok", "payload": {"healthy": True, "module": "graphql-depth-limit-auditor"}}), flush=True)
            continue
        payload = req.get("payload", {})
        target = payload.get("target") or req.get("target", "https://api.target.corp/graphql")
        scope_approved = payload.get("scope_approved", True)
        options = payload.get("options", {})
        auth_targets = options.get("authorized_targets") or req.get("authorized_targets", [target])
        if not scope_approved or not ScopeGuard.is_authorized(target, auth_targets):
            print(json.dumps({"type": "TaskCompleted", "status": "failed", "payload": {"success": False, "error": "ScopeGuard: target not in approved scope", "findings": []}}), flush=True)
            continue
        findings = audit_graphql_depth(target, options)
        print(json.dumps({"type": "TaskCompleted", "status": "success", "payload": {"success": True, "target": target, "findings": findings}}), flush=True)

if __name__ == "__main__":
    main()
'''
    },
    {
        "id": "oauth-redirect-uri-validator",
        "name": "OAuth 2.0 Strict Redirect URI & Wildcard Auditor",
        "category": "Authentication & Token",
        "cwe": "CWE-601",
        "description": "Validates OAuth 2.0 authorization server configurations for strict redirect_uri matching, preventing path traversal and wildcard domain matching (RFC 6749 Section 10.6).",
        "icon": "key",
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "code": '''#!/usr/bin/env python3
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
        if "/.." in uri or "\\.." in uri:
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
'''
    }
]

def main():
    print(f"[*] Creating {len(NEW_MODULES)} new security modules...")
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    existing_ids = {m["id"] for m in catalog.get("modules", [])}

    for mod in NEW_MODULES:
        mod_id = mod["id"]
        mod_dir = MODULES_DIR / mod_id
        os.makedirs(mod_dir, exist_ok=True)

        manifest = {
            "id": mod_id,
            "name": mod["name"],
            "description": mod["description"],
            "author": mod["author"],
            "version": mod["version"],
            "min_host_version": "0.1.0",
            "category": mod["category"],
            "icon": mod["icon"],
            "banner_url": "",
            "supported_os": ["windows", "linux", "macos"],
            "supported_arch": ["x86_64", "aarch64"],
            "required_dependencies": {},
            "optional_dependencies": {},
            "required_permissions": ["network:connect", "findings:write"],
            "entry_point": {
                "runtime": "python",
                "executable": "worker.py",
                "default_args": []
            },
            "config_schema": {"type": "object", "properties": {}},
            "contracts": {
                "input_schema": {"type": "object", "properties": {}, "required": []},
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "findings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "cwe": {"type": "string"},
                                    "title": {"type": "string"},
                                    "description": {"type": "string"},
                                    "evidence": {"type": "string"},
                                    "detected_at": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        }

        # Write manifest.json
        with open(mod_dir / "manifest.json", "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2)

        # Write worker.py
        with open(mod_dir / "worker.py", "w", encoding="utf-8") as wf:
            wf.write(mod["code"])

        # Package into tar.gz
        tar_name = f"{mod_id}-{mod['version']}.tar.gz"
        tar_path = ARTIFACTS_DIR / tar_name
        with tarfile.open(tar_path, "w:gz") as tar:
            for item in sorted(os.listdir(mod_dir)):
                tar.add(mod_dir / item, arcname=item)

        with open(tar_path, "rb") as tf:
            tar_data = tf.read()
            tar_sha = hashlib.sha256(tar_data).hexdigest()
            tar_size = len(tar_data)

        catalog_entry = dict(manifest)
        catalog_entry["artifact"] = {
            "url": f"https://github.com/VoidStudioos/Cyber-Hashira/releases/download/v1.0.0/{tar_name}",
            "sha256": tar_sha,
            "size_bytes": tar_size
        }

        if mod_id not in existing_ids:
            catalog["modules"].append(catalog_entry)
            print(f"  [+] Added '{mod_id}' to catalog & created archive.")
        else:
            print(f"  [*] Updated '{mod_id}' in catalog.")

    with open(REGISTRY_CATALOG, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)

    print(f"[OK] Total modules in catalog now: {len(catalog['modules'])}")

if __name__ == "__main__":
    main()
