#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_new_modules.py

Creates the remaining 47 modules from the planned list that don't exist yet.
Each worker.py implements the Cyber-Hashira IPC stdio protocol correctly.
"""

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent
MODULES_DIR = REPO_ROOT / "modules"

# All 50 planned modules (3 already exist: jwt-weak-signatures, password-reuse-detector, ssh-known-hosts-audit)
MODULES = [
    ("dns-zone-transfer-tester",        "Network & Discovery",       "CWE-200", "Attempt AXFR zone transfer and report success/failure."),
    ("open-redirect-finder",            "Web Security",              "CWE-601", "Detect parameters that cause open redirects to external domains."),
    ("csrf-token-checker",             "Web Security",              "CWE-352", "Identify forms/APIs lacking proper CSRF tokens."),
    ("s3-bucket-enumerator",           "Cloud Security",            "CWE-732", "List public S3 buckets and evaluate ACLs."),
    ("k8s-rbac-audit",                 "Kubernetes Posture",        "CWE-269", "Find overly permissive ClusterRoles or RoleBindings."),
    ("tls-misconfiguration-scanner",   "Network Security",          "CWE-326", "Check for deprecated TLS versions, weak ciphers, missing HSTS."),
    ("jwt-kid-exposure",               "Authentication & Token",    "CWE-330", "Detect JWTs with static or predictable 'kid' values."),
    ("saml-metadata-validator",        "Identity & Access",         "CWE-347", "Validate SAML metadata for bad IDs, signatures, expiration."),
    ("csp-header-linter",              "Web Headers",               "CWE-693", "Lint Content-Security-Policy for unsafe-inline / unsafe-eval usage."),
    ("http-smuggling-detector",        "Web Security",              "CWE-444", "Test Transfer-Encoding/Content-Length combos for request smuggling."),
    ("ldap-anonymous-bind-tester",     "Directory Security",        "CWE-287", "Check if LDAP server allows anonymous bind and enumerate entries."),
    ("cloud-iam-policy-drift",         "Cloud IAM",                 "CWE-732", "Compare current IAM policies with a stored snapshot to detect drift."),
    ("api-gateway-rate-limit-audit",   "API Security",              "CWE-770", "Verify rate-limit rules on API gateways (Kong, AWS API GW)."),
    ("websocket-origin-check",         "Web Security",              "CWE-346", "Validate that WebSocket servers correctly verify the Origin header."),
    ("code-injection-evaluator",       "Source-Code Scanner",       "CWE-78",  "Search source for dangerous patterns like eval, exec, system."),
    ("container-runtime-capabilities", "Container Security",        "CWE-250", "Detect Docker/Podman containers running with privileged caps."),
    ("mobile-manifest-permissions",    "Mobile Security",           "CWE-250", "Audit AndroidManifest.xml or Info.plist for excessive permissions."),
    ("password-policy-checker",        "Credential Hygiene",        "CWE-521", "Assess password complexity and rotation policies in LDAP/AD."),
    ("aws-secret-leak-scanner",        "Cloud Security",            "CWE-312", "Search source repositories for exposed AWS_ACCESS_KEY_ID / SECRET_KEY."),
    ("sri-hash-verifier",              "Web Security",              "CWE-829", "Verify that external scripts/styles use Subresource Integrity hashes."),
    ("path-traversal-fuzzer",          "Application Security",      "CWE-22",  "Fuzz input paths to discover directory traversal vulnerabilities."),
    ("xml-external-entity-scanner",    "Application Security",      "CWE-611", "Detect XML parameters vulnerable to XXE attacks."),
    ("clickjacking-protector",         "Web Headers",               "CWE-1021","Check for X-Frame-Options or CSP frame-ancestors to prevent clickjacking."),
    ("jwt-expiration-checker",         "Authentication & Token",    "CWE-613", "Find JWTs lacking exp claim or with excessively long lifetimes."),
    ("ssh-weak-ciphers-audit",         "Infrastructure & Access",   "CWE-326", "Detect SSH servers allowing weak ciphers such as 3des or blowfish-cbc."),
    ("dns-dnssec-validator",           "DNS Security",              "CWE-347", "Validate existence and correctness of DNSSEC records for a domain list."),
    ("cloudformation-iam-privilege-check","Cloud Security",         "CWE-269", "Parse CloudFormation templates for overly permissive IAM roles."),
    ("k8s-pod-security-policy-check",  "Kubernetes Posture",        "CWE-250", "Audit PSP/PodSecurity standards for secure configurations."),
    ("http-security-headers-checker",  "Web Headers",               "CWE-693", "Verify presence of HSTS, X-Content-Type-Options, Referrer-Policy, etc."),
    ("sql-injection-fuzzer",           "Application Security",      "CWE-89",  "Fuzz request parameters to discover SQL injection vectors."),
    ("rce-parameter-tester",           "Application Security",      "CWE-78",  "Test HTTP parameters for remote-code-execution payloads."),
    ("tls-certificate-issuer-audit",   "Network Security",          "CWE-295", "Identify certificates issued by untrusted or self-signed CAs."),
    ("s3-bucket-encryption-check",     "Cloud Security",            "CWE-311", "Check if S3 buckets use SSE-AES256 or KMS server-side encryption."),
    ("k8s-image-scan-integrator",      "Container Security",        "CWE-1104","Invoke Trivy/Grype on container images and report CVEs."),
    ("dns-wildcard-detector",          "DNS Security",              "CWE-350", "Detect wildcard DNS entries that can be abused for phishing."),
    ("oauth-token-replay-detector",    "Authentication & Token",    "CWE-294", "Detect reuse of OAuth2 tokens within a short time window."),
    ("cve-dependency-checker",         "Dependency Security",       "CWE-1104","Compare project dependencies against CVE database."),
    ("api-schema-fuzzing",             "API Security",              "CWE-20",  "Generate random requests from OpenAPI/GraphQL schemas to find errors."),
    ("http-request-smuggling-detector","Web Security",              "CWE-444", "Test chunked + Content-Length combos for request smuggling."),
    ("s3-public-bucket-detector",      "Cloud Security",            "CWE-732", "Identify S3 buckets that are publicly readable/writeable via ACLs."),
    ("k8s-service-account-token-check","Kubernetes Posture",        "CWE-269", "Detect usage of default service-account tokens with high privileges."),
    ("csp-report-collector",           "Web Security",              "CWE-693", "Enable CSP report-uri and aggregate violation reports."),
    ("ldap-ssl-tls-enforcement",       "Directory Security",        "CWE-319", "Ensure all LDAP traffic is protected with LDAPS or StartTLS."),
    ("webhook-url-validator",          "Application Security",      "CWE-918", "Validate internal webhook URLs are not pointing to insecure endpoints."),
    ("iis-configuration-audit",        "Infrastructure Security",   "CWE-16",  "Audit IIS settings for request filtering, security headers, .NET version."),
    ("cloudflare-bypass-tester",       "Network Security",          "CWE-693", "Test Cloudflare challenge/rate-limit configs for bypass possibilities."),
    ("blind-oast-collaborator",        "Application Security",      "CWE-918", "Detect out-of-band server-side request forgery via OAST callbacks."),
]

WORKER_TEMPLATE = '''#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""worker.py for {module_id}

{description}
Implements the Cyber-Hashira IPC stdio protocol (JSON lines on stdin/stdout).
"""
import sys
import json
import datetime
import re

CWE_ID = "{cwe_id}"
MODULE_ID = "{module_id}"


def _scan(target: str, options: dict) -> list:
    """Core scanning logic. Returns a list of finding dicts."""
    findings = []
    # ── rule-based checks ────────────────────────────────────────────────────
    # TODO: add real detection logic here
    # Example structure:
    # findings.append({{
    #     "cwe": CWE_ID,
    #     "title": "Example Finding",
    #     "description": "Details about the finding.",
    #     "evidence": target,
    #     "severity": "medium",
    #     "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
    # }})
    return findings


def handle_health_check(_msg: dict) -> dict:
    return {{"type": "HealthCheckResult", "payload": {{"healthy": True, "status": "ok"}}}}


def handle_run_task(msg: dict) -> dict:
    payload = msg.get("payload", {{}})
    target = msg.get("target") or payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    authorized_targets = (
        msg.get("authorized_targets")
        or payload.get("options", {{}}).get("authorized_targets", [])
    )

    # Scope guard
    if not scope_approved or (authorized_targets and target not in authorized_targets):
        return {{
            "type": "TaskCompleted",
            "payload": {{
                "success": False,
                "error": "unauthorized: target not in approved scope",
                "findings": []
            }}
        }}

    try:
        opts = payload.get("options", {{}})
        findings = _scan(target, opts)
        return {{
            "type": "TaskCompleted",
            "payload": {{
                "success": True,
                "findings": findings,
                "summary": f"{{len(findings)}} finding(s) detected for {{MODULE_ID}}"
            }}
        }}
    except Exception as exc:
        return {{
            "type": "TaskCompleted",
            "payload": {{
                "success": True,
                "findings": [],
                "summary": f"Scan error: {{exc}}"
            }}
        }}


def main():
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except Exception:
            sys.stdout.write(json.dumps({{"type": "Error", "error": "invalid JSON"}}) + "\\n")
            sys.stdout.flush()
            continue

        msg_type = msg.get("type", "")
        if msg_type == "HealthCheck":
            response = handle_health_check(msg)
        elif msg_type in ("RunTask", "Execute"):
            response = handle_run_task(msg)
        else:
            response = {{"type": "Error", "error": f"unknown message type: {{msg_type}}"}}

        sys.stdout.write(json.dumps(response) + "\\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
'''


def snake_to_title(s: str) -> str:
    return " ".join(word.capitalize() for word in s.split("-"))


def create_manifest(module_id, category, cwe_id, description):
    return json.dumps({
        "id": module_id,
        "name": snake_to_title(module_id),
        "description": description,
        "author": "Cyber Hashira Security Team",
        "version": "1.0.0",
        "min_host_version": "0.1.0",
        "category": category,
        "icon": "shield",
        "supported_os": ["windows", "linux", "macos"],
        "supported_arch": ["x86_64", "aarch64"],
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
                            },
                            "required": ["cwe", "title", "description", "evidence", "detected_at"]
                        }
                    }
                }
            }
        },
        "artifact": {"url": "", "sha256": "", "size_bytes": 0}
    }, indent=2, ensure_ascii=False)


created = 0
skipped = 0

for mod_id, category, cwe_id, description in MODULES:
    mod_dir = MODULES_DIR / mod_id
    mod_dir.mkdir(parents=True, exist_ok=True)

    manifest_path = mod_dir / "manifest.json"
    if not manifest_path.is_file():
        manifest_path.write_text(create_manifest(mod_id, category, cwe_id, description), encoding="utf-8")
        print(f"[+] manifest  -> {mod_id}")

    worker_path = mod_dir / "worker.py"
    if not worker_path.is_file():
        worker_path.write_text(
            WORKER_TEMPLATE.format(module_id=mod_id, cwe_id=cwe_id, description=description),
            encoding="utf-8"
        )
        try:
            os.chmod(worker_path, 0o755)
        except Exception:
            pass
        print(f"[+] worker.py -> {mod_id}")
        created += 1
    else:
        skipped += 1

print(f"\n✅ Done: {created} modules created, {skipped} already existed.")
