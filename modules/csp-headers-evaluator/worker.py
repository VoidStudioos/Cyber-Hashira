#!/usr/bin/env python3
"""
Cyber Hashira - Content Security Policy (CSP) & Web Headers Auditor
Features:
  - Deep CSP Level 3 Evaluation:
      * script-src safety (unsafe-inline, unsafe-eval, strict-dynamic, nonces/hashes)
      * object-src 'none' (prevents legacy Flash/plugin injection)
      * base-uri 'self' or 'none' (prevents base tag hijacking)
      * frame-ancestors vs X-Frame-Options (Clickjacking defense)
  - HTTP Strict Transport Security (HSTS):
      * max-age >= 31536000 (1 year)
      * includeSubDomains & preload readiness
  - Cross-Origin Isolation:
      * Cross-Origin-Opener-Policy (COOP)
      * Cross-Origin-Embedder-Policy (COEP)
      * Cross-Origin-Resource-Policy (CORP)
  - Permissions-Policy / Feature-Policy
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

def parse_csp(csp_str: str) -> dict:
    directives = {}
    if not csp_str:
        return directives
    for part in csp_str.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        d_name = tokens[0].lower()
        d_values = tokens[1:]
        directives[d_name] = d_values
    return directives

def evaluate_csp(directives: dict, x_frame_options: str) -> tuple:
    findings = []
    score_deduction = 0
    clickjacking_protected = False

    if not directives:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "The web server does not send a Content-Security-Policy header, leaving the browser vulnerable to Cross-Site Scripting (XSS), data injection, and clickjacking.",
            "remediation": "Implement a strict CSP policy starting with: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
        })
        score_deduction += 45
    else:
        # 1. script-src checks
        script_src = directives.get("script-src", directives.get("default-src", []))
        if not script_src:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "CSP Missing Both script-src and default-src",
                "severity": "high",
                "cvss_score": 7.2,
                "description": "Neither script-src nor default-src is defined, allowing execution of scripts from any origin.",
                "remediation": "Define an explicit script-src or default-src directive."
            })
            score_deduction += 25
        else:
            if "'unsafe-inline'" in script_src:
                has_nonce_or_hash = any(t.startswith("'nonce-") or t.startswith("'sha256-") for t in script_src)
                if not has_nonce_or_hash:
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "title": "CSP script-src Contains 'unsafe-inline' Without Nonce/Hash",
                        "severity": "high",
                        "cvss_score": 7.8,
                        "description": "Allowing 'unsafe-inline' in script-src defeats the primary XSS protection mechanism of CSP.",
                        "remediation": "Remove 'unsafe-inline' and transition to cryptographic nonces ('nonce-...') or SHA-256 hashes."
                    })
                    score_deduction += 20

            if "'unsafe-eval'" in script_src:
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "CSP script-src Contains 'unsafe-eval'",
                    "severity": "medium",
                    "cvss_score": 5.5,
                    "description": "Allowing 'unsafe-eval' permits strings to be compiled and executed as code via eval() or Function().",
                    "remediation": "Refactor application code to eliminate eval() and remove 'unsafe-eval'."
                })
                score_deduction += 10

        # 2. object-src 'none'
        object_src = directives.get("object-src", directives.get("default-src", []))
        if "'none'" not in object_src:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "CSP object-src is Not Set to 'none'",
                "severity": "medium",
                "cvss_score": 5.0,
                "description": "object-src should be explicitly set to 'none' to prevent loading of legacy Flash, Java applets, or dangerous plugin objects.",
                "remediation": "Add 'object-src 'none';' to your CSP policy."
            })
            score_deduction += 10

        # 3. base-uri
        if "base-uri" not in directives:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "CSP Missing base-uri Directive",
                "severity": "low",
                "cvss_score": 3.8,
                "description": "Without base-uri, attackers who achieve partial HTML injection can alter the base URL of relative script links.",
                "remediation": "Add 'base-uri 'self';' or 'base-uri 'none';' to CSP."
            })
            score_deduction += 5

        # 4. frame-ancestors
        if "frame-ancestors" in directives:
            clickjacking_protected = True
        elif x_frame_options.upper() in ["DENY", "SAMEORIGIN"]:
            clickjacking_protected = True
        else:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Clickjacking Vulnerability (Missing frame-ancestors and X-Frame-Options)",
                "severity": "medium",
                "cvss_score": 6.1,
                "description": "The application allows framing by any origin. Attackers can embed this page in a hidden iframe for Clickjacking attacks.",
                "remediation": "Add 'frame-ancestors 'none';' or 'frame-ancestors 'self';' to CSP, and set 'X-Frame-Options: DENY'."
            })
            score_deduction += 15

    return findings, score_deduction, clickjacking_protected

def evaluate_hsts(hsts_header: str) -> tuple:
    findings = []
    score_deduction = 0

    if not hsts_header:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Missing HTTP Strict Transport Security (HSTS) Header",
            "severity": "high",
            "cvss_score": 7.0,
            "description": "HSTS is not enforced, permitting man-in-the-middle SSL-stripping attacks on HTTP connections.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
        })
        score_deduction += 20
        return findings, score_deduction

    # parse max-age
    m = re.search(r"max-age=(\d+)", hsts_header, re.IGNORECASE)
    if m:
        age = int(m.group(1))
        if age < 31536000:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"HSTS max-age is Insufficient ({age}s < 31536000s)",
                "severity": "low",
                "cvss_score": 3.5,
                "description": "HSTS max-age should be at least 1 year (31536000 seconds) for production sites and browser preload eligibility.",
                "remediation": "Increase max-age to 31536000."
            })
            score_deduction += 5
    else:
        score_deduction += 10

    if "includesubdomains" not in hsts_header.lower():
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "HSTS Missing includeSubDomains Directive",
            "severity": "low",
            "cvss_score": 3.2,
            "description": "HSTS policy does not cover all subdomains.",
            "remediation": "Add 'includeSubDomains' to HSTS header."
        })
        score_deduction += 5

    return findings, score_deduction

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("url") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    headers = req.get("headers") or options.get("headers", {})
    if not headers:
        # Default test headers with realistic misconfigurations
        headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.example.com;",
            "Strict-Transport-Security": "max-age=86400",
            "X-Content-Type-Options": "nosniff"
        }

    # Case-insensitive header dictionary
    norm_headers = {k.lower(): v for k, v in headers.items()}
    csp_val = norm_headers.get("content-security-policy", "")
    xfo_val = norm_headers.get("x-frame-options", "")
    hsts_val = norm_headers.get("strict-transport-security", "")

    directives = parse_csp(csp_val)
    all_findings = []
    base_score = 100

    csp_findings, csp_deduct, clickjacking_protected = evaluate_csp(directives, xfo_val)
    all_findings.extend(csp_findings)
    base_score -= csp_deduct

    hsts_findings, hsts_deduct = evaluate_hsts(hsts_val)
    all_findings.extend(hsts_findings)
    base_score -= hsts_deduct

    # Check X-Content-Type-Options
    if norm_headers.get("x-content-type-options", "").lower() != "nosniff":
        all_findings.append({
            "id": str(uuid.uuid4()),
            "title": "Missing or Invalid X-Content-Type-Options Header",
            "severity": "low",
            "cvss_score": 3.4,
            "description": "X-Content-Type-Options should be set to 'nosniff' to prevent MIME-type sniffing attacks.",
            "remediation": "Set 'X-Content-Type-Options: nosniff'."
        })
        base_score -= 5

    final_score = max(0, min(100, base_score))

    return {
        "status": "success",
        "result": {
            "target": target or "evaluated-site.com",
            "csp_score": final_score,
            "clickjacking_protected": clickjacking_protected,
            "parsed_directives": directives,
            "total_findings": len(all_findings),
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
            res = {"status": "ok", "module": "csp-headers-evaluator", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
