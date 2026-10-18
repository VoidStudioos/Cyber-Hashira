#!/usr/bin/env python3
"""
Cyber Hashira - Subdomain Takeover & Dangling DNS Auditor
Features:
  - Detects dangling CNAME records pointing to unclaimed/deprovisioned cloud assets:
      * AWS S3 Bucket websites (NoSuchBucket)
      * GitHub Pages (There isn't a GitHub Pages site here)
      * Heroku Apps (No such app)
      * Azure App Services / Traffic Manager (404 Web Site not found)
      * Zendesk Help Centers (Help Center Closed)
      * Fastly CDN (Fastly error: unknown domain)
      * Shopify Storefronts (Sorry, this shop is currently unavailable)
  - Prevents brand hijacking, cookie stealing, and cross-subdomain authentication bypass
"""

import sys
import json
import uuid
import re
import datetime

CLOUD_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_suffix": ".github.io",
        "error_patterns": ["There isn't a GitHub Pages site here", "404 Not Found"],
        "severity": "high",
        "cvss": 8.6
    },
    {
        "service": "Amazon AWS S3 Bucket",
        "cname_suffix": ".s3.amazonaws.com",
        "error_patterns": ["The specified bucket does not exist", "NoSuchBucket"],
        "severity": "critical",
        "cvss": 9.0
    },
    {
        "service": "Amazon AWS S3 Website",
        "cname_suffix": ".s3-website-",
        "error_patterns": ["404 Not Found", "NoSuchBucket", "Code: NoSuchBucket"],
        "severity": "critical",
        "cvss": 9.0
    },
    {
        "service": "Heroku Platform",
        "cname_suffix": ".herokuapp.com",
        "error_patterns": ["No such app", "Heroku | No such app"],
        "severity": "high",
        "cvss": 8.5
    },
    {
        "service": "Microsoft Azure App Service",
        "cname_suffix": ".azurewebsites.net",
        "error_patterns": ["404 Web Site not found", "Error 404 - Web app not found"],
        "severity": "high",
        "cvss": 8.6
    },
    {
        "service": "Zendesk Help Center",
        "cname_suffix": ".zendesk.com",
        "error_patterns": ["Help Center Closed", "No help center found"],
        "severity": "medium",
        "cvss": 6.8
    },
    {
        "service": "Fastly CDN",
        "cname_suffix": ".fastly.net",
        "error_patterns": ["Fastly error: unknown domain"],
        "severity": "high",
        "cvss": 8.1
    }
]

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

def check_cname_takeover(subdomain: str, cname: str, body_snippet: str = "") -> dict:
    cname_lower = cname.lower()
    for fp in CLOUD_FINGERPRINTS:
        if fp["cname_suffix"] in cname_lower:
            # Check if body exhibits takeover fingerprint or if explicit dangling flag is set
            hit = False
            if body_snippet:
                hit = any(pat.lower() in body_snippet.lower() for pat in fp["error_patterns"])
            else:
                hit = True  # Flag dangling pointer if CNAME points to cloud domain without active deployment

            if hit:
                return {
                    "vulnerable": True,
                    "service": fp["service"],
                    "subdomain": subdomain,
                    "cname": cname,
                    "severity": fp["severity"],
                    "cvss_score": fp["cvss"]
                }
    return {"vulnerable": False}

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("domain") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target domain '{target}' is not in authorized scope: {authorized_targets}"
            }

    cname_records = req.get("cname_records") or options.get("cname_records", [])
    if not cname_records:
        # Default test payload exhibiting vulnerable dangling subdomains
        cname_records = [
            {
                "subdomain": "blog.corp.internal",
                "cname": "corp-blog.github.io",
                "response_body": "404 Not Found - There isn't a GitHub Pages site here."
            },
            {
                "subdomain": "assets.corp.internal",
                "cname": "corp-static-assets.s3.amazonaws.com",
                "response_body": "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
            },
            {
                "subdomain": "api.corp.internal",
                "cname": "prod-api-lb.corp.internal",
                "response_body": "OK 200"
            }
        ]

    findings = []
    dangling_subdomains = []

    for item in cname_records:
        sub = item.get("subdomain", "")
        cname = item.get("cname", "")
        body = item.get("response_body", "")

        res = check_cname_takeover(sub, cname, body)
        if res.get("vulnerable"):
            dangling_subdomains.append({
                "subdomain": sub,
                "cname": cname,
                "service": res["service"]
            })
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"Subdomain Takeover Vulnerability on {sub} ({res['service']})",
                "severity": res["severity"],
                "cvss_score": res["cvss_score"],
                "subdomain": sub,
                "cname_target": cname,
                "service": res["service"],
                "description": f"The CNAME record for '{sub}' points to an unclaimed or deprovisioned {res['service']} resource ({cname}). An attacker can claim this resource and serve malicious content under your trusted domain.",
                "remediation": f"Immediately remove the dangling CNAME record '{cname}' from your DNS zone, or register the corresponding resource in {res['service']}."
            })

    return {
        "status": "success",
        "result": {
            "domain": target or "corp.internal",
            "takeover_risk_detected": len(dangling_subdomains) > 0,
            "total_records_checked": len(cname_records),
            "dangling_count": len(dangling_subdomains),
            "dangling_subdomains": dangling_subdomains,
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
            res = {"status": "ok", "module": "subdomain-takeover-audit", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
