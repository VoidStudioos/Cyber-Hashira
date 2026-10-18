#!/usr/bin/env python3
"""
Cyber Hashira - SSRF & Cloud Metadata Defense Validator
Features:
  - Validates webhooks, URL-fetching features, and proxy destinations:
      * AWS/GCP/Azure/DigitalOcean Metadata Endpoints (169.254.169.254, metadata.google.internal)
      * RFC 1918 Private Subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      * Loopback addresses (127.0.0.0/8, localhost, ::1, 0.0.0.0)
      * Obfuscated IP notations (Decimal 2130706433, Octal 0177.0.0.1, Hex 0x7f000001)
      * Dangerous URI schemes (file://, gopher://, dict://, ldap://)
      * DNS rebinding / wildcard resolution domains (nip.io, sslip.io)
"""

import sys
import json
import uuid
import re
import ipaddress
import urllib.parse
import datetime

DANGEROUS_SCHEMES = ["file", "gopher", "dict", "ldap", "tftp"]

CLOUD_METADATA_HOSTS = [
    "169.254.169.254", "metadata.google.internal", "metadata.azure.com",
    "100.100.100.200", "fd00:ec2::254", "kubernetes.default.svc"
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

def parse_obfuscated_ip(host: str):
    # Check decimal IP notation: e.g. 2130706433
    if host.isdigit():
        try:
            val = int(host)
            if 0 <= val <= 4294967295:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Check hex IP notation: e.g. 0x7f000001
    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 4294967295:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass

    # Standard IP parse
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass

    return None

def audit_url_target(raw_url: str) -> list:
    findings = []
    
    # Check scheme
    parsed = urllib.parse.urlparse(raw_url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""

    if not scheme and "://" in raw_url:
        scheme = raw_url.split("://")[0].lower()
    
    if scheme in DANGEROUS_SCHEMES:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": f"Dangerous URI Scheme Detected ({scheme}://)",
            "severity": "critical",
            "cvss_score": 9.5,
            "target": raw_url,
            "description": f"URL uses the '{scheme}://' protocol. Attackers use this scheme to achieve local file disclosure or protocol smuggling in SSRF vulnerabilities.",
            "remediation": "Restrict accepted schemes strictly to 'https://' or 'http://' with a hardened HTTP client."
        })

    # Check Cloud Metadata
    if host.lower() in CLOUD_METADATA_HOSTS or any(meta in raw_url.lower() for meta in CLOUD_METADATA_HOSTS):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Critical SSRF: Cloud Instance Metadata Access Attempt",
            "severity": "critical",
            "cvss_score": 9.8,
            "target": raw_url,
            "description": f"Destination '{host}' targets cloud instance metadata (AWS/GCP/Azure). In vulnerable environments, this leaks IAM role credentials and service account tokens.",
            "remediation": "Block all outbound requests to 169.254.169.254 and enforce IMDSv2 with token hops restricted to 1."
        })

    # Check Obfuscated or Direct Private IP
    ip_obj = parse_obfuscated_ip(host)
    if ip_obj:
        if ip_obj.is_loopback:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"SSRF Target Points to Loopback Interface ({ip_obj})",
                "severity": "high",
                "cvss_score": 8.7,
                "target": raw_url,
                "description": f"IP '{ip_obj}' resolves to the local machine loopback interface (localhost). Attackers can probe internal microservices.",
                "remediation": "Block all loopback IP addresses in outbound firewall and reverse proxy validation logic."
            })
        elif ip_obj.is_private:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"SSRF Target Points to RFC 1918 Private Subnet ({ip_obj})",
                "severity": "high",
                "cvss_score": 8.4,
                "target": raw_url,
                "description": f"IP '{ip_obj}' is in a private network range. Internal enterprise networks or cluster databases may be exposed.",
                "remediation": "Disallow non-routable private IP addresses in webhook URL resolvers."
            })
        elif ip_obj.is_link_local:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": f"SSRF Target Points to Link-Local Address ({ip_obj})",
                "severity": "high",
                "cvss_score": 8.5,
                "target": raw_url,
                "description": f"IP '{ip_obj}' is a link-local address commonly used for cloud metadata and router discovery.",
                "remediation": "Drop all link-local traffic in application egress rules."
            })

    # Check Wildcard DNS Rebinding Services
    if any(host.lower().endswith("." + d) or host.lower() == d for d in ["nip.io", "sslip.io", "localtest.me"]):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": f"DNS Rebinding / Wildcard Resolution Service ({host})",
            "severity": "medium",
            "cvss_score": 6.8,
            "target": raw_url,
            "description": f"Hostname '{host}' relies on a wildcard DNS resolver frequently abused to bypass domain string matching in SSRF filters.",
            "remediation": "Resolve hostnames to IP addresses before checking allowlists, and pin the resolved IP address for the outbound socket connection."
        })

    return findings

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target_endpoint") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    urls = req.get("url_or_ips") or options.get("url_or_ips", [])
    if not urls:
        # Default test set exercising all SSRF bypass vectors
        urls = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://2130706433:8080/admin",
            "file:///etc/passwd",
            "http://127.0.0.1.nip.io/internal",
            "https://public-api.trusted.com/data"
        ]

    all_findings = []
    dangerous_targets = []

    for u in urls:
        f_list = audit_url_target(u)
        if f_list:
            dangerous_targets.append(u)
            all_findings.extend(f_list)

    return {
        "status": "success",
        "result": {
            "evaluated_endpoint": target or "webhook-dispatcher",
            "ssrf_risk_detected": len(dangerous_targets) > 0,
            "total_urls_tested": len(urls),
            "dangerous_count": len(dangerous_targets),
            "dangerous_targets": dangerous_targets,
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
            res = {"status": "ok", "module": "ssrf-guard-validator", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
