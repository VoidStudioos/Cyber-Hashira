#!/usr/bin/env python3
"""
Cyber Hashira - Secrets, API Keys & PII Leak Scanner
Features:
  - Regex signature scanning for:
      * AWS Access Keys (AKIA...) & Secret Keys
      * GitHub Personal Access Tokens (ghp_..., github_pat_...)
      * Stripe Secret Keys (sk_live_...)
      * OpenAI API Keys (sk-...)
      * Slack Webhooks & Bot Tokens (xoxb-...)
      * Private Keys (RSA, OpenSSH, EC)
      * Database Connection URIs with credentials
  - Shannon Entropy token calculation (discovers obfuscated / high-entropy secrets)
  - Automatic secret masking/redaction in reports (prevents leakage)
"""

import sys
import json
import uuid
import re
import math
import datetime

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "critical",
        "cvss": 9.3,
        "type": "Cloud Credential"
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{60,90})\b",
        "severity": "critical",
        "cvss": 9.5,
        "type": "Source Code Platform"
    },
    {
        "name": "Stripe API Secret Key",
        "pattern": r"\b(sk_(?:live|test)_[0-9a-zA-Z]{24,34})\b",
        "severity": "critical",
        "cvss": 9.8,
        "type": "Payment Gateway"
    },
    {
        "name": "OpenAI Secret API Key",
        "pattern": r"\b(sk-[a-zA-Z0-9]{32,64}|sk-proj-[a-zA-Z0-9_\-]{40,90})\b",
        "severity": "high",
        "cvss": 8.5,
        "type": "AI Platform"
    },
    {
        "name": "Slack Webhook or Bot Token",
        "pattern": r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)\b",
        "severity": "high",
        "cvss": 8.0,
        "type": "Communication"
    },
    {
        "name": "Unencrypted Private Key Block",
        "pattern": r"(-----BEGIN (?:RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY-----)",
        "severity": "critical",
        "cvss": 9.9,
        "type": "Cryptographic Key"
    },
    {
        "name": "Database Connection String with Credentials",
        "pattern": r"\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_-]+:([a-zA-Z0-9_%@!#$^&*()-]+)@[a-zA-Z0-9_\.\-]+(?::[0-9]+)?",
        "severity": "critical",
        "cvss": 9.6,
        "type": "Database"
    }
]

class ScopeGuard:
    @staticmethod
    def is_authorized(target: str, authorized_targets: list) -> bool:
        if not target:
            return True
        clean_target = target.strip().lower()
        for auth in authorized_targets:
            if clean_target == auth.strip().lower() or clean_target.startswith(auth.strip().lower()):
                return True
        return False

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "****"
    return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

def scan_content(text: str, entropy_threshold: float = 4.5) -> tuple:
    findings = []
    secrets_found = []
    high_entropy_tokens = []

    lines = text.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        # 1. Regex Pattern Matching
        for sp in SECRET_PATTERNS:
            matches = re.finditer(sp["pattern"], line)
            for m in matches:
                raw_token = m.group(1) if m.groups() else m.group(0)
                masked = mask_secret(raw_token)
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": f"Exposed {sp['name']}",
                    "severity": sp["severity"],
                    "cvss_score": sp["cvss"],
                    "line": line_idx,
                    "secret_type": sp["type"],
                    "masked_token": masked,
                    "description": f"A plaintext {sp['name']} was discovered at line {line_idx}.",
                    "remediation": f"Revoke this {sp['name']} immediately, remove it from git history, and use an environment variable or Secret Manager."
                })
                secrets_found.append({"type": sp["name"], "line": line_idx, "token": masked})

        # 2. High Entropy Token Detection in variable assignments
        assign_match = re.search(r"['\"]([a-zA-Z0-9_\-\.]{24,})['\"]", line)
        if assign_match:
            candidate = assign_match.group(1)
            ent = calculate_shannon_entropy(candidate)
            if ent >= entropy_threshold and not any(candidate in s.get("token", "") for s in secrets_found):
                high_entropy_tokens.append({
                    "line": line_idx,
                    "entropy": round(ent, 3),
                    "token_prefix": candidate[:6] + "..."
                })
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": f"Suspicious High-Entropy Secret (Entropy: {round(ent, 2)})",
                    "severity": "medium",
                    "cvss_score": 6.0,
                    "line": line_idx,
                    "description": f"A string token with high Shannon entropy ({round(ent, 2)}) was detected at line {line_idx}.",
                    "remediation": "Audit this token to ensure it is not an active unmanaged secret."
                })

    return findings, secrets_found, high_entropy_tokens

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target") or req.get("target_path", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    content = req.get("content") or options.get("content", "")
    entropy_threshold = float(options.get("entropy_threshold", 4.5))

    if not content:
        # Default test payload demonstrating multi-cloud secrets
        content = (
            "# App Config\n"
            "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "GH_TOKEN=ghp_ABC1234567890abcdefghijklmnopqrstuv\n"
            "DATABASE_AUTH_KEY=db_auth_placeholder_token_safe_9918\n"
            "HIGH_ENTROPY_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n"
        )

    findings, secrets_found, high_entropy = scan_content(content, entropy_threshold)

    return {
        "status": "success",
        "result": {
            "total_findings": len(findings),
            "secrets_count": len(secrets_found),
            "high_entropy_count": len(high_entropy),
            "secrets_found": secrets_found,
            "high_entropy_tokens": high_entropy,
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
            res = {"status": "ok", "module": "secrets-leak-scanner", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
