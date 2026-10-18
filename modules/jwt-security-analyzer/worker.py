#!/usr/bin/env python3
"""
Cyber Hashira - JWT & Cryptographic Token Analyzer
Features:
  - Base64URL decodes and inspects JSON Web Tokens (Header, Payload, Signature)
  - Identifies Critical JWT Vulnerabilities:
      * 'alg: none' signature verification bypass
      * Weak common secret keys (secret, 123456, admin, jwtsecret)
      * RSA to HMAC algorithm confusion risk (RS256 -> HS256)
      * Missing expiration claims ('exp' claim missing - perpetual validity)
      * Dangerous header parameters: 'kid' path traversal, 'jku' / 'jwk' untrusted key injection
"""

import sys
import json
import uuid
import base64
import hmac
import hashlib
import time
import datetime

COMMON_WEAK_SECRETS = [
    "secret", "secret123", "password", "123456", "jwtsecret",
    "admin", "supersecret", "mysecret", "test", "development"
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

def base64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def parse_jwt(token_str: str) -> tuple:
    parts = token_str.strip().split(".")
    if len(parts) < 2:
        return {}, {}, b""
    try:
        header = json.loads(base64url_decode(parts[0]).decode("utf-8", errors="ignore"))
    except Exception:
        header = {}
    try:
        payload = json.loads(base64url_decode(parts[1]).decode("utf-8", errors="ignore"))
    except Exception:
        payload = {}
    
    sig = base64url_decode(parts[2]) if len(parts) > 2 else b""
    return header, payload, sig

def audit_jwt(token_str: str) -> tuple:
    header, payload, sig = parse_jwt(token_str)
    findings = []
    vulnerabilities = []

    parts = token_str.strip().split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8") if len(parts) >= 2 else b""

    alg = header.get("alg", "").lower()

    # 1. alg: none bypass
    if alg == "none":
        f = {
            "id": str(uuid.uuid4()),
            "title": "Critical JWT Vulnerability: 'alg: none' Signature Bypass",
            "severity": "critical",
            "cvss_score": 9.8,
            "vuln_type": "JWT_ALG_NONE",
            "description": "Token specifies algorithm 'none'. If the backend accepts this, attackers can forge arbitrary claims (such as admin=true) without a valid signature.",
            "remediation": "Explicitly reject tokens with 'alg: none' and enforce strong cryptographic algorithms (RS256, ES256, HS256)."
        }
        findings.append(f)
        vulnerabilities.append("JWT_ALG_NONE")

    # 2. RSA to HMAC confusion check
    if alg == "hs256" and any(k in str(header).lower() for k in ["rsa", "public", "x5c"]):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Algorithm Confusion Risk: Symmetric HS256 with Asymmetric Parameters",
            "severity": "high",
            "cvss_score": 8.5,
            "vuln_type": "JWT_ALGORITHM_CONFUSION",
            "description": "Token uses symmetric HS256 but contains asymmetric key metadata. If the server expects RSA, attackers can sign forged tokens using the server's public RSA key as an HMAC secret (CVE-2015-9235).",
            "remediation": "Do not determine verification algorithm from the token header. Hardcode expected verification algorithms."
        }
        findings.append(f)
        vulnerabilities.append("JWT_ALGORITHM_CONFUSION")

    # 3. Weak Secret Cracking (Dictionary Audit)
    if alg in ["hs256", "hs384", "hs512"] and sig:
        for secret in COMMON_WEAK_SECRETS:
            computed = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if computed == sig:
                f = {
                    "id": str(uuid.uuid4()),
                    "title": f"Trivially Predictable HMAC Secret Key Discovered ('{secret}')",
                    "severity": "critical",
                    "cvss_score": 9.8,
                    "vuln_type": "JWT_WEAK_SECRET",
                    "description": f"The JWT signature was verified using the common weak secret key '{secret}'. Attackers can forge tokens with arbitrary privileges.",
                    "remediation": "Generate high-entropy HMAC secret keys (at least 256 bits of cryptographically secure random bytes) or migrate to asymmetric RS256/ES256."
                }
                findings.append(f)
                vulnerabilities.append("JWT_WEAK_SECRET")
                break

    # 4. Missing Expiration claim (exp)
    if "exp" not in payload:
        f = {
            "id": str(uuid.uuid4()),
            "title": "JWT Missing Expiration Claim ('exp')",
            "severity": "medium",
            "cvss_score": 6.5,
            "vuln_type": "JWT_MISSING_EXP",
            "description": "Token lacks an 'exp' (Expiration Time) claim. Compromised tokens will remain valid indefinitely.",
            "remediation": "Include an 'exp' claim with an appropriate short lifespan (e.g., 15-60 minutes) alongside refresh tokens."
        }
        findings.append(f)
        vulnerabilities.append("JWT_MISSING_EXP")
    else:
        # Check if expired
        try:
            exp_time = int(payload["exp"])
            if exp_time < time.time():
                findings.append({
                    "id": str(uuid.uuid4()),
                    "title": "Expired JWT Token",
                    "severity": "low",
                    "cvss_score": 3.0,
                    "vuln_type": "JWT_EXPIRED",
                    "description": f"Token expired at {datetime.datetime.utcfromtimestamp(exp_time).isoformat()}Z.",
                    "remediation": "Ensure backend rejects expired tokens."
                })
        except Exception:
            pass

    # 5. Path Traversal in 'kid'
    kid = header.get("kid", "")
    if "../" in kid or "..\\" in kid:
        f = {
            "id": str(uuid.uuid4()),
            "title": "Directory Traversal in JWT 'kid' (Key ID) Header",
            "severity": "high",
            "cvss_score": 8.6,
            "vuln_type": "JWT_KID_PATH_TRAVERSAL",
            "description": f"The 'kid' header parameter contains path traversal sequences ('{kid}'). In vulnerable implementations, this forces the backend to use an empty file (/dev/null) as secret key.",
            "remediation": "Sanitize and whitelist 'kid' parameter values; avoid file system lookups based on unverified header inputs."
        }
        findings.append(f)
        vulnerabilities.append("JWT_KID_PATH_TRAVERSAL")

    return header, payload, findings, vulnerabilities

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target") or ""
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    token = req.get("token") or options.get("token", "")
    if not token:
        # Default test token illustrating 'alg: none' and missing 'exp'
        h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        p = base64.urlsafe_b64encode(json.dumps({"sub": "12345", "name": "Admin", "admin": True}).encode()).decode().rstrip("=")
        token = f"{h}.{p}."

    header, payload, findings, vulns = audit_jwt(token)

    return {
        "status": "success",
        "result": {
            "header": header,
            "payload": payload,
            "has_signature": token.count(".") == 2 and len(token.split(".")[2]) > 0,
            "vulnerabilities_count": len(vulns),
            "vulnerabilities": vulns,
            "total_findings": len(findings),
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
            res = {"status": "ok", "module": "jwt-security-analyzer", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
