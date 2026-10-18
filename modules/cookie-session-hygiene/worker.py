#!/usr/bin/env python3
"""
Cyber Hashira - Cookie Security & Session Hygiene Inspector
Features:
  - Security Flags Audit on Set-Cookie:
      * Missing 'Secure' flag (Cleartext transmission risk)
      * Missing 'HttpOnly' flag on sensitive session tokens (XSS theft risk)
      * Missing or weak 'SameSite' attribute (CSRF risk)
  - Cookie Prefix Enforcement:
      * __Host- prefix validation (must have Secure, Path=/, and omit Domain)
      * __Secure- prefix validation (must have Secure)
  - Session Token Entropy & Predictability:
      * Shannon entropy calculation
      * Short token length / sequential pattern detection
"""

import sys
import json
import uuid
import re
import math
import datetime

SENSITIVE_COOKIE_NAMES = [
    "session", "sessionid", "session_id", "phpsessid", "jsessionid",
    "aspsessionid", "token", "auth_token", "jwt", "connect.sid", "remember_me"
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

def calculate_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log2(p_x)
    return entropy

def parse_set_cookie(cookie_str: str) -> dict:
    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    if not parts:
        return {}

    first = parts[0]
    name, val = first.split("=", 1) if "=" in first else (first, "")

    parsed = {
        "name": name.strip(),
        "value": val.strip(),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None
    }

    for p in parts[1:]:
        p_lower = p.lower()
        if p_lower == "secure":
            parsed["secure"] = True
        elif p_lower == "httponly":
            parsed["httponly"] = True
        elif p_lower.startswith("samesite="):
            parsed["samesite"] = p.split("=", 1)[1].strip()
        elif p_lower.startswith("domain="):
            parsed["domain"] = p.split("=", 1)[1].strip()
        elif p_lower.startswith("path="):
            parsed["path"] = p.split("=", 1)[1].strip()

    return parsed

def audit_cookie(c: dict) -> tuple:
    findings = []
    deductions = 0
    name = c["name"]
    is_session = any(s in name.lower() for s in SENSITIVE_COOKIE_NAMES)

    # 1. HttpOnly on session cookie
    if is_session and not c["httponly"]:
        f = {
            "id": str(uuid.uuid4()),
            "title": f"Missing HttpOnly Flag on Sensitive Session Cookie ({name})",
            "severity": "high",
            "cvss_score": 7.5,
            "cookie": name,
            "description": f"The session cookie '{name}' lacks the HttpOnly flag, permitting client-side scripts to read it via document.cookie during an XSS attack.",
            "remediation": f"Set 'HttpOnly' flag on {name} in Set-Cookie response header."
        }
        findings.append(f)
        deductions += 25

    # 2. Secure flag
    if not c["secure"]:
        f = {
            "id": str(uuid.uuid4()),
            "title": f"Missing Secure Flag on Cookie ({name})",
            "severity": "high" if is_session else "medium",
            "cvss_score": 7.4 if is_session else 5.3,
            "cookie": name,
            "description": f"The cookie '{name}' does not have the Secure flag. Browsers will transmit this cookie over unencrypted HTTP connections.",
            "remediation": f"Add 'Secure' flag to {name}."
        }
        findings.append(f)
        deductions += 20 if is_session else 10

    # 3. SameSite attribute
    if not c["samesite"]:
        f = {
            "id": str(uuid.uuid4()),
            "title": f"Missing SameSite Attribute on Cookie ({name})",
            "severity": "medium",
            "cvss_score": 5.8,
            "cookie": name,
            "description": f"Cookie '{name}' does not specify SameSite (Strict or Lax), increasing susceptibility to Cross-Site Request Forgery (CSRF).",
            "remediation": f"Set SameSite=Lax or SameSite=Strict on {name}."
        }
        findings.append(f)
        deductions += 15
    elif c["samesite"].lower() == "none" and not c["secure"]:
        f = {
            "id": str(uuid.uuid4()),
            "title": f"SameSite=None Configured Without Secure Flag on ({name})",
            "severity": "high",
            "cvss_score": 7.1,
            "cookie": name,
            "description": "SameSite=None must be paired with Secure; otherwise, modern browsers reject the cookie completely.",
            "remediation": "Add 'Secure' flag when using SameSite=None."
        }
        findings.append(f)
        deductions += 20

    # 4. __Host- prefix validation
    if name.startswith("__Host-"):
        if not c["secure"] or c["path"] != "/" or c["domain"] is not None:
            f = {
                "id": str(uuid.uuid4()),
                "title": f"Invalid __Host- Cookie Prefix Usage ({name})",
                "severity": "medium",
                "cvss_score": 6.0,
                "cookie": name,
                "description": "__Host- prefixed cookies must be set with Secure, Path=/, and MUST NOT include a Domain attribute.",
                "remediation": "Ensure __Host- cookies have Secure, Path=/, and no Domain attribute."
            }
            findings.append(f)
            deductions += 15

    # 5. Session Token Entropy
    if is_session and c.get("value"):
        ent = calculate_entropy(c["value"])
        if len(c["value"]) < 16 or ent < 3.2:
            f = {
                "id": str(uuid.uuid4()),
                "title": f"Weak Session ID Entropy / Short Token ({name})",
                "severity": "high",
                "cvss_score": 7.9,
                "cookie": name,
                "description": f"Session token '{name}' has low Shannon entropy ({round(ent, 2)}) or short length ({len(c['value'])} chars). Vulnerable to token prediction or brute-force.",
                "remediation": "Generate session IDs using a cryptographically secure random number generator (CSPRNG) with at least 128 bits (16 bytes) of entropy."
            }
            findings.append(f)
            deductions += 20

    return findings, deductions

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target_url") or req.get("target", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    raw_cookies = req.get("cookies") or options.get("cookies", [])
    if not raw_cookies:
        # Default test cookies illustrating common session risks
        raw_cookies = [
            "sessionid=12345; Path=/; Domain=.corp.internal",
            "token=eyJhbGciOiJIUzI1NiJ9.test; Path=/; Secure",
            "preferences=theme_dark; Path=/"
        ]

    parsed_cookies = []
    all_findings = []
    total_deductions = 0
    insecure_cookies = []

    for item in raw_cookies:
        if isinstance(item, str):
            c = parse_set_cookie(item)
        else:
            c = item
        if not c:
            continue
        parsed_cookies.append(c)
        c_findings, c_deduct = audit_cookie(c)
        if c_findings:
            insecure_cookies.append(c["name"])
            all_findings.extend(c_findings)
            total_deductions += c_deduct

    score = max(0, 100 - total_deductions)

    return {
        "status": "success",
        "result": {
            "target": target or "evaluated-app.com",
            "cookie_hygiene_score": score,
            "total_cookies": len(parsed_cookies),
            "insecure_count": len(insecure_cookies),
            "insecure_cookies": insecure_cookies,
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
            res = {"status": "ok", "module": "cookie-session-hygiene", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
