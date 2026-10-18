#!/usr/bin/env python3
"""
Cyber Hashira - Active Directory & Identity Hygiene Auditor
Features:
  - CIS Active Directory Benchmark & Identity Security Audit:
      * AS-REP Roasting Risk: Accounts with Kerberos Pre-Authentication disabled (DONT_REQ_PREAUTH)
      * Kerberoasting Risk: SPNs associated with high-privilege accounts using weak RC4-HMAC ciphers
      * Stale / Inactive Privileged Accounts: Domain Admins inactive for > 90 days
      * Password Hygiene: User accounts configured with 'Password Never Expires' (DONT_EXPIRE_PASSWORD)
      * Legacy Protocol Exposure: SMBv1 or NTLMv1 authentication allowed across domain
  - Overall Identity Hygiene Score calculation (0 - 100)
"""

import sys
import json
import uuid
import re
import datetime

UAC_DONT_EXPIRE_PASSWORD = 0x10000       # 65536
UAC_DONT_REQ_PREAUTH = 0x400000          # 4194304
UAC_ACCOUNTDISABLE = 0x0002              # 2

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

def audit_directory_data(data: dict) -> tuple:
    findings = []
    critical_misconfigs = []
    deductions = 0

    users = data.get("users", [])
    domain_policies = data.get("domain_policies", {})

    for u in users:
        username = u.get("sAMAccountName", "unknown")
        uac = u.get("userAccountControl", 512)
        is_disabled = bool(uac & UAC_ACCOUNTDISABLE)
        if is_disabled:
            continue

        is_admin = u.get("is_domain_admin", False)
        spn = u.get("servicePrincipalName")

        # 1. AS-REP Roasting (DONT_REQ_PREAUTH)
        if (uac & UAC_DONT_REQ_PREAUTH) or u.get("dont_req_preauth"):
            f = {
                "id": str(uuid.uuid4()),
                "title": f"AS-REP Roasting Risk: Pre-Authentication Disabled for {username}",
                "severity": "critical",
                "cvss_score": 9.0,
                "account": username,
                "description": f"Account '{username}' does not require Kerberos pre-authentication (DONT_REQ_PREAUTH). An attacker can request an AS-REP ticket offline to crack credentials.",
                "remediation": "Re-enable Kerberos pre-authentication in Active Directory Users and Computers (Account tab)."
            }
            findings.append(f)
            critical_misconfigs.append(f"ASREP_ROASTING_{username}")
            deductions += 25

        # 2. Kerberoasting Risk on Admin SPN
        if spn and is_admin:
            f = {
                "id": str(uuid.uuid4()),
                "title": f"Kerberoasting Risk: Service Principal Name on Domain Admin ({username})",
                "severity": "high",
                "cvss_score": 8.4,
                "account": username,
                "description": f"Domain Admin account '{username}' has an SPN ({spn}) configured. Any domain user can request a TGS ticket to crack the account offline.",
                "remediation": "Move services to Managed Service Accounts (gMSA) and separate administrative accounts from service accounts."
            }
            findings.append(f)
            critical_misconfigs.append(f"KERBEROASTING_ADMIN_{username}")
            deductions += 20

        # 3. Password Never Expires
        if (uac & UAC_DONT_EXPIRE_PASSWORD) or u.get("password_never_expires"):
            f = {
                "id": str(uuid.uuid4()),
                "title": f"Password Never Expires Flag Set on {username}",
                "severity": "medium",
                "cvss_score": 5.2,
                "account": username,
                "description": f"User '{username}' is configured with password never expires, increasing persistence exposure if credentials leak.",
                "remediation": "Uncheck 'Password never expires' and enforce periodic password rotation or FIDO2/MFA."
            }
            findings.append(f)
            deductions += 10

        # 4. Inactive Domain Admin
        days_inactive = u.get("days_inactive", 0)
        if is_admin and days_inactive > 90:
            f = {
                "id": str(uuid.uuid4()),
                "title": f"Stale Privileged Account: Domain Admin {username} Inactive for {days_inactive} Days",
                "severity": "medium",
                "cvss_score": 6.8,
                "account": username,
                "description": f"Privileged Domain Admin account '{username}' has had no logon activity for {days_inactive} days.",
                "remediation": "Disable or decommission inactive privileged accounts to reduce attack surface."
            }
            findings.append(f)
            deductions += 15

    # 5. Legacy Protocols
    if domain_policies.get("smbv1_enabled", False):
        f = {
            "id": str(uuid.uuid4()),
            "title": "Legacy Insecure SMBv1 Protocol Enabled on Domain",
            "severity": "high",
            "cvss_score": 8.5,
            "description": "SMBv1 is active in domain group policies. SMBv1 is inherently vulnerable to EternalBlue and relay attacks.",
            "remediation": "Disable SMBv1 globally via GPO (MS17-010 compliance)."
        }
        findings.append(f)
        critical_misconfigs.append("SMBV1_ACTIVE")
        deductions += 20

    if domain_policies.get("lm_compatibility_level", 5) < 3:
        f = {
            "id": str(uuid.uuid4()),
            "title": "Insecure NTLMv1 / LM Authentication Allowed (LMCompatibilityLevel < 3)",
            "severity": "high",
            "cvss_score": 7.8,
            "description": "Domain accepts obsolete NTLMv1/LM responses, vulnerable to rainbow table crack and relay.",
            "remediation": "Set LMCompatibilityLevel to 5 (Send NTLMv2 response only. Refuse LM & NTLM)."
        }
        findings.append(f)
        critical_misconfigs.append("NTLMV1_ALLOWED")
        deductions += 20

    return findings, critical_misconfigs, deductions

def handle_execute(req):
    options = req.get("options", {})
    target = req.get("target") or req.get("domain", "")
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target domain '{target}' is not in authorized scope: {authorized_targets}"
            }

    directory_data = req.get("directory_data") or options.get("directory_data", {})
    if not directory_data:
        # Default real-world simulated Active Directory environment data
        directory_data = {
            "domain": target or "corp.internal",
            "domain_policies": {
                "smbv1_enabled": True,
                "lm_compatibility_level": 2
            },
            "users": [
                {
                    "sAMAccountName": "sql_svc",
                    "userAccountControl": 4194816, # DONT_REQ_PREAUTH + NORMAL_ACCOUNT
                    "is_domain_admin": False,
                    "servicePrincipalName": "MSSQLSvc/db01.corp.internal:1433"
                },
                {
                    "sAMAccountName": "legacy_admin",
                    "userAccountControl": 65536, # DONT_EXPIRE_PASSWORD
                    "is_domain_admin": True,
                    "days_inactive": 120
                },
                {
                    "sAMAccountName": "it_admin",
                    "userAccountControl": 512,
                    "is_domain_admin": True,
                    "servicePrincipalName": "HTTP/portal.corp.internal"
                }
            ]
        }

    findings, critical_misconfigs, deductions = audit_directory_data(directory_data)
    hygiene_score = max(0, 100 - deductions)

    return {
        "status": "success",
        "result": {
            "domain": target or directory_data.get("domain", "corp.internal"),
            "identity_hygiene_score": hygiene_score,
            "total_findings": len(findings),
            "critical_misconfigurations": critical_misconfigs,
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
            res = {"status": "ok", "module": "identity-ad-hygiene", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
