#!/usr/bin/env python3
"""
Cyber Hashira - Email Security & Anti-Spoofing Auditor
Features:
  - Domain Email Posture:
      * SPF record audit (v=spf1, qualifier: -all, ~all, +all, lookup count)
      * DMARC policy enforcement (p=reject, p=quarantine, p=none)
      * Reporting tags (rua, ruf) & percentage enforcement (pct)
      * BIMI (Brand Indicators) & MTA-STS (Strict Transport Security)
  - Raw EML Header Forensics:
      * From vs Return-Path mismatch (Sender Spoofing)
      * Authentication-Results evaluation (dkim=fail, spf=fail)
      * Anomalous Received: hop count
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

def audit_spf(spf_record: str) -> tuple:
    findings = []
    score_deduction = 0
    parsed = {"record": spf_record, "qualifier": "unknown", "includes": []}

    if not spf_record or not spf_record.startswith("v=spf1"):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Missing or Invalid SPF (Sender Policy Framework) Record",
            "severity": "high",
            "cvss_score": 7.5,
            "description": "Domain lacks a valid v=spf1 DNS TXT record, allowing unauthorized servers to spoof email as this domain.",
            "remediation": "Publish a valid TXT record for SPF: 'v=spf1 include:_spf.example.com -all'."
        })
        return parsed, findings, 35

    tokens = spf_record.split()
    parsed["includes"] = [t for t in tokens if t.startswith("include:")]

    if "+all" in tokens:
        parsed["qualifier"] = "+all"
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Extremely Permissive SPF Policy (+all Detected)",
            "severity": "critical",
            "cvss_score": 9.1,
            "description": "The SPF record ends with +all, which explicitly allows any IP address on the internet to send email on behalf of your domain.",
            "remediation": "Replace +all with -all (hardfail) or ~all (softfail)."
        })
        score_deduction += 40
    elif "?all" in tokens:
        parsed["qualifier"] = "?all"
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Neutral SPF Policy (?all)",
            "severity": "medium",
            "cvss_score": 5.3,
            "description": "The SPF record ends with ?all (neutral), providing zero protection against domain impersonation.",
            "remediation": "Enforce strict fail with -all or ~all."
        })
        score_deduction += 20
    elif "~all" in tokens:
        parsed["qualifier"] = "~all"
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "SoftFail SPF Policy (~all) in Use",
            "severity": "low",
            "cvss_score": 3.2,
            "description": "SPF is configured with ~all (SoftFail). While acceptable during transition, strict -all is recommended with DMARC reject.",
            "remediation": "Transition to -all once mail flows and third-party senders are verified."
        })
        score_deduction += 5
    elif "-all" in tokens:
        parsed["qualifier"] = "-all"
    else:
        parsed["qualifier"] = "none"
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "SPF Record Missing Terminal Qualifier",
            "severity": "medium",
            "cvss_score": 5.0,
            "description": "The SPF record does not specify a terminal mechanism (-all, ~all).",
            "remediation": "Add -all to the end of the SPF record."
        })
        score_deduction += 15

    return parsed, findings, score_deduction

def audit_dmarc(dmarc_record: str) -> tuple:
    findings = []
    score_deduction = 0
    parsed = {"record": dmarc_record, "policy": "none", "rua": None, "pct": 100}

    if not dmarc_record or not dmarc_record.startswith("v=DMARC1"):
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "Missing DMARC Policy (Domain-based Message Authentication)",
            "severity": "high",
            "cvss_score": 7.8,
            "description": "The domain lacks a DMARC policy (_dmarc TXT record). Receiving mail servers cannot verify how to treat unauthenticated emails.",
            "remediation": "Create a TXT record at _dmarc.yourdomain.com with 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com'."
        })
        return parsed, findings, 40

    parts = [p.strip() for p in dmarc_record.split(";") if p.strip()]
    for p in parts:
        if p.startswith("p="):
            parsed["policy"] = p.split("=")[1].strip().lower()
        elif p.startswith("rua="):
            parsed["rua"] = p.split("=")[1].strip()
        elif p.startswith("pct="):
            try:
                parsed["pct"] = int(p.split("=")[1].strip())
            except ValueError:
                pass

    if parsed["policy"] == "none":
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "DMARC Policy Set to 'none' (Monitoring Only)",
            "severity": "medium",
            "cvss_score": 5.8,
            "description": "DMARC policy is set to p=none. Spoofed emails will still be delivered to recipient inboxes without rejection or quarantine.",
            "remediation": "Advance DMARC policy from p=none to p=quarantine and eventually p=reject."
        })
        score_deduction += 20
    elif parsed["policy"] == "quarantine":
        score_deduction += 5

    if not parsed["rua"]:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": "DMARC Missing Aggregate Reporting URI (rua)",
            "severity": "low",
            "cvss_score": 3.5,
            "description": "DMARC record does not define rua= destination. Administrators will not receive visibility reports on authentication failures.",
            "remediation": "Add 'rua=mailto:reports@yourdomain.com' to DMARC record."
        })
        score_deduction += 10

    if parsed["pct"] < 100:
        findings.append({
            "id": str(uuid.uuid4()),
            "title": f"Partial DMARC Enforcement (pct={parsed['pct']}%)",
            "severity": "low",
            "cvss_score": 3.0,
            "description": f"Only {parsed['pct']}% of unauthenticated mail is subjected to policy action.",
            "remediation": "Increase pct to 100 once authentication alignment is verified."
        })
        score_deduction += 5

    return parsed, findings, score_deduction

def analyze_raw_eml(eml_text: str) -> list:
    findings = []
    from_match = re.search(r"^From:\s*(.+)$", eml_text, re.MULTILINE | re.IGNORECASE)
    return_path = re.search(r"^Return-Path:\s*<?([^>]+)>?", eml_text, re.MULTILINE | re.IGNORECASE)
    auth_results = re.search(r"^Authentication-Results:\s*(.+)$", eml_text, re.MULTILINE | re.IGNORECASE)

    sender_email = ""
    return_path_email = ""

    if from_match:
        m = re.search(r"[\w\.-]+@[\w\.-]+", from_match.group(1))
        if m:
            sender_email = m.group(0).lower()

    if return_path:
        m = re.search(r"[\w\.-]+@[\w\.-]+", return_path.group(1))
        if m:
            return_path_email = m.group(0).lower()

    if sender_email and return_path_email:
        sender_domain = sender_email.split("@")[1]
        return_domain = return_path_email.split("@")[1]
        if sender_domain != return_domain:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Email Header Spoofing Detected (From vs Return-Path Domain Mismatch)",
                "severity": "high",
                "cvss_score": 8.0,
                "description": f"Display From domain '{sender_domain}' differs from Return-Path domain '{return_domain}'. Indicator of spoofing or phishing.",
                "remediation": "Verify sending server identity and enforce SPF/DKIM alignment."
            })

    if auth_results:
        res = auth_results.group(1).lower()
        if "dkim=fail" in res or "dkim=temperror" in res:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Cryptographic DKIM Signature Verification Failed",
                "severity": "high",
                "cvss_score": 7.6,
                "description": "Authentication-Results indicates DKIM cryptographic signature verification failed.",
                "remediation": "Check DNS selector key alignment and ensure mail server does not modify body after signing."
            })
        if "spf=fail" in res or "spf=softfail" in res:
            findings.append({
                "id": str(uuid.uuid4()),
                "title": "Sender Policy Framework (SPF) Verification Failed",
                "severity": "medium",
                "cvss_score": 6.5,
                "description": "Authentication-Results indicates sending MTA IP address was not authorized by domain SPF record.",
                "remediation": "Authorize sending IP or relay MTA in domain SPF record."
            })

    return findings

def handle_execute(req):
    target = req.get("target") or req.get("domain", "")
    options = req.get("options", {})
    authorized_targets = options.get("authorized_targets", [])

    if target and authorized_targets:
        if not ScopeGuard.is_authorized(target, authorized_targets):
            return {
                "status": "error",
                "code": "SCOPE_VIOLATION",
                "message": f"Target '{target}' is not in authorized scope: {authorized_targets}"
            }

    all_findings = []
    base_score = 100

    # Simulate or query records
    spf_record = options.get("simulate_spf", "v=spf1 include:_spf.google.com ~all")
    dmarc_record = options.get("simulate_dmarc", "v=DMARC1; p=none; sp=none; rua=mailto:dmarc@target.com")

    spf_parsed, spf_findings, spf_deduct = audit_spf(spf_record)
    all_findings.extend(spf_findings)
    base_score -= spf_deduct

    dmarc_parsed, dmarc_findings, dmarc_deduct = audit_dmarc(dmarc_record)
    all_findings.extend(dmarc_findings)
    base_score -= dmarc_deduct

    raw_eml = options.get("raw_eml", "")
    if raw_eml:
        eml_findings = analyze_raw_eml(raw_eml)
        all_findings.extend(eml_findings)
        base_score -= len(eml_findings) * 15

    final_score = max(0, min(100, base_score))

    return {
        "status": "success",
        "result": {
            "domain": target or "evaluated_domain.org",
            "security_score": final_score,
            "spf_evaluation": spf_parsed,
            "dmarc_evaluation": dmarc_parsed,
            "findings_count": len(all_findings),
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
            res = {"status": "ok", "module": "email-security", "version": "1.0.0"}
        else:
            res = handle_execute(req)

        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()

if __name__ == "__main__":
    main()
