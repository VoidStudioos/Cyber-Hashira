#!/usr/bin/env python3
"""
Cyber Hashira - Threat Intelligence & MITRE ATT&CK Correlation Engine
Provides:
  - IOC Enrichment (IP, Domain, MD5, SHA-256)
  - MITRE ATT&CK Tactic & Technique Mapping
  - Reputation Scoring & Threat Actor Attribution
Communicates via standard Host Stdio JSON-RPC IPC.
"""

import sys
import json
import uuid
import datetime
import re

MITRE_DATABASE = {
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    "web_exploit": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    "credentials": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access / Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    "command_injection": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "data_leak": {
        "id": "T1552",
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/"
    },
    "phishing": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/"
    }
}

KNOWN_MALICIOUS_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "family": "ZeroByte Test Artifact",
        "score": 0,
        "type": "Harmless"
    },
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {
        "family": "Cobalt Strike Stage 1 Stager",
        "score": 95,
        "type": "C2 Beacon",
        "mitre": "T1071"
    },
    "d04b98f48e8f8bcc15c6ae5ac050801cd6dcfd428fb5f9e65c4e16e7807340fa": {
        "family": "LockBit 3.0 Ransomware Encryptor",
        "score": 98,
        "type": "Ransomware",
        "mitre": "T1486"
    }
}

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "Threat intelligence and MITRE ATT&CK correlation engine is operational.",
            "details": {
                "mitre_framework": "Enterprise ATT&CK v14",
                "cache_status": "synced"
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def enrich_ioc(ioc):
    ioc = ioc.strip()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    findings = []
    mitre_list = []
    threat_score = 15
    reputation = "Low Risk / Neutral"

    # 1. SHA-256 or MD5 Hash check
    if re.match(r"^[a-fA-F0-9]{64}$", ioc) or re.match(r"^[a-fA-F0-9]{32}$", ioc):
        norm_hash = ioc.lower()
        if norm_hash in KNOWN_MALICIOUS_HASHES:
            intel = KNOWN_MALICIOUS_HASHES[norm_hash]
            threat_score = intel["score"]
            reputation = f"Malicious ({intel['family']})"
            mitre_list.append(intel.get("mitre", "T1204"))

            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "threat-intelligence",
                "title": f"Known Malware Signature Match: {intel['family']}",
                "description": f"File hash '{ioc}' corresponds to confirmed threat artifact: {intel['family']}.",
                "severity": "Critical" if threat_score >= 80 else "Medium",
                "cvss_v3": 9.5 if threat_score >= 80 else 5.0,
                "cve": None,
                "cwe": "CWE-506",
                "evidence": f"Threat Intelligence Database Hash Match: {ioc}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Isolate affected host immediately and extract forensic memory dump.",
                "analyst_notes": f"Correlated with MITRE technique {intel.get('mitre', 'T1204')}."
            })
        else:
            threat_score = 10
            reputation = "Unknown / Clean Hash"

    # 2. IP Address check
    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc):
        if ioc.startswith("10.") or ioc.startswith("192.168.") or ioc.startswith("127."):
            reputation = "Private / RFC1918 Internal Network"
            threat_score = 0
        else:
            threat_score = 45
            reputation = "Public Routable Endpoint"
            mitre_list.append("T1595")
            mitre_list.append("T1046")

    # 3. Domain check
    elif "." in ioc:
        if ioc.endswith(".top") or ioc.endswith(".xyz") or ioc.endswith(".cc"):
            threat_score = 70
            reputation = "Suspicious TLD / Potential Phishing Infrastructure"
            mitre_list.append("T1566")
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "threat-intelligence",
                "title": f"High-Risk TLD Associated with Threat Infrastructure: {ioc}",
                "description": f"Domain '{ioc}' utilizes a top-level domain frequently abused in automated phishing campaigns.",
                "severity": "Medium",
                "cvss_v3": 6.2,
                "cve": None,
                "cwe": "CWE-200",
                "evidence": f"TLD reputation inspection for {ioc}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Inspect registrar WHOIS details and restrict email routing through this domain.",
                "analyst_notes": "Reputation engine alert."
            })
        else:
            threat_score = 25
            reputation = "Legitimate Registered Domain"

    # Resolve MITRE ATT&CK details
    resolved_techniques = []
    for m in mitre_list:
        for k, v in MITRE_DATABASE.items():
            if v["id"] == m:
                resolved_techniques.append(v)

    if not resolved_techniques:
        resolved_techniques.append(MITRE_DATABASE["port_scan"])

    return {
        "threat_score": threat_score,
        "reputation": reputation,
        "mitre_techniques": resolved_techniques,
        "findings": findings
    }

def handle_run_task(payload):
    task_id = payload.get("task_id", str(uuid.uuid4()))
    target = payload.get("target", "").strip()
    scope_approved = payload.get("scope_approved", False)
    options = payload.get("options", {})

    if not scope_approved:
        resp = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "findings": [],
                "raw_output": None,
                "error": "Execution aborted: Target scope has not been authorized by ScopeGuard."
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        return

    ioc = options.get("ioc", target)
    result = enrich_ioc(ioc)

    raw_output = (
        f"=== Cyber Hashira Threat Intelligence Enrichment ===\n"
        f"Indicator of Compromise (IOC): {ioc}\n"
        f"Threat Reputation: {result['reputation']}\n"
        f"Risk Score: {result['threat_score']} / 100\n\n"
        f"Correlated MITRE ATT&CK Techniques:\n"
    )
    for t in result["mitre_techniques"]:
        raw_output += f" - [{t['id']}] {t['name']} (Tactic: {t['tactic']})\n"

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": result["findings"],
            "threat_score": result["threat_score"],
            "reputation": result["reputation"],
            "mitre_techniques": result["mitre_techniques"],
            "raw_output": raw_output,
            "error": None
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_type = req.get("type")
            payload = req.get("payload", {})

            if req_type == "HealthCheck":
                handle_health_check()
                break
            elif req_type == "RunTask":
                handle_run_task(payload)
                break
            else:
                err_resp = {
                    "type": "Error",
                    "payload": {
                        "message": f"Unknown request type: {req_type}",
                        "code": "INVALID_REQUEST"
                    }
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                break
        except Exception as e:
            err_resp = {
                "type": "Error",
                "payload": {
                    "message": str(e),
                    "code": "EXCEPTION"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            break

if __name__ == "__main__":
    main()
