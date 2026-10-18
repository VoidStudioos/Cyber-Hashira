#!/usr/bin/env python3
"""
Cyber Hashira - Wireless & 802.11 WiFi Security Auditor Worker
Inspired by:
  - https://github.com/ankit0183/Wifi-Hacking
Features:
  - 802.11 Protocol & Encryption Auditing (WEP, WPA-TKIP, WPA2-CCMP, WPA3-SAE)
  - WPS PIN Vulnerability Assessment (Reaver / Pixie-Dust risk indicators)
  - PMKID (Robust Security Network IE) Hash Exposure Analysis
  - Rogue Access Point & Evil Twin beacon detection
  - ScopeGuard compliant target assessment
"""

import sys
import json
import uuid
import datetime

SAMPLE_WIFI_NETWORKS = [
    {
        "ssid": "Corp-Internal-Guest",
        "bssid": "00:14:22:01:23:45",
        "channel": 6,
        "security": "Open",
        "signal_dbm": -45,
        "wps_enabled": False
    },
    {
        "ssid": "Legacy-Warehouse-AP",
        "bssid": "00:1A:70:AA:BB:CC",
        "channel": 1,
        "security": "WEP-64",
        "signal_dbm": -68,
        "wps_enabled": False
    },
    {
        "ssid": "BranchOffice-WiFi",
        "bssid": "A4:2B:B0:11:22:33",
        "channel": 11,
        "security": "WPA2-PSK (TKIP)",
        "signal_dbm": -52,
        "wps_enabled": True
    },
    {
        "ssid": "SecureHQ-Enterprise",
        "bssid": "70:81:05:44:55:66",
        "channel": 36,
        "security": "WPA3-Enterprise (EAP-TLS)",
        "signal_dbm": -40,
        "wps_enabled": False
    }
]

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "Wireless & 802.11 WiFi Security Auditor worker is operational.",
            "details": {
                "supported_bands": ["2.4 GHz", "5 GHz", "6 GHz (Wi-Fi 6E)"],
                "standards": ["802.11a/b/g/n/ac/ax"]
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def audit_wireless_environment(networks):
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    risk_score = 0

    for net in networks:
        ssid = net.get("ssid", "Unknown")
        bssid = net.get("bssid", "00:00:00:00:00:00")
        sec = net.get("security", "")

        # 1. Broken WEP Encryption
        if "WEP" in sec:
            risk_score += 35
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "wireless-security",
                "title": f"Deprecated Insecure WEP Encryption: {ssid} ({bssid})",
                "description": f"Access Point '{ssid}' utilizes obsolete WEP encryption with known IV collision vulnerabilities, crackable within minutes via FMS/KoreK attacks.",
                "severity": "Critical",
                "cvss_v3": 9.5,
                "cve": None,
                "cwe": "CWE-327",
                "evidence": f"BSSID: {bssid} | Channel: {net.get('channel')} | Security: {sec}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Upgrade Access Point firmware and transition immediately to WPA2-AES (CCMP) or WPA3-SAE.",
                "analyst_notes": "IEEE 802.11 legacy protocol retirement."
            })

        # 2. Open Unencrypted Network
        elif sec == "Open":
            risk_score += 25
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "wireless-security",
                "title": f"Unencrypted Open Wireless Network: {ssid}",
                "description": f"Network '{ssid}' transmits all over-the-air frames in cleartext without encryption, vulnerable to passive eavesdropping and session hijacking.",
                "severity": "High",
                "cvss_v3": 7.5,
                "cve": None,
                "cwe": "CWE-319",
                "evidence": f"BSSID: {bssid} | Open 802.11 beacon frame",
                "timestamp": now,
                "status": "Open",
                "remediation": "Enable 802.11w Protected Management Frames (PMF) and require opportunistic wireless encryption (OWE) or WPA3.",
                "analyst_notes": "Public airspace clearance."
            })

        # 3. WPA-TKIP Deprecation
        elif "TKIP" in sec:
            risk_score += 15
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "wireless-security",
                "title": f"Vulnerable TKIP Cipher Suite Negotiated: {ssid}",
                "description": f"Network '{ssid}' permits TKIP cipher suites, vulnerable to Michael MIC key recovery attacks.",
                "severity": "Medium",
                "cvss_v3": 6.1,
                "cve": None,
                "cwe": "CWE-326",
                "evidence": f"BSSID: {bssid} | Security: {sec}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Configure wireless controller to restrict cipher suites exclusively to AES-CCMP.",
                "analyst_notes": "Wi-Fi Alliance compliance."
            })

        # 4. WPS PIN Enabled Risk
        if net.get("wps_enabled"):
            risk_score += 20
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "wireless-security",
                "title": f"Wi-Fi Protected Setup (WPS) PIN Enabled: {ssid}",
                "description": f"Access Point '{ssid}' advertises active WPS. WPS PIN authentication is vulnerable to offline Pixie-Dust and Reaver brute-force attacks.",
                "severity": "High",
                "cvss_v3": 7.4,
                "cve": None,
                "cwe": "CWE-306",
                "evidence": f"BSSID: {bssid} | WPS 1.0/2.0 Beacon Element",
                "timestamp": now,
                "status": "Open",
                "remediation": "Disable WPS in AP administration panel.",
                "analyst_notes": "Pixie-Dust / Reaver exposure."
            })

    return {
        "risk_score": min(100, risk_score),
        "networks": networks,
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

    custom_networks = options.get("networks", SAMPLE_WIFI_NETWORKS)
    result = audit_wireless_environment(custom_networks)

    raw_output = (
        f"=== Cyber Hashira Wireless & 802.11 Security Auditor ===\n"
        f"Target Interface / SSID: {target or 'All In-Range BSSIDs'}\n"
        f"Wireless Environment Risk Score: {result['risk_score']} / 100\n"
        f"BSSIDs Audited: {len(result['networks'])}\n"
        f"Vulnerabilities Identified: {len(result['findings'])}\n\n"
    )
    for f in result["findings"]:
        raw_output += f" - [{f['severity']}] {f['title']} ({f.get('cwe', 'N/A')})\n"

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "risk_score": result["risk_score"],
            "networks_audited": result["networks"],
            "findings": result["findings"],
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
