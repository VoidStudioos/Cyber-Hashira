#!/usr/bin/env python3
"""
Cyber Hashira - MITRE Sensor Mappings & Detection Coverage Auditor
Based on:
  - MITRE Center for Threat-Informed Defense (CTID) - Sensor Mappings to ATT&CK (SMAP)
Features:
  - Connects deployed security sensors to ATT&CK Data Sources:
      * Sysmon (Process Creation, Network Connections, Registry, Driver Load)
      * Windows Event Logs (Security 4624/4625, PowerShell 4104)
      * Linux Auditd / eBPF (execve, openat, ptrace)
      * Zeek / Bro (dns.log, ssl.log, conn.log)
      * Suricata (Alerts, Protocol Inspection)
  - Identifies Detection Blind Spots for critical techniques (T1059, T1055, T1003, T1071)
  - Calculates Overall Threat-Informed Detection Coverage Score
"""

import sys
import json
import uuid
import datetime

# Sensor capabilities mapping to ATT&CK Data Sources and Techniques
SMAP_SENSOR_DEFINITIONS = {
    "sysmon": {
        "name": "Microsoft Sysmon",
        "type": "Endpoint Host Telemetry",
        "data_sources": [
            "Process: Process Creation",
            "Process: Process Termination",
            "Network Traffic: Network Connection Creation",
            "Windows Registry: Windows Registry Key Modification",
            "File: File Creation"
        ],
        "covered_techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
            {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
            {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
        ]
    },
    "windows_event_log": {
        "name": "Windows Security & PowerShell Event Logs",
        "type": "OS Audit Log",
        "data_sources": [
            "Logon Session: Logon Session Creation",
            "Script: Script Execution",
            "User Account: User Account Authentication"
        ],
        "covered_techniques": [
            {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
            {"id": "T1059.001", "name": "PowerShell Script Block Logging", "tactic": "Execution"},
            {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"}
        ]
    },
    "linux_auditd": {
        "name": "Linux Auditd / eBPF Trace",
        "type": "Host Kernel Telemetry",
        "data_sources": [
            "Kernel: Syscall Auditing",
            "File: File Modification"
        ],
        "covered_techniques": [
            {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
            {"id": "T1003.008", "name": "/etc/passwd & /etc/shadow Access", "tactic": "Credential Access"}
        ]
    },
    "zeek": {
        "name": "Zeek Network Security Monitor",
        "type": "Network Metadata Sensor",
        "data_sources": [
            "Network Traffic: Network Traffic Flow",
            "Network Traffic: DNS Queries",
            "Network Traffic: TLS Handshake Metadata"
        ],
        "covered_techniques": [
            {"id": "T1071.001", "name": "Web Protocols (HTTP/HTTPS C2)", "tactic": "Command and Control"},
            {"id": "T1071.004", "name": "DNS C2 Tunneling", "tactic": "Command and Control"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}
        ]
    },
    "suricata": {
        "name": "Suricata Network IDS/IPS",
        "type": "Network Signature Sensor",
        "data_sources": [
            "Network Traffic: Network Traffic Content",
            "Network Traffic: Protocol Violation"
        ],
        "covered_techniques": [
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
            {"id": "T1566", "name": "Phishing Payload Delivery", "tactic": "Initial Access"}
        ]
    }
}

CRITICAL_TECHNIQUES = [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "req_sensor": "sysmon"},
    {"id": "T1055", "name": "Process Injection", "req_sensor": "sysmon"},
    {"id": "T1078", "name": "Valid Accounts / Credential Abuse", "req_sensor": "windows_event_log"},
    {"id": "T1071.004", "name": "DNS C2 Tunneling", "req_sensor": "zeek"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "req_sensor": "suricata"}
]

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "MITRE Sensor Mappings to ATT&CK Coverage Auditor worker is operational.",
            "details": {
                "mitre_smap_version": "v13.1",
                "framework": "Center for Threat-Informed Defense (CTID)"
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def evaluate_sensor_coverage(active_sensor_keys):
    findings = []
    covered_techniques = []
    blind_spots = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    active_keys = set(k.lower().strip() for k in active_sensor_keys)

    # Accumulate all techniques covered by active sensors
    for s_key in active_keys:
        if s_key in SMAP_SENSOR_DEFINITIONS:
            s_def = SMAP_SENSOR_DEFINITIONS[s_key]
            for t in s_def["covered_techniques"]:
                if t not in covered_techniques:
                    covered_techniques.append(t)

    # Check for critical detection blind spots
    for crit in CRITICAL_TECHNIQUES:
        req = crit["req_sensor"]
        if req not in active_keys:
            blind_spots.append(crit)
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "sensor-coverage-attack",
                "title": f"Detection Blind Spot: [{crit['id']}] {crit['name']}",
                "description": (
                    f"Adversary technique '{crit['name']}' ({crit['id']}) lacks requisite telemetry sensors. "
                    f"According to MITRE SMAP, this technique requires '{SMAP_SENSOR_DEFINITIONS[req]['name']}' "
                    f"to provide required data sources."
                ),
                "severity": "High",
                "cvss_v3": 7.5,
                "cve": None,
                "cwe": "CWE-778",
                "evidence": f"Missing Sensor: {req} | Technique: {crit['id']}",
                "timestamp": now,
                "status": "Open",
                "remediation": f"Deploy and configure {SMAP_SENSOR_DEFINITIONS[req]['name']} to forward telemetry events to your SIEM/XDR.",
                "analyst_notes": "MITRE CTID Sensor Mappings to ATT&CK gap analysis."
            })

    total_possible = len(CRITICAL_TECHNIQUES)
    covered_count = total_possible - len(blind_spots)
    coverage_score = int((covered_count / total_possible) * 100)

    return {
        "detection_coverage_score": coverage_score,
        "covered_techniques": covered_techniques,
        "blind_spots": blind_spots,
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

    # If active sensors passed in options, use them; otherwise default to partial coverage for testing
    active_sensors = options.get("active_sensors", ["sysmon", "windows_event_log"])
    result = evaluate_sensor_coverage(active_sensors)

    raw_output = (
        f"=== Cyber Hashira MITRE Sensor Coverage Auditor ===\n"
        f"Target Pipeline: {target or 'Enterprise Detection Stack'}\n"
        f"Active Sensors Evaluated: {', '.join(active_sensors)}\n"
        f"Threat-Informed Coverage Score: {result['detection_coverage_score']} / 100\n"
        f"Covered Techniques: {len(result['covered_techniques'])}\n"
        f"Critical Blind Spots Identified: {len(result['blind_spots'])}\n\n"
    )
    for b in result["blind_spots"]:
        raw_output += f" - [BLIND SPOT] [{b['id']}] {b['name']} (Missing: {b['req_sensor']})\n"

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "detection_coverage_score": result["detection_coverage_score"],
            "covered_techniques": result["covered_techniques"],
            "blind_spots": result["blind_spots"],
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
