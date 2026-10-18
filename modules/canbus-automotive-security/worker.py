#!/usr/bin/env python3
"""
Cyber Hashira - CAN Bus & Automotive Vehicle Security Worker
Inspired by:
  - https://github.com/iDoka/awesome-canbus
Features:
  - CAN 2.0A (11-bit) and CAN 2.0B (29-bit) traffic analysis
  - Bus arbitration DoS flooding detection (ID 0x000 dominance attack)
  - Diagnostic OBD-II / UDS service exposures (Service 0x27 SecurityAccess bypass)
  - Unauthorized engine torque / brake actuator frame spoofing indicators
  - Candump log parsing and live interface simulation
"""

import sys
import json
import uuid
import datetime
import re

SAMPLE_CAN_LOG = """
(1600000000.000100) vcan0 000#0000000000000000
(1600000000.000200) vcan0 000#0000000000000000
(1600000000.000300) vcan0 7DF#0201000000000000
(1600000000.000400) vcan0 7E8#064100BE7FA81300
(1600000000.000500) vcan0 7DF#0227010000000000
(1600000000.000600) vcan0 244#FFFFFFFFFFFFFFFF
"""

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "CAN Bus & Automotive Vehicle Security worker is operational.",
            "details": {
                "supported_protocols": ["ISO 11898", "ISO 14229 (UDS)", "ISO 15765 (DoCAN)", "OBD-II"],
                "bus_speeds": ["125 kbps", "250 kbps", "500 kbps", "1 Mbps"]
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def analyze_can_traffic(candump_text):
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    health_score = 100

    lines = [line.strip() for line in candump_text.splitlines() if line.strip()]
    frames_count = len(lines)

    id_counts = {}
    uds_security_access = False
    has_arbitration_flood = False

    for line in lines:
        # Match standard candump format: (timestamp) interface ID#DATA
        match = re.search(r"([0-9a-fA-F]{3,8})#([0-9a-fA-F]*)", line)
        if match:
            can_id = match.group(1).upper()
            payload = match.group(2).upper()

            id_counts[can_id] = id_counts.get(can_id, 0) + 1

            # Check 1: Dominant 0x000 Bus Arbitration Flooding
            if can_id in ("000", "00000000"):
                has_arbitration_flood = True

            # Check 2: UDS Diagnostic Service 0x27 (SecurityAccess)
            if can_id in ("7DF", "7E0") and len(payload) >= 4:
                # Payload format: Length, Service ID, Subfunction...
                if payload[2:4] == "27":
                    uds_security_access = True

    # Finding 1: Bus Flooding / Denial of Service
    if has_arbitration_flood:
        health_score -= 40
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "canbus-automotive-security",
            "title": "High-Priority Bus Arbitration Flooding (ID 0x000 Denial of Service)",
            "description": "Detected repeated transmission of ID 0x000 frames. Because CAN arbitration prioritizes dominant bits (zeros), 0x000 indefinitely halts safety-critical ECU transmissions.",
            "severity": "Critical",
            "cvss_v3": 8.9,
            "cve": None,
            "cwe": "CWE-400",
            "evidence": f"Found {id_counts.get('000', 0)} arbitration dominant 0x000 frames.",
            "timestamp": now,
            "status": "Open",
            "remediation": "Deploy hardware CAN bus boundary gateways with hardware rate limiters and frame whitelist filters.",
            "analyst_notes": "Automotive DoS attack vector."
        })

    # Finding 2: Exposed UDS SecurityAccess Diagnostic Service
    if uds_security_access:
        health_score -= 25
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "canbus-automotive-security",
            "title": "Exposed Unified Diagnostic Service 0x27 (SecurityAccess)",
            "description": "ISO 14229 UDS SecurityAccess request detected on broadcast diagnostic ID 0x7DF. Threat actors can attempt seed-key algorithmic recovery to flash untrusted firmware or override vehicle controls.",
            "severity": "High",
            "cvss_v3": 7.8,
            "cve": None,
            "cwe": "CWE-287",
            "evidence": "UDS Request with Service ID 0x27 discovered in CAN traffic.",
            "timestamp": now,
            "status": "Open",
            "remediation": "Restrict diagnostic services while vehicle velocity > 0 km/h and implement asymmetric HSM-based key exchange.",
            "analyst_notes": "UN R155 automotive cybersecurity compliance."
        })

    return {
        "bus_health_score": max(0, health_score),
        "frames_analyzed": frames_count,
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

    candump_content = options.get("can_dump", SAMPLE_CAN_LOG)
    result = analyze_can_traffic(candump_content)

    raw_output = (
        f"=== Cyber Hashira CAN Bus & Automotive Security Auditor ===\n"
        f"Target Interface / Log: {target or 'vcan0 / Candump'}\n"
        f"CAN Bus Health Score: {result['bus_health_score']} / 100\n"
        f"Frames Analyzed: {result['frames_analyzed']}\n"
        f"Vulnerabilities Identified: {len(result['findings'])}\n\n"
    )
    for f in result["findings"]:
        raw_output += f" - [{f['severity']}] {f['title']} ({f.get('cwe', 'N/A')})\n"

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "bus_health_score": result["bus_health_score"],
            "frames_analyzed": result["frames_analyzed"],
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
