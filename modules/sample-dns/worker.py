#!/usr/bin/env python3
"""
Cyber Hashira - Sample DNS & Domain Reconnaissance Module
Independent Worker Process communicating via stdio JSON-RPC contract
"""
import sys
import json
import socket
import datetime
import uuid

def log_debug(msg):
    sys.stderr.write(f"[sample-dns] {msg}\n")
    sys.stderr.flush()

def handle_health_check():
    response = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "DNS reconnaissance worker is healthy and ready.",
            "details": {
                "resolver": "system_socket",
                "python_version": sys.version
            }
        }
    }
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()

def handle_run_task(payload):
    task_id = payload.get("task_id", str(uuid.uuid4()))
    target = payload.get("target", "").strip()
    scope_approved = payload.get("scope_approved", False)

    # 1. Mandatory scope check enforcement
    if not scope_approved:
        response = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "findings": [],
                "raw_output": None,
                "error": "Execution aborted: Target scope has not been authorized."
            }
        }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
        return

    # Extract hostname if target is a URL
    hostname = target
    if "://" in hostname:
        hostname = hostname.split("://")[1].split("/")[0].split(":")[0]

    findings = []
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw_lines = [f"=== DNS Reconnaissance Report for {hostname} ==="]

    # Perform DNS resolution
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = sorted(list({info[4][0] for info in addr_info}))
        raw_lines.append(f"Resolved IP addresses: {', '.join(ips)}")

        # Finding 1: Discovered Host Mapping
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "sample-dns",
            "title": f"DNS Resolution Discovered {len(ips)} IP Addresses",
            "description": f"Domain '{hostname}' successfully resolved to: {', '.join(ips)}.",
            "severity": "Informational",
            "cvss_v3": None,
            "cve": None,
            "cwe": "CWE-200",
            "evidence": f"getaddrinfo({hostname}) -> {ips}",
            "timestamp": now_iso,
            "status": "Open",
            "remediation": "Verify that all public IP endpoints align with authorized cloud/hosting infrastructure.",
            "analyst_notes": "Passive DNS query performed."
        })

        # Check for RFC1918 private IP exposure in public DNS
        has_private_ip = any(
            ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
            for ip in ips if "." in ip
        )
        if has_private_ip:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "sample-dns",
                "title": f"Internal RFC1918 IP Exposed in Public DNS for {hostname}",
                "description": f"The domain {hostname} resolves to one or more internal/private RFC1918 addresses.",
                "severity": "Medium",
                "cvss_v3": 5.3,
                "cve": None,
                "cwe": "CWE-200",
                "evidence": f"Internal IPs detected: {[ip for ip in ips if ip.startswith('10.') or ip.startswith('192.168.')]}",
                "timestamp": now_iso,
                "status": "Open",
                "remediation": "Remove internal IP allocations from publicly resolvable DNS zones.",
                "analyst_notes": "Internal network architecture leakage detected."
            })

    except socket.gaierror as e:
        raw_lines.append(f"DNS Resolution Failed: {e}")
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "sample-dns",
            "title": f"DNS Resolution Failure for {hostname}",
            "description": f"Target host could not be resolved by system resolver: {e}",
            "severity": "Low",
            "cvss_v3": None,
            "cve": None,
            "cwe": None,
            "evidence": str(e),
            "timestamp": now_iso,
            "status": "Open",
            "remediation": "Check target spelling and DNS nameserver reachability.",
            "analyst_notes": None
        })

    response = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": findings,
            "raw_output": "\n".join(raw_lines),
            "error": None
        }
    }
    sys.stdout.write(json.dumps(response) + "\n")
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
