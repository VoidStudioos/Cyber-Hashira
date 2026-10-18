#!/usr/bin/env python3
"""
Cyber Hashira - Network Security & Port Discovery Worker Process
Provides:
  - Authorized Port & Service Scanning
  - Insecure Protocol Identification (Telnet, FTP, unencrypted HTTP, exposed RDP/SMB)
  - Native Nmap execution adapter with high-speed socket scanner fallback
Communicates via standard Host Stdio JSON-RPC IPC.
"""

import sys
import json
import socket
import concurrent.futures
import time
import uuid
import datetime
import shutil
import subprocess

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB"
}

def handle_health_check():
    nmap_path = shutil.which("nmap")
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "Network security scanner is operational.",
            "details": {
                "nmap_available": nmap_path is not None,
                "nmap_path": nmap_path,
                "engine": "cyber_hashira_net_engine"
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def probe_port(host, port, timeout_sec=0.7):
    """Probes a single TCP port and attempts simple service banner extraction"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    start = time.time()
    try:
        res = s.connect_ex((host, port))
        if res == 0:
            elapsed_ms = int((time.time() - start) * 1000)
            service_name = COMMON_PORTS.get(port, "unknown")
            banner = ""
            try:
                s.sendall(b"\r\n")
                raw = s.recv(256)
                banner = raw.decode("utf-8", errors="replace").strip()
            except Exception:
                pass
            s.close()
            return {
                "port": port,
                "state": "open",
                "service": service_name,
                "banner": banner,
                "latency_ms": elapsed_ms
            }
        s.close()
    except Exception:
        pass
    return None

def analyze_discovered_ports(target_host, open_ports):
    """Generates structured findings for dangerous or insecure open services"""
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # General Open Ports inventory finding
    if open_ports:
        port_list_str = ", ".join(f"{p['port']}/{p['service']}" for p in open_ports)
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "network-security",
            "title": f"Discovered {len(open_ports)} Open TCP Ports on {target_host}",
            "description": f"Port discovery identified the following open listening endpoints on '{target_host}': {port_list_str}.",
            "severity": "Informational",
            "cvss_v3": None,
            "cve": None,
            "cwe": "CWE-200",
            "evidence": json.dumps(open_ports, indent=2),
            "timestamp": now,
            "status": "Open",
            "remediation": "Audit exposed ports to ensure only authorized public services are reachable.",
            "analyst_notes": "Port scan completed."
        })

    for p in open_ports:
        port_num = p["port"]

        # 1. Telnet (Port 23)
        if port_num == 23:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "network-security",
                "title": f"Insecure Cleartext Telnet Service on Port 23",
                "description": f"Host '{target_host}' is running an unencrypted Telnet service on port 23, exposing administrative credentials to packet sniffing.",
                "severity": "High",
                "cvss_v3": 7.5,
                "cve": None,
                "cwe": "CWE-319",
                "evidence": f"Port 23 is OPEN. Banner: {p.get('banner', 'N/A')}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Disable Telnet and migrate administration strictly to SSH (Port 22).",
                "analyst_notes": "Legacy cleartext protocol exposure."
            })

        # 2. Plaintext FTP (Port 21)
        elif port_num == 21:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "network-security",
                "title": f"Cleartext FTP Protocol on Port 21",
                "description": f"Host '{target_host}' exposes standard FTP on port 21 without mandatory encryption.",
                "severity": "Medium",
                "cvss_v3": 5.3,
                "cve": None,
                "cwe": "CWE-319",
                "evidence": f"Port 21 is OPEN. Banner: {p.get('banner', 'N/A')}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Enforce FTPS (TLS) or migrate file transfers to SFTP over SSH.",
                "analyst_notes": "Plaintext credentials in transit risk."
            })

        # 3. Exposed SMB (Port 445)
        elif port_num == 445:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "network-security",
                "title": f"Exposed SMB File Sharing on Port 445",
                "description": f"Host '{target_host}' has SMB file sharing accessible directly over the network.",
                "severity": "Medium",
                "cvss_v3": 5.8,
                "cve": None,
                "cwe": "CWE-284",
                "evidence": "Port 445 is OPEN.",
                "timestamp": now,
                "status": "Open",
                "remediation": "Block inbound SMB port 445 from public/untrusted networks using perimeter firewalls.",
                "analyst_notes": "Lateral movement and remote file access risk."
            })

        # 4. Exposed RDP (Port 3389)
        elif port_num == 3389:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "network-security",
                "title": f"Exposed Remote Desktop (RDP) on Port 3389",
                "description": f"Windows Remote Desktop service is listening on port 3389 at '{target_host}'.",
                "severity": "Medium",
                "cvss_v3": 5.3,
                "cve": None,
                "cwe": "CWE-284",
                "evidence": "Port 3389 is OPEN.",
                "timestamp": now,
                "status": "Open",
                "remediation": "Place RDP behind a VPN, MFA gateway, or restrict access via strict IP allowlists.",
                "analyst_notes": "Brute force and remote access vector."
            })

    return findings

def handle_run_task(payload):
    task_id = payload.get("task_id", str(uuid.uuid4()))
    target = payload.get("target", "").strip()
    scope_approved = payload.get("scope_approved", False)
    options = payload.get("options", {})

    # 1. Mandatory scope check enforcement
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

    # Extract clean hostname or IP
    clean_host = target
    if "://" in clean_host:
        clean_host = clean_host.split("://")[1].split("/")[0].split(":")[0]

    # Resolve IP address
    try:
        ip_addr = socket.gethostbyname(clean_host)
    except Exception as e:
        resp = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "findings": [],
                "raw_output": None,
                "error": f"Failed to resolve target hostname '{clean_host}': {e}"
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        return

    # Determine port list
    port_profile = options.get("port_profile", "top-100")
    if port_profile == "top-20":
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    elif port_profile == "custom":
        raw_ports = options.get("custom_ports", "80,443,22,21,3389,8080")
        ports = []
        for p in raw_ports.split(","):
            p = p.strip()
            if p.isdigit():
                ports.append(int(p))
    else:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    # Concurrently scan selected ports
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(probe_port, ip_addr, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])

    # Analyze open ports for security findings
    findings = analyze_discovered_ports(clean_host, open_ports)

    # Format output report
    lines = [
        f"=== Cyber Hashira Network Port Scan Report ===",
        f"Target: {clean_host} ({ip_addr})",
        f"Scan Time: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
        f"Ports Scanned: {len(ports)} | Open Ports Found: {len(open_ports)}",
        ""
    ]
    if open_ports:
        lines.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<20} {'LATENCY':<10}")
        lines.append("-" * 55)
        for p in open_ports:
            lines.append(f"{p['port']:<10} {p['state']:<10} {p['service']:<20} {p['latency_ms']} ms")
    else:
        lines.append("No open ports discovered in the requested scan range.")

    raw_output = "\n".join(lines)

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": findings,
            "raw_output": raw_output,
            "discovered_ports": open_ports,
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
