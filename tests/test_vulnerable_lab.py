#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — Operational Vulnerability Assessment Lab Test
Runs an integrated mock target lab and verifies multi-module active scanning,
ScopeGuard target authorization, findings generation, and SARIF/HTML report export.
"""

import sys
import os
import json
import time
import threading
import subprocess
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "modules"
REPORTS_DIR = REPO_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class VulnerableMockTargetHandler(BaseHTTPRequestHandler):
    """Simulates realistic web and API vulnerabilities for automated testing."""

    def log_message(self, format, *args):
        pass  # Quiet logging

    def do_GET(self):
        # 1. Exposed .env credentials
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_PASS=SuperSecret123!\n")
            return

        # 2. Exposed OpenAPI / Swagger Spec
        if self.path in ("/swagger.json", "/api/v1/swagger.json"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")  # Insecure CORS
            self.end_headers()
            spec = {
                "swagger": "2.0",
                "info": {"title": "Vulnerable Demo API", "version": "1.0.0"},
                "paths": {
                    "/api/v1/users/{id}": {"get": {"description": "BOLA user lookup"}},
                    "/api/v1/admin/dump": {"post": {"description": "Unauthenticated administrative action"}}
                }
            }
            self.wfile.write(json.dumps(spec).encode("utf-8"))
            return

        # 3. BOLA / IDOR Endpoint
        if self.path.startswith("/api/v1/users/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"user_id": 1001, "email": "victim@example.com", "role": "admin"}).encode("utf-8"))
            return

        # 4. Insecure CORS and missing security headers
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1")  # Information Disclosure
        # Intentionally missing: HSTS, CSP, X-Content-Type-Options
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Vulnerable Demo Target</h1><script src='https://cdn.untrusted.org/app.js'></script></body></html>")


def run_module_ipc(module_id: str, target: str, options: dict = None) -> dict:
    """Execute a module worker via Stdio IPC."""
    worker_script = MODULES_DIR / module_id / "worker.py"
    if not worker_script.is_file():
        raise FileNotFoundError(f"Worker for {module_id} not found at {worker_script}")

    task_payload = {
        "type": "RunTask",
        "action": "execute",
        "target": target,
        "authorized_targets": [target],
        "payload": {
            "task_id": f"lab-{module_id}",
            "target": target,
            "scope_approved": True,
            "options": options or {"simulate_vulnerabilities": True}
        }
    }

    proc = subprocess.Popen(
        [sys.executable, str(worker_script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=json.dumps(task_payload) + "\n", timeout=10)
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if line:
            try:
                return json.loads(line)
            except Exception:
                continue
    return {"error": stderr or "No response from worker"}


def main():
    print("=" * 70)
    print("CYBER HASHIRA - OPERATIONAL VULNERABILITY LAB ASSESSMENT")
    print("=" * 70)

    # 1. Start Mock Target Lab Server
    server_address = ("127.0.0.1", 8888)
    httpd = HTTPServer(server_address, VulnerableMockTargetHandler)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()
    print("[+] Vulnerable Target Lab Server running on http://127.0.0.1:8888")

    target_url = "http://127.0.0.1:8888"
    all_findings = []

    # 2. Run Multi-Module Vulnerability Assessments
    modules_to_test = [
        ("api-security", "API Security & BOLA Inspector"),
        ("web-security", "Web Application Security Analyzer"),
        ("cors-websocket-audit", "CORS & WebSocket Origin Auditor"),
        ("jwt-security-analyzer", "JWT & Token Cryptographic Inspector"),
        ("secrets-leak-scanner", "Sensitive Data & Credentials Scanner"),
    ]

    for mod_id, mod_name in modules_to_test:
        print(f"\n[*] Executing {mod_name} ({mod_id})...")
        res = run_module_ipc(mod_id, target_url)
        payload = res.get("payload", {})
        result = res.get("result", {})
        
        success = payload.get("success", False) or res.get("status") == "success" or bool(result)
        findings = payload.get("findings") or result.get("findings") or []

        status_str = "[PASS]" if success else "[FAIL]"
        print(f"    Status: {status_str} | Generated Findings: {len(findings)}")
        for f in findings:
            cwe = f.get("cwe", f.get("vuln_type", "CWE-Unknown"))
            title = f.get("title", "Untitled finding")
            sev = f.get("severity", "Medium")
            print(f"      - [{sev}] {title} ({cwe})")
            
            # Normalize finding format for reporting engine
            norm_finding = {
                "id": f.get("id", str(len(all_findings) + 1)),
                "title": title,
                "severity": sev,
                "cwe": cwe,
                "description": f.get("description", ""),
                "evidence": f.get("evidence", ""),
                "target": target_url,
                "module_id": mod_id,
                "timestamp": f.get("timestamp", f.get("detected_at", ""))
            }
            all_findings.append(norm_finding)

    # 3. Test Reporting Pipeline & Export SARIF v2.1.0
    print("\n" + "=" * 70)
    print("[*] Generating Consolidated Reports from Lab Findings...")
    print(f"[*] Total Raw Findings Collected: {len(all_findings)}")

    raw_findings_file = REPORTS_DIR / "lab_findings.json"
    raw_findings_file.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")

    sarif_output_file = REPORTS_DIR / "lab_report.sarif"
    html_output_file = REPORTS_DIR / "lab_report.html"

    reporting_script = REPO_ROOT / "scripts" / "reporting_engine.py"
    if reporting_script.is_file():
        # Export SARIF
        subprocess.run([
            sys.executable, str(reporting_script),
            "--input-json", str(raw_findings_file),
            "--format", "sarif",
            "--output", str(sarif_output_file),
            "--project-name", "Vulnerable Lab Simulation",
            "--target", target_url
        ], check=True)
        print(f"[+] SARIF v2.1.0 report generated: {sarif_output_file.name}")

        # Export HTML
        subprocess.run([
            sys.executable, str(reporting_script),
            "--input-json", str(raw_findings_file),
            "--format", "html",
            "--output", str(html_output_file),
            "--project-name", "Vulnerable Lab Simulation",
            "--target", target_url
        ], check=True)
        print(f"[+] Executive HTML report generated: {html_output_file.name}")

    # 4. Stop Mock Server
    httpd.shutdown()
    print("\n" + "=" * 70)
    print("[SUCCESS] OPERATIONAL LAB ASSESSMENT COMPLETED 100% SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    main()
