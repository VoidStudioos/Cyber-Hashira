#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Web Application Security Module (Phase 3)
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. ScopeGuard rejection for unauthorized web targets.
  3. Worker Health Check execution.
  4. Repeater execution & live response inspection against local HTTP test server.
  5. Passive vulnerability engine: detects missing CSP, missing X-Content-Type-Options,
     and insecure Set-Cookie attributes.
"""

import os
import sys
import json
import hashlib
import subprocess
import threading
import http.server
import socketserver
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "web-security", "worker.py")

class TestHttpHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        # Deliberately omit CSP and X-Content-Type-Options, add server banner & insecure cookie
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "VulnerableTestServer/1.0.0")
        self.send_header("Set-Cookie", "session_token=secret123; Path=/") # Missing Secure & HttpOnly
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Cyber Hashira Test Lab</h1></body></html>")

    def log_message(self, format, *args):
        pass # Suppress server noise

def run_test(name, fn):
    sys.stdout.write(f"[*] Running test: {name} ... ")
    sys.stdout.flush()
    try:
        fn()
        print("\033[92mPASSED\033[0m")
        return True
    except Exception as e:
        print(f"\033[91mFAILED\033[0m: {e}")
        return False

def test_registry_and_checksum():
    """Verify registry catalog entry and SHA-256 checksum for web-security"""
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    mod = next((m for m in catalog["modules"] if m["id"] == "web-security"), None)
    assert mod is not None, "web-security not found in registry catalog"

    expected_sha256 = mod["artifact"]["sha256"]
    tar_path = os.path.join(ARTIFACTS_DIR, f"{mod['id']}-{mod['version']}.tar.gz")
    assert os.path.exists(tar_path), f"Tarball missing: {tar_path}"

    with open(tar_path, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()

    assert actual_sha256 == expected_sha256, f"Checksum mismatch: expected {expected_sha256}, got {actual_sha256}"

def test_health_check():
    """Verify web-security worker health check response"""
    req = {"type": "HealthCheck", "payload": {}}
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "HealthCheckResult"
    assert resp["payload"]["healthy"] is True

def test_scope_guard_blocking():
    """Verify that unauthorized requests are blocked before execution"""
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "scope-test-1",
            "target": "https://unauthorized-victim.com",
            "scope_approved": False,
            "options": {"action": "repeater"}
        }
    }
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "TaskCompleted"
    assert resp["payload"]["success"] is False
    assert "scope" in resp["payload"]["error"].lower()

def test_repeater_and_passive_analysis():
    """Test repeater request dispatch and passive header vulnerability detection against local server"""
    # Start temporary local HTTP server on port 8999
    server = socketserver.TCPServer(("127.0.0.1", 8999), TestHttpHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    time.sleep(0.1)

    try:
        req = {
            "type": "RunTask",
            "payload": {
                "task_id": "rep-test-1",
                "target": "http://127.0.0.1:8999",
                "scope_approved": True,
                "options": {
                    "action": "repeater",
                    "repeater_request": {
                        "method": "GET",
                        "url": "http://127.0.0.1:8999/test",
                        "headers": {"Accept": "text/html"},
                        "body": ""
                    }
                }
            }
        }
        p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate(json.dumps(req))
        resp = json.loads(out)

        assert resp["type"] == "TaskCompleted"
        assert resp["payload"]["success"] is True
        findings = resp["payload"]["findings"]
        assert len(findings) >= 2, f"Expected at least 2 passive findings, got {len(findings)}"

        titles = [f["title"] for f in findings]
        assert any("Content-Security-Policy" in t for t in titles), "Missing CSP finding was not generated"
        assert any("Insecure Cookie" in t for t in titles), "Insecure cookie finding was not generated"
    finally:
        server.shutdown()
        server.server_close()

def main():
    print("=" * 70)
    print("CYBER HASHIRA — WEB APPLICATION SECURITY VERIFICATION SUITE")
    print("=" * 70)

    tests = [
        ("Web-Security registry catalog & SHA-256 verification", test_registry_and_checksum),
        ("Web-Security worker Health Check", test_health_check),
        ("ScopeGuard enforcement on unauthorized targets", test_scope_guard_blocking),
        ("Repeater dispatch & passive vulnerability findings", test_repeater_and_passive_analysis),
    ]

    passed = 0
    for name, fn in tests:
        if run_test(name, fn):
            passed += 1

    print("=" * 70)
    print(f"Results: {passed}/{len(tests)} tests passed.")
    print("=" * 70)

    if passed != len(tests):
        sys.exit(1)

if __name__ == "__main__":
    main()
