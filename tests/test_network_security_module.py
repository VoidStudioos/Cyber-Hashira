#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Network Security Module (Phase 4)
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. ScopeGuard rejection for unauthorized network targets.
  3. Worker Health Check execution.
  4. Port discovery execution & finding generation against local listening TCP socket.
"""

import os
import sys
import json
import hashlib
import subprocess
import threading
import socket
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "network-security", "worker.py")

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
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    mod = next((m for m in catalog["modules"] if m["id"] == "network-security"), None)
    assert mod is not None, "network-security not found in registry catalog"

    expected_sha256 = mod["artifact"]["sha256"]
    tar_path = os.path.join(ARTIFACTS_DIR, f"{mod['id']}-{mod['version']}.tar.gz")
    assert os.path.exists(tar_path), f"Tarball missing: {tar_path}"

    with open(tar_path, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()

    assert actual_sha256 == expected_sha256, f"Checksum mismatch: expected {expected_sha256}, got {actual_sha256}"

def test_health_check():
    req = {"type": "HealthCheck", "payload": {}}
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "HealthCheckResult"
    assert resp["payload"]["healthy"] is True

def test_scope_guard_blocking():
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "scope-test-net-1",
            "target": "10.99.99.99",
            "scope_approved": False,
            "options": {}
        }
    }
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "TaskCompleted"
    assert resp["payload"]["success"] is False
    assert "scope" in resp["payload"]["error"].lower()

def test_port_discovery():
    # Start a dummy TCP server on port 9777
    test_port = 9777
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", test_port))
    server_sock.listen(5)

    def serve():
        try:
            while True:
                client, _ = server_sock.accept()
                client.sendall(b"SSH-2.0-OpenSSH_8.9\r\n")
                client.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    time.sleep(0.1)

    try:
        req = {
            "type": "RunTask",
            "payload": {
                "task_id": "scan-test-1",
                "target": "127.0.0.1",
                "scope_approved": True,
                "options": {
                    "port_profile": "custom",
                    "custom_ports": f"{test_port},9998"
                }
            }
        }
        p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate(json.dumps(req))
        resp = json.loads(out)

        assert resp["type"] == "TaskCompleted"
        assert resp["payload"]["success"] is True
        open_ports = resp["payload"]["discovered_ports"]
        assert any(p["port"] == test_port for p in open_ports), f"Port {test_port} was not discovered as open"
        assert len(resp["payload"]["findings"]) > 0
    finally:
        server_sock.close()

def main():
    print("=" * 70)
    print("CYBER HASHIRA — NETWORK SECURITY MODULE VERIFICATION SUITE")
    print("=" * 70)

    tests = [
        ("Network-Security registry & SHA-256 verification", test_registry_and_checksum),
        ("Network-Security worker Health Check", test_health_check),
        ("ScopeGuard enforcement on unauthorized targets", test_scope_guard_blocking),
        ("Port discovery & finding generation on authorized target", test_port_discovery),
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
