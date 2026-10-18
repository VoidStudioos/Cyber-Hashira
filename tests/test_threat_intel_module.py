#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Threat Intelligence Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. IOC Enrichment for malicious hash (Cobalt Strike / LockBit match).
  4. IOC Enrichment for domain reputation & MITRE ATT&CK mapping.
  5. ScopeGuard enforcement (unapproved targets rejected).
"""

import os
import sys
import json
import hashlib
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "threat-intelligence", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "threat-intelligence"), None)
    assert mod is not None, "threat-intelligence not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "threat-intelligence-1.0.0.tar.gz"
    archive_path = os.path.join(ARTIFACTS_DIR, archive_name)
    assert os.path.isfile(archive_path), f"Archive not found: {archive_path}"

    with open(archive_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    assert actual_hash == mod["artifact"]["sha256"], (
        f"Checksum mismatch! Catalog: {mod['artifact']['sha256']}, Actual: {actual_hash}"
    )

def test_worker_health_check():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {"type": "HealthCheck"}
    stdout, stderr = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    assert proc.returncode == 0, f"Worker exited with code {proc.returncode}: {stderr}"

    resp = json.loads(stdout.strip())
    assert resp["type"] == "HealthCheckResult"
    assert resp["payload"]["healthy"] is True
    assert "Enterprise ATT&CK" in resp["payload"]["details"]["mitre_framework"]

def test_malicious_hash_enrichment():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Known Cobalt Strike hash from worker database
    test_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "test-intel-01",
            "target": test_hash,
            "scope_approved": True,
            "options": {"ioc": test_hash}
        }
    }
    stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp["type"] == "TaskCompleted"
    p = resp["payload"]
    assert p["success"] is True
    assert p["threat_score"] >= 90
    assert "Cobalt Strike" in p["reputation"]
    assert len(p["findings"]) >= 1
    assert p["findings"][0]["severity"] == "Critical"

def test_domain_reputation_and_mitre():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "test-intel-02",
            "target": "suspicious-phish.top",
            "scope_approved": True,
            "options": {"ioc": "suspicious-phish.top"}
        }
    }
    stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    p = resp["payload"]
    assert p["success"] is True
    assert p["threat_score"] >= 60
    assert any(t["id"] == "T1566" for t in p["mitre_techniques"])

def test_scope_guard_rejection():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "test-intel-scope",
            "target": "unauthorized-target.org",
            "scope_approved": False,
            "options": {}
        }
    }
    stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    p = resp["payload"]
    assert p["success"] is False
    assert "ScopeGuard" in p["error"]

def main():
    print("=" * 70)
    print("CYBER HASHIRA — THREAT INTELLIGENCE VERIFICATION SUITE")
    print("=" * 70)

    tests = [
        ("Threat-Intelligence registry & SHA-256 verification", test_registry_and_checksum),
        ("Threat-Intelligence worker Health Check", test_worker_health_check),
        ("Known malicious hash detection & score triage", test_malicious_hash_enrichment),
        ("Domain reputation assessment & MITRE ATT&CK mapping", test_domain_reputation_and_mitre),
        ("ScopeGuard enforcement on unauthorized target", test_scope_guard_rejection),
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
