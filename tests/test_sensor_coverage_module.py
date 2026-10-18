#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for MITRE Sensor Coverage Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. ScopeGuard enforcement on unauthorized targets.
  4. Detection blind spot identification against ATT&CK data sources.
"""

import os
import sys
import json
import hashlib
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "sensor-coverage-attack", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "sensor-coverage-attack"), None)
    assert mod is not None, "sensor-coverage-attack not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "sensor-coverage-attack-1.0.0.tar.gz"
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
    assert "Center for Threat-Informed Defense" in resp["payload"]["details"]["framework"]

def test_sensor_coverage_evaluation():
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
            "task_id": "test-sensor-01",
            "target": "SOC-SIEM-Stack",
            "scope_approved": True,
            "options": {"active_sensors": ["sysmon"]}
        }
    }
    stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    p = resp["payload"]
    assert p["success"] is True
    assert p["detection_coverage_score"] < 100
    assert len(p["blind_spots"]) >= 1

    titles = [f["title"] for f in p["findings"]]
    # Blind spot for missing network/web sensors (e.g. Zeek, Suricata)
    assert any("Detection Blind Spot" in t for t in titles)

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
            "task_id": "test-sensor-scope",
            "target": "unauthorized-soc-cluster",
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
    print("CYBER HASHIRA — MITRE SENSOR COVERAGE AUDITOR VERIFICATION")
    print("=" * 70)

    tests = [
        ("Sensor-Coverage registry & SHA-256 verification", test_registry_and_checksum),
        ("Sensor-Coverage worker Health Check", test_worker_health_check),
        ("MITRE SMAP sensor gap & blind spot evaluation", test_sensor_coverage_evaluation),
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
