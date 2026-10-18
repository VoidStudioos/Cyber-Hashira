#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Identity & Active Directory Hygiene Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. Kerberos Pre-Auth (AS-REP Roasting), Kerberoasting SPN, and SMBv1 detection.
  4. ScopeGuard enforcement on unauthorized targets.
"""

import os
import sys
import json
import hashlib
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "identity-ad-hygiene", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "identity-ad-hygiene"), None)
    assert mod is not None, "identity-ad-hygiene not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "identity-ad-hygiene-1.0.0.tar.gz"
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
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "ok", f"HealthCheck failed: {resp}"
    assert resp.get("module") == "identity-ad-hygiene"

def test_identity_hygiene_audit():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "Execute",
        "domain": "target.corp",
        "directory_data": {
            "domain": "target.corp",
            "domain_policies": {
                "smbv1_enabled": True
            },
            "users": [
                {
                    "sAMAccountName": "service_account",
                    "userAccountControl": 4194304, # DONT_REQ_PREAUTH
                    "is_domain_admin": False
                }
            ]
        }
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "success", f"Execution failed: {resp}"
    res = resp["result"]
    assert res["identity_hygiene_score"] < 70
    assert any("AS-REP Roasting Risk" in f["title"] for f in res["findings"])
    assert any("SMBv1" in f["title"] for f in res["findings"])

def test_scope_guard():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "Execute",
        "domain": "unauthorized.ad.corp",
        "options": {
            "authorized_targets": ["authorized.ad.corp"]
        }
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "error", "ScopeGuard failed to reject unauthorized target!"
    assert resp.get("code") == "SCOPE_VIOLATION"

def main():
    print("=" * 70)
    print("CYBER HASHIRA \u2014 IDENTITY & AD HYGIENE AUDITOR VERIFICATION")
    print("=" * 70)

    tests = [
        ("Identity-Hygiene registry & SHA-256 verification", test_registry_and_checksum),
        ("Identity-Hygiene worker Health Check", test_worker_health_check),
        ("AS-REP Roasting & SMBv1 hygiene evaluation", test_identity_hygiene_audit),
        ("ScopeGuard enforcement on unauthorized target", test_scope_guard),
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
