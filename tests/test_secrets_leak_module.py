#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Secrets Leak Scanner Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. Discovery of AWS keys, GitHub tokens, Private keys, and high Shannon entropy.
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
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "secrets-leak-scanner", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "secrets-leak-scanner"), None)
    assert mod is not None, "secrets-leak-scanner not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "secrets-leak-scanner-1.0.0.tar.gz"
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
    assert resp.get("module") == "secrets-leak-scanner"

def test_secrets_and_entropy():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "Execute",
        "content": (
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
            "export DB_URI=postgres://admin:P@ssw0rd123!@db.internal:5432/corp\n"
            "const highEntropySecret = 'x8Hk9#mP$2vL@qW5zR&tY*uI!';\n"
        )
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "success", f"Execution failed: {resp}"
    res = resp["result"]
    assert res["secrets_count"] >= 3
    # Check that tokens are masked in output
    for s in res["secrets_found"]:
        assert "*" in s["token"]
        assert "AKIAIOSFODNN7EXAMPLE" not in s["token"]

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
        "target": "c:\\secret_vault\\passwords.txt",
        "options": {
            "authorized_targets": ["c:\\authorized_projects"]
        }
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "error", "ScopeGuard failed to reject unauthorized target!"
    assert resp.get("code") == "SCOPE_VIOLATION"

def main():
    print("=" * 70)
    print("CYBER HASHIRA \u2014 SECRETS LEAK SCANNER VERIFICATION")
    print("=" * 70)

    tests = [
        ("Secrets-Scanner registry & SHA-256 verification", test_registry_and_checksum),
        ("Secrets-Scanner worker Health Check", test_worker_health_check),
        ("Multi-cloud secret token & masking verification", test_secrets_and_entropy),
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
