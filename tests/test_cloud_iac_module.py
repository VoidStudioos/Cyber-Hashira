#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Cloud IaC Security Auditor Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. CIS AWS & Kubernetes benchmark misconfiguration detection (Public S3, Open Ingress SSH, Privileged Pod).
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
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "cloud-iac-security", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "cloud-iac-security"), None)
    assert mod is not None, "cloud-iac-security not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "cloud-iac-security-1.0.0.tar.gz"
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
    assert resp.get("module") == "cloud-iac-security"

def test_iac_misconfigurations():
    proc = subprocess.Popen(
        [sys.executable, WORKER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    req = {
        "type": "Execute",
        "template_type": "terraform",
        "content": (
            "resource \"aws_s3_bucket\" \"leak\" {\n"
            "  acl = \"public-read\"\n"
            "}\n"
            "resource \"aws_security_group\" \"sg\" {\n"
            "  ingress {\n"
            "    from_port = 22\n"
            "    to_port = 22\n"
            "    cidr_blocks = [\"0.0.0.0/0\"]\n"
            "  }\n"
            "}\n"
        )
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "success", f"Execution failed: {resp}"
    res = resp["result"]
    assert res["compliance_score"] < 60
    assert "S3_PUBLIC_ACL" in res["misconfigurations"]
    assert "SG_OPEN_ADMIN_PORT" in res["misconfigurations"]

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
        "target": "/unauthorized/infra/main.tf",
        "options": {
            "authorized_targets": ["/home/user/authorized/infra"]
        }
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "error", "ScopeGuard failed to reject unauthorized target!"
    assert resp.get("code") == "SCOPE_VIOLATION"

def main():
    print("=" * 70)
    print("CYBER HASHIRA \u2014 CLOUD IAC SECURITY AUDITOR VERIFICATION")
    print("=" * 70)

    tests = [
        ("Cloud-IaC registry & SHA-256 verification", test_registry_and_checksum),
        ("Cloud-IaC worker Health Check", test_worker_health_check),
        ("CIS Benchmark Terraform misconfiguration audit", test_iac_misconfigurations),
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
