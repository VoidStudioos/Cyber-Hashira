#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Subdomain Takeover Auditor Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. GitHub Pages & AWS S3 dangling CNAME takeover detection.
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
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "subdomain-takeover-audit", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "subdomain-takeover-audit"), None)
    assert mod is not None, "subdomain-takeover-audit not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "subdomain-takeover-audit-1.0.0.tar.gz"
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
    assert resp.get("module") == "subdomain-takeover-audit"

def test_takeover_detection():
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
        "cname_records": [
            {
                "subdomain": "community.target.corp",
                "cname": "target-community.github.io",
                "response_body": "404 Not Found - There isn't a GitHub Pages site here."
            },
            {
                "subdomain": "static.target.corp",
                "cname": "target-static.s3.amazonaws.com",
                "response_body": "<Error><Code>NoSuchBucket</Code></Error>"
            }
        ]
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "success", f"Execution failed: {resp}"
    res = resp["result"]
    assert res["takeover_risk_detected"] is True
    assert res["dangling_count"] == 2
    assert any("GitHub Pages" in f["service"] for f in res["dangling_subdomains"])
    assert any("AWS S3" in f["service"] for f in res["dangling_subdomains"])

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
        "domain": "unauthorized-domain.com",
        "options": {
            "authorized_targets": ["authorized-domain.com"]
        }
    }
    stdout, _ = proc.communicate(json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    assert resp.get("status") == "error", "ScopeGuard failed to reject unauthorized target!"
    assert resp.get("code") == "SCOPE_VIOLATION"

def main():
    print("=" * 70)
    print("CYBER HASHIRA \u2014 SUBDOMAIN TAKEOVER AUDITOR VERIFICATION")
    print("=" * 70)

    tests = [
        ("Subdomain-Takeover registry & SHA-256 verification", test_registry_and_checksum),
        ("Subdomain-Takeover worker Health Check", test_worker_health_check),
        ("GitHub Pages & S3 dangling CNAME detection", test_takeover_detection),
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
