#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for GitHub Actions & CI/CD Security Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. ScopeGuard enforcement on unauthorized targets.
  4. Detection of Script Injections, Unpinned Actions, Overprivileged Tokens, and pull_request_target.
"""

import os
import sys
import json
import hashlib
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "github-actions-security", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "github-actions-security"), None)
    assert mod is not None, "github-actions-security not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "github-actions-security-1.0.0.tar.gz"
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
    assert "OWASP CI/CD" in resp["payload"]["details"]["standard"]

def test_workflow_audit_detections():
    vulnerable_workflow = """
name: Insecure CI Pipeline
on:
  pull_request_target:
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet Contributor
        run: echo "${{ github.event.pull_request.title }}"
      - name: Build
        run: |
          echo "Building..."
          curl -H "Authorization: token ghp_111122223333444455556666777788889999" https://internal.corp
"""
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
            "task_id": "test-actions-01",
            "target": "github.com/VoidStudioos/test-repo",
            "scope_approved": True,
            "options": {"workflow_content": vulnerable_workflow}
        }
    }
    stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
    resp = json.loads(stdout.strip())
    p = resp["payload"]
    assert p["success"] is True
    assert p["compliance_score"] < 50, f"Score should be low for vulnerable workflow, got {p['compliance_score']}"

    titles = [f["title"] for f in p["findings"]]
    # Verify all 4 major rules triggered
    assert any("Script Injection" in t for t in titles)
    assert any("Not Pinned" in t for t in titles)
    assert any("Overprivileged Workflow Token" in t for t in titles)
    assert any("pull_request_target" in t for t in titles)
    assert any("Personal Access Token" in t for t in titles)

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
            "task_id": "test-actions-scope",
            "target": "github.com/unauthorized-org/repo",
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
    print("CYBER HASHIRA — GITHUB ACTIONS & CI/CD SECURITY VERIFICATION")
    print("=" * 70)

    tests = [
        ("GitHub-Actions registry & SHA-256 verification", test_registry_and_checksum),
        ("GitHub-Actions worker Health Check", test_worker_health_check),
        ("Wiz Code & OWASP CI/CD vulnerability detections", test_workflow_audit_detections),
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
