#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Hashira AI Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. Secret and credential redaction engine.
  4. Vulnerability remediation patch generation (English).
  5. Bilingual security triage generation (Persian / فارسی).
"""

import os
import sys
import json
import hashlib
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "hashira-ai", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "hashira-ai"), None)
    assert mod is not None, "hashira-ai not found in registry catalog"

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

def test_secret_redaction():
    # Import redact_sensitive_data directly from worker
    sys.path.insert(0, os.path.join(REPO_ROOT, "modules", "hashira-ai"))
    import worker
    sensitive_input = "Database config: password=SuperSecretPassword123 and api_key=sk-proj-999888777666"
    sanitized = worker.redact_sensitive_data(sensitive_input)
    assert "SuperSecretPassword123" not in sanitized, "Password was not redacted"
    assert "sk-proj" not in sanitized, "API key was not redacted"
    assert "[REDACTED_PASSWORD]" in sanitized
    assert "[REDACTED_KEY]" in sanitized

def test_remediation_generation_en():
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "ai-test-en-1",
            "target": "example.com",
            "options": {
                "action": "explain",
                "language": "en",
                "finding": {
                    "title": "Missing Content-Security-Policy (CSP)",
                    "description": "CSP header is not present on response.",
                    "severity": "Medium",
                    "cwe": "CWE-1021"
                }
            }
        }
    }
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "TaskCompleted"
    assert resp["payload"]["success"] is True
    assert "Content-Security-Policy" in resp["payload"]["remediation_patch"]

def test_triage_generation_fa():
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "ai-test-fa-1",
            "target": "example.com",
            "options": {
                "action": "triage",
                "language": "fa",
                "findings_list": [
                    {"title": "Exposed Environment File", "severity": "Critical"},
                    {"title": "Missing CSP", "severity": "Medium"}
                ]
            }
        }
    }
    p = subprocess.Popen([sys.executable, WORKER_SCRIPT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "TaskCompleted"
    assert resp["payload"]["success"] is True
    assert "تریاژ" in resp["payload"]["response"]
    assert "بحرانی" in resp["payload"]["response"]

def main():
    print("=" * 70)
    print("CYBER HASHIRA — HASHIRA AI ASSISTANT VERIFICATION SUITE")
    print("=" * 70)

    tests = [
        ("Hashira-AI registry & SHA-256 verification", test_registry_and_checksum),
        ("Hashira-AI worker Health Check", test_health_check),
        ("Sensitive credential & secret redaction engine", test_secret_redaction),
        ("Vulnerability explanation & remediation patch generation (EN)", test_remediation_generation_en),
        ("Bilingual security triage & report generation (FA)", test_triage_generation_fa),
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
