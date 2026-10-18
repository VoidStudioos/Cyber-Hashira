#!/usr/bin/env python3
"""
Cyber Hashira - Automated Verification Suite for Digital Forensics & Malware Triage Module
Tests:
  1. Registry catalog & SHA-256 package artifact verification.
  2. Worker Health Check execution.
  3. Cryptographic hash calculation (MD5, SHA-1, SHA-256).
  4. Shannon entropy calculation & packed binary detection (threshold > 7.0).
  5. Suspicious string extraction (Win32 process injection APIs).
  6. Chain-of-custody immutable record generation.
  7. ScopeGuard enforcement on unapproved targets.
"""

import os
import sys
import json
import hashlib
import subprocess
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")
WORKER_SCRIPT = os.path.join(REPO_ROOT, "modules", "forensics", "worker.py")

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

    mod = next((m for m in catalog["modules"] if m["id"] == "digital-forensics"), None)
    assert mod is not None, "digital-forensics not found in registry catalog"
    assert mod["version"] == "1.0.0", f"Expected version 1.0.0, got {mod['version']}"

    archive_name = "digital-forensics-1.0.0.tar.gz"
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
    assert "Shannon-Entropy" in resp["payload"]["details"]["algorithms"]

def test_cryptographic_hashes_and_strings():
    # Create a temporary file with known content and suspicious strings
    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
        sample_data = b"Cyber Hashira Forensic Sample\nVirtualAlloc\nCreateRemoteThread\nWriteProcessMemory\nhttps://evil-c2.net/payload.bin\n"
        tmp.write(sample_data)
        tmp_path = tmp.name

    try:
        expected_sha256 = hashlib.sha256(sample_data).hexdigest()
        expected_md5 = hashlib.md5(sample_data).hexdigest()

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
                "task_id": "test-forensics-01",
                "target": tmp_path,
                "scope_approved": True,
                "options": {"file_path": tmp_path}
            }
        }
        stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
        resp = json.loads(stdout.strip())
        assert resp["type"] == "TaskCompleted"
        p = resp["payload"]
        assert p["success"] is True
        assert p["hashes"]["sha256"] == expected_sha256
        assert p["hashes"]["md5"] == expected_md5
        assert p["chain_of_custody"]["custody_id"] is not None
        assert p["chain_of_custody"]["integrity_verified"] is True

        # Check suspicious strings detection
        categories = [ind["category"] for ind in p["suspicious_indicators"]]
        assert "Potential Process Injection Win32 API" in categories
        assert "URL / Remote Endpoint Reference" in categories
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

def test_packed_entropy_detection():
    # Generate high entropy random bytes (> 7.5 bits/byte)
    import os as _os
    random_bytes = _os.urandom(4096)

    with tempfile.NamedTemporaryFile("wb", delete=False) as tmp:
        tmp.write(random_bytes)
        tmp_path = tmp.name

    try:
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
                "task_id": "test-forensics-entropy",
                "target": tmp_path,
                "scope_approved": True,
                "options": {"file_path": tmp_path, "entropy_threshold": 7.0}
            }
        }
        stdout, _ = proc.communicate(input=json.dumps(req) + "\n", timeout=5)
        resp = json.loads(stdout.strip())
        p = resp["payload"]
        assert p["success"] is True
        assert p["entropy"] >= 7.0
        assert p["is_packed"] is True
        assert any("High Entropy" in f["title"] for f in p["findings"])
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

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
            "task_id": "test-forensics-scope",
            "target": "C:/Windows/System32/calc.exe",
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
    print("CYBER HASHIRA — DIGITAL FORENSICS & MALWARE TRIAGE VERIFICATION")
    print("=" * 70)

    tests = [
        ("Digital-Forensics registry & SHA-256 verification", test_registry_and_checksum),
        ("Digital-Forensics worker Health Check", test_worker_health_check),
        ("Cryptographic hash verification & suspicious string extraction", test_cryptographic_hashes_and_strings),
        ("High Shannon entropy calculation & packed malware detection", test_packed_entropy_detection),
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
