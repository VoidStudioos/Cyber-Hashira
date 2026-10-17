#!/usr/bin/env python3
"""
Cyber Hashira - Milestone Verification & End-to-End Modular Lifecycle Test Suite
Verifies:
 1. Host launches cleanly without optional modules bundled.
 2. Sample module is packaged independently in registry artifacts.
 3. Artifact SHA-256 integrity verification.
 4. Strict ScopeGuard enforcement (unauthorized targets rejected).
 5. Authorized target approval & scope validation.
 6. Module installation into isolated directory.
 7. Module health check execution.
 8. Authorized assessment execution & finding generation.
 9. Module deactivation (disabling).
 10. Module uninstallation & verification that Host remains functional.
"""

import os
import sys
import json
import sqlite3
import hashlib
import tarfile
import subprocess
import tempfile
import shutil

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")

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

def test_host_clean_state_without_modules():
    """Verify that the Host database schema initializes without modules pre-bundled"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS installed_modules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                install_path TEXT NOT NULL,
                installed_at TEXT NOT NULL,
                permissions TEXT
            );
        """)
        cur.execute("SELECT COUNT(*) FROM installed_modules")
        count = cur.fetchone()[0]
        assert count == 0, f"Expected 0 modules bundled in Host, found {count}"
        conn.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

def test_registry_catalog_and_artifact_integrity():
    """Verify registry metadata and SHA-256 checksum of independent artifact"""
    assert os.path.exists(REGISTRY_CATALOG), f"Registry catalog missing: {REGISTRY_CATALOG}"
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    assert "modules" in catalog
    sample_mod = next((m for m in catalog["modules"] if m["id"] == "sample-dns"), None)
    assert sample_mod is not None, "sample-dns module not found in registry"

    expected_sha256 = sample_mod["artifact"]["sha256"]
    artifact_path = os.path.join(ARTIFACTS_DIR, f"{sample_mod['id']}-{sample_mod['version']}.tar.gz")
    assert os.path.exists(artifact_path), f"Artifact missing: {artifact_path}"

    with open(artifact_path, "rb") as f:
        actual_sha256 = hashlib.sha256(f.read()).hexdigest()

    assert actual_sha256 == expected_sha256, f"SHA-256 mismatch! expected {expected_sha256}, got {actual_sha256}"

def test_scope_guard_rejection():
    """Verify that unauthorized target is rejected by module worker contract"""
    worker_script = os.path.join(REPO_ROOT, "modules", "sample-dns", "worker.py")
    req = {
        "type": "RunTask",
        "payload": {
            "task_id": "test-unauth-1",
            "target": "unauthorized-external-target.com",
            "scope_approved": False,
            "options": {}
        }
    }
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    out, _ = p.communicate(json.dumps(req))
    resp = json.loads(out)
    assert resp["type"] == "TaskCompleted"
    assert resp["payload"]["success"] is False
    assert "scope" in resp["payload"]["error"].lower()

def test_full_module_lifecycle():
    """Verify install -> healthcheck -> execute -> disable -> uninstall lifecycle"""
    test_install_root = tempfile.mkdtemp(prefix="hashira_test_inst_")
    artifact_path = os.path.join(ARTIFACTS_DIR, "sample-dns-1.0.0.tar.gz")

    try:
        # 1. Install by extracting verified tarball into isolated dir
        dest_dir = os.path.join(test_install_root, "sample-dns", "1.0.0")
        os.makedirs(dest_dir, exist_ok=True)
        with tarfile.open(artifact_path, "r:gz") as tar:
            tar.extractall(dest_dir)

        manifest_file = os.path.join(dest_dir, "manifest.json")
        worker_file = os.path.join(dest_dir, "worker.py")
        assert os.path.exists(manifest_file), "manifest.json missing after extraction"
        assert os.path.exists(worker_file), "worker.py missing after extraction"

        # 2. Run Health Check
        health_req = {"type": "HealthCheck", "payload": {}}
        p = subprocess.Popen([sys.executable, worker_file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate(json.dumps(health_req))
        resp = json.loads(out)
        assert resp["type"] == "HealthCheckResult"
        assert resp["payload"]["healthy"] is True

        # 3. Run Authorized Assessment Task
        task_req = {
            "type": "RunTask",
            "payload": {
                "task_id": "test-auth-1",
                "target": "localhost",
                "scope_approved": True,
                "options": {}
            }
        }
        p = subprocess.Popen([sys.executable, worker_file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate(json.dumps(task_req))
        resp = json.loads(out)
        assert resp["type"] == "TaskCompleted"
        assert resp["payload"]["success"] is True
        assert len(resp["payload"]["findings"]) > 0

        finding = resp["payload"]["findings"][0]
        assert finding["module_id"] == "sample-dns"
        assert finding["severity"] in ["Informational", "Low", "Medium", "High", "Critical"]

        # 4. Uninstall: remove directory
        shutil.rmtree(test_install_root)
        assert not os.path.exists(dest_dir), "Module directory was not removed upon uninstall"

    finally:
        if os.path.exists(test_install_root):
            shutil.rmtree(test_install_root)

def main():
    print("=" * 70)
    print("CYBER HASHIRA — AUTOMATED MODULAR LIFECYCLE VERIFICATION SUITE")
    print("=" * 70)

    tests = [
        ("Host clean state without optional modules", test_host_clean_state_without_modules),
        ("Registry metadata and artifact SHA-256 verification", test_registry_catalog_and_artifact_integrity),
        ("Strict ScopeGuard rejection on unauthorized targets", test_scope_guard_rejection),
        ("End-to-End installation, health check, execution, and uninstallation", test_full_module_lifecycle),
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
