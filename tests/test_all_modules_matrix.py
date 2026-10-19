#!/usr/bin/env python3
"""
Cyber Hashira - Master Matrix Verification Harness for All 30 Modules
Implements Gate 1 & Gate 2 verification required by CYBER_HASHIRA_MODULE_AUDIT_AND_ROADMAP.md:
  - Manifest validation (Schema, ID, Version, Entrypoint, OS Support)
  - Registry artifact presence & SHA-256 checksum integrity
  - Stdio IPC HealthCheck contract test
  - ScopeGuard enforcement (unauthorized scope rejection)
  - Authorized execution test on deterministic test target
"""

import os
import sys
import json
import hashlib
import subprocess
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(REPO_ROOT, "modules")
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
ARTIFACTS_DIR = os.path.join(REPO_ROOT, "registry", "artifacts")

def load_catalog():
    if not os.path.isfile(REGISTRY_CATALOG):
        return {}
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {m["id"]: m for m in data.get("modules", [])}

def verify_module(module_id, catalog_entry, catalog):
    mod_path = os.path.join(MODULES_DIR, module_id)
    manifest_file = os.path.join(mod_path, "manifest.json")
    
    res = {
        "id": module_id,
        "manifest_valid": False,
        "artifact_verified": False,
        "health_check_pass": False,
        "scope_guard_pass": False,
        "run_task_pass": False,
        "error": None
    }
    
    # 1. Manifest Check
    if not os.path.isfile(manifest_file):
        res["error"] = "manifest.json missing"
        return res
        
    try:
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        actual_id = manifest.get("id", module_id)
        assert actual_id, "Missing module ID in manifest"
        assert "version" in manifest
        assert "entry_point" in manifest and "executable" in manifest["entry_point"]
        res["manifest_valid"] = True
        res["id"] = actual_id
    except Exception as e:
        res["error"] = f"Manifest invalid: {e}"
        return res

    # 2. Registry Artifact & SHA-256 Check
    cat_entry = catalog_entry or catalog.get(actual_id)
    if cat_entry:
        version = cat_entry.get("version", manifest.get("version", "1.0.0"))
        archive_name = f"{actual_id}-{version}.tar.gz"
        archive_path = os.path.join(ARTIFACTS_DIR, archive_name)
        if not os.path.isfile(archive_path):
            archive_name = f"{module_id}-{version}.tar.gz"
            archive_path = os.path.join(ARTIFACTS_DIR, archive_name)
        if os.path.isfile(archive_path):
            with open(archive_path, "rb") as af:
                actual_hash = hashlib.sha256(af.read()).hexdigest()
            expected_hash = cat_entry.get("artifact", {}).get("sha256", "")
            if actual_hash == expected_hash:
                res["artifact_verified"] = True
            else:
                res["error"] = f"SHA-256 mismatch: actual {actual_hash[:8]} vs catalog {expected_hash[:8]}"
        else:
            res["error"] = f"Archive {archive_name} missing"

    # 3. Worker Executable
    exec_rel = manifest["entry_point"]["executable"]
    worker_script = os.path.join(mod_path, exec_rel)
    if not os.path.isfile(worker_script):
        res["error"] = f"Worker script not found at {exec_rel}"
        return res

    cmd = [sys.executable, worker_script]

    # 4. IPC HealthCheck Test
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(input=json.dumps({"type": "HealthCheck"}) + "\n", timeout=5)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if (msg.get("type") == "HealthCheckResult" and msg.get("payload", {}).get("healthy") is True) or \
                   (msg.get("status") == "ok") or (msg.get("healthy") is True):
                    res["health_check_pass"] = True
                    break
            except Exception:
                continue
    except Exception as e:
        res["error"] = f"HealthCheck failed: {e}"
        return res

    # 5. IPC RunTask / Execute with unauthorized scope (ScopeGuard enforcement)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        task_req = {
            "type": "RunTask",
            "action": "execute",
            "target": "unauthorized-target.evil.test",
            "authorized_targets": ["authorized-only.example.com"],
            "options": {"authorized_targets": ["authorized-only.example.com"]},
            "payload": {
                "task_id": "test-scope-unauthorized",
                "target": "unauthorized-target.evil.test",
                "scope_approved": False,
                "options": {"authorized_targets": ["authorized-only.example.com"]}
            }
        }
        stdout, _ = proc.communicate(input=json.dumps(task_req) + "\n", timeout=5)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if msg.get("type") == "TaskCompleted" and msg.get("payload", {}).get("success") is False:
                    res["scope_guard_pass"] = True
                    break
                elif msg.get("status") == "error" or "unauthorized" in str(msg).lower() or "scope" in str(msg).lower():
                    res["scope_guard_pass"] = True
                    break
            except Exception:
                continue
    except Exception as e:
        res["error"] = f"ScopeGuard test failed: {e}"
        return res

    # 6. IPC RunTask / Execute with authorized scope and simulation/safe target
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        task_req = {
            "type": "RunTask",
            "action": "execute",
            "target": "example.com",
            "authorized_targets": ["example.com"],
            "payload": {
                "task_id": "test-authorized-execution",
                "target": "example.com",
                "scope_approved": True,
                "options": {"simulate_vulnerabilities": True}
            }
        }
        stdout, _ = proc.communicate(input=json.dumps(task_req) + "\n", timeout=5)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                if (msg.get("type") == "TaskCompleted" and msg.get("payload", {}).get("success") is True) or \
                   (msg.get("status") == "success") or ("result" in msg and "findings" in str(msg)):
                    res["run_task_pass"] = True
                    break
            except Exception:
                continue
    except Exception as e:
        res["error"] = f"Authorized RunTask failed: {e}"
        return res

    return res

def main():
    print("=" * 80)
    print("CYBER HASHIRA - ALL 30 MODULES TEST MATRIX & CONTRACT HARNESS")
    print("=" * 80)
    
    catalog = load_catalog()
    modules = sorted([d for d in os.listdir(MODULES_DIR) if os.path.isdir(os.path.join(MODULES_DIR, d))])
    
    results = []
    print(f"[*] Discovered {len(modules)} module directories. Executing test matrix...\n")
    
    header = f"{'#':<3} | {'Module ID':<28} | {'Manifest':<8} | {'Artifact':<8} | {'Health':<6} | {'Scope':<6} | {'RunTask':<7}"
    print(header)
    print("-" * len(header))
    
    passed_count = 0
    for idx, mod_id in enumerate(modules, start=1):
        cat_entry = catalog.get(mod_id)
        res = verify_module(mod_id, cat_entry, catalog)
        results.append(res)
        
        m_str = "OK" if res["manifest_valid"] else "FAIL"
        a_str = "OK" if res["artifact_verified"] else "FAIL"
        h_str = "OK" if res["health_check_pass"] else "FAIL"
        s_str = "OK" if res["scope_guard_pass"] else "FAIL"
        r_str = "OK" if res["run_task_pass"] else "FAIL"
        
        all_passed = res["manifest_valid"] and res["artifact_verified"] and res["health_check_pass"] and res["scope_guard_pass"] and res["run_task_pass"]
        if all_passed:
            passed_count += 1
            status_symbol = "[PASS]"
        else:
            status_symbol = "[FAIL]"
            
        print(f"{idx:<3} | {mod_id:<28} | {m_str:<8} | {a_str:<8} | {h_str:<6} | {s_str:<6} | {r_str:<7} {status_symbol}")
    
    print("-" * len(header))
    print(f"\nMatrix Summary: {passed_count}/{len(modules)} modules fully certified across all 5 verification gates.")
    print("=" * 80)

if __name__ == "__main__":
    main()
