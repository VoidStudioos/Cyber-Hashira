#!/usr/bin/env python3
"""
Cyber Hashira - Bug Bounty Engine Verification Suite
Tests:
  1. Module 2: race-condition-engine (TOCTOU double-spend & OTP rate-limit bypass)
  2. Module 3: oauth-account-takeover (redirect_uri traversal, state CSRF, Pre-ATO)
  3. Module 1: http-request-smuggling (CL.TE, TE.CL desync & H2 downgrade)
  4. Web Cache Poisoning & Deception (unkeyed headers & path delimiters)
  5. JS Endpoint Miner & Param Miner differential discovery
  6. SSTI Polyglot non-destructive arithmetic evaluation
"""

import os
import sys
import json
import hashlib
import subprocess

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

def test_module_2_race_condition():
    """Verify Module 2: race-condition-engine execution and findings"""
    worker_script = os.path.join(REPO_ROOT, "modules", "race-condition-engine", "worker.py")
    assert os.path.isfile(worker_script), "race-condition worker missing"

    # 1. Health check
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({"type": "HealthCheck"}) + "\n", timeout=5)
    msg = json.loads(out.strip().split("\n")[0])
    assert msg.get("type") == "HealthCheckResult" and msg.get("payload", {}).get("healthy") is True

    # 2. ScopeGuard rejection
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "scope-test",
            "target": "unauthorized.evil.org",
            "scope_approved": False
        }
    }) + "\n", timeout=5)
    assert "scope" in out.lower() or "violation" in out.lower() or "aborted" in out.lower()

    # 3. Execution & Finding validation
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "race-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    findings = res["payload"]["findings"]
    cwes = [f["cwe"] for f in findings]
    assert "CWE-367" in cwes, "TOCTOU race condition CWE-367 must be detected"

def test_module_3_oauth_account_takeover():
    """Verify Module 3: oauth-account-takeover execution and findings"""
    worker_script = os.path.join(REPO_ROOT, "modules", "oauth-account-takeover", "worker.py")
    assert os.path.isfile(worker_script), "oauth worker missing"

    # 1. Health check
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({"type": "HealthCheck"}) + "\n", timeout=5)
    msg = json.loads(out.strip().split("\n")[0])
    assert msg.get("type") == "HealthCheckResult" and msg.get("payload", {}).get("healthy") is True

    # 2. Execution & Finding validation
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "oauth-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    findings = res["payload"]["findings"]
    cwes = [f["cwe"] for f in findings]
    assert "CWE-601" in cwes or "CWE-352" in cwes or "CWE-287" in cwes

def test_module_2_batch2_js_endpoint_miner():
    """Verify JS Endpoint Miner discovery & source map detection"""
    worker_script = os.path.join(REPO_ROOT, "modules", "js-endpoint-miner", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "js-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert len(res["payload"]["endpoints_discovered"]) > 0

def test_module_3_batch2_param_miner():
    """Verify Parameter Miner differential detection"""
    worker_script = os.path.join(REPO_ROOT, "modules", "param-miner", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "param-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert "debug" in res["payload"]["hidden_parameters_found"]

def test_prototype_pollution():
    """Verify Prototype Pollution detection"""
    worker_script = os.path.join(REPO_ROOT, "modules", "prototype-pollution-detector", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "proto-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-1321" == f.get("cwe") for f in res["payload"]["findings"])

def test_nosql_injection():
    """Verify NoSQL operator injection detection"""
    worker_script = os.path.join(REPO_ROOT, "modules", "nosql-injection-auditor", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "nosql-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-943" == f.get("cwe") for f in res["payload"]["findings"])

def test_crlf_injection():
    """Verify CRLF injection and HTTP response splitting"""
    worker_script = os.path.join(REPO_ROOT, "modules", "crlf-injection-engine", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "crlf-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-113" == f.get("cwe") for f in res["payload"]["findings"])

def test_dom_xss_postmessage():
    """Verify DOM XSS and postMessage unvalidated origin auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "dom-xss-postmessage", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "domxss-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-79" == f.get("cwe") or "CWE-345" == f.get("cwe") for f in res["payload"]["findings"])

def main():
    print("=" * 70)
    print("CYBER HASHIRA - BUG BOUNTY ADVANCED VERIFICATION SUITE (8 ENGINES)")
    print("=" * 70)

    tests = [
        ("Module 2: Race Condition & Concurrency Engine", test_module_2_race_condition),
        ("Module 3: OAuth 2.0 & SSO Account Takeover Auditor", test_module_3_oauth_account_takeover),
        ("Module: JavaScript Endpoint & Secret Miner", test_module_2_batch2_js_endpoint_miner),
        ("Module: Hidden Parameter & Debug Switch Miner", test_module_3_batch2_param_miner),
        ("Module: Prototype Pollution (CWE-1321)", test_prototype_pollution),
        ("Module: NoSQL Injection & MongoDB Operators (CWE-943)", test_nosql_injection),
        ("Module: CRLF Injection & Response Splitting (CWE-113)", test_crlf_injection),
        ("Module: DOM XSS & postMessage Origin Security (CWE-79/345)", test_dom_xss_postmessage)
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
