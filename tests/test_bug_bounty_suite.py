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

def test_xxe_injection():
    """Verify XML External Entity (XXE) injection auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "xxe-injection-auditor", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "xxe-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-611" == f.get("cwe") for f in res["payload"]["findings"])

def test_grpc_protobuf():
    """Verify gRPC & Protobuf security analyzer"""
    worker_script = os.path.join(REPO_ROOT, "modules", "grpc-protobuf-security", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "grpc-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert len(res["payload"]["services_discovered"]) > 0

def test_open_redirect():
    """Verify Open Redirect & chaining engine"""
    worker_script = os.path.join(REPO_ROOT, "modules", "open-redirect-chainer", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "redir-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-601" == f.get("cwe") for f in res["payload"]["findings"])

def test_graphql_batch_dos():
    """Verify GraphQL query amplification & batching auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "graphql-batch-dos", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "gqlbatch-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-776" == f.get("cwe") or "CWE-400" == f.get("cwe") for f in res["payload"]["findings"])

def test_http_request_smuggling():
    """Verify HTTP Request Smuggling & CL.TE / TE.CL desync auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "http-request-smuggling", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "smug-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-444" == f.get("cwe") for f in res["payload"]["findings"])

def test_cache_poisoning():
    """Verify Web Cache Poisoning & Web Cache Deception auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "cache-poisoning-deception", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "cache-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-444" == f.get("cwe") or "CWE-524" == f.get("cwe") for f in res["payload"]["findings"])

def test_ssti_polyglot():
    """Verify Server-Side Template Injection (SSTI) polyglot auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "ssti-polyglot-engine", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "ssti-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"simulation": True}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("type") == "TaskCompleted" and res.get("payload", {}).get("success") is True
    assert any("CWE-1336" == f.get("cwe") or "CWE-917" == f.get("cwe") for f in res["payload"]["findings"])

def test_jwt_security():
    """Verify JWT & cryptographic token analyzer"""
    worker_script = os.path.join(REPO_ROOT, "modules", "jwt-security-analyzer", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "jwt-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"sample_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("status") == "success" or res.get("type") == "TaskCompleted"
    findings = res.get("result", {}).get("findings", []) or res.get("payload", {}).get("findings", [])
    assert any("JWT_ALG_NONE" in f.get("vuln_type", "") or "JWT" in f.get("title", "") for f in findings)

def test_ssrf_guard():
    """Verify SSRF & Cloud Metadata defense validator"""
    worker_script = os.path.join(REPO_ROOT, "modules", "ssrf-guard-validator", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "ssrf-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"sample_urls": ["http://169.254.169.254/latest/meta-data/"]}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("status") == "success" or res.get("type") == "TaskCompleted"
    findings = res.get("result", {}).get("findings", []) or res.get("payload", {}).get("findings", [])
    assert any("SSRF" in f.get("title", "") or "Metadata" in f.get("title", "") for f in findings)

def test_subdomain_takeover():
    """Verify Subdomain Takeover & dangling DNS auditor"""
    worker_script = os.path.join(REPO_ROOT, "modules", "subdomain-takeover-audit", "worker.py")
    p = subprocess.Popen([sys.executable, worker_script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, _ = p.communicate(input=json.dumps({
        "type": "RunTask",
        "payload": {
            "task_id": "takeover-task-1",
            "target": "example.com",
            "scope_approved": True,
            "options": {"sample_cnames": [{"subdomain": "blog.corp.internal", "cname": "corp-blog.github.io"}]}
        }
    }) + "\n", timeout=5)
    res = json.loads(out.strip().split("\n")[0])
    assert res.get("status") == "success" or res.get("type") == "TaskCompleted"
    findings = res.get("result", {}).get("findings", []) or res.get("payload", {}).get("findings", [])
    assert any("Takeover" in f.get("title", "") for f in findings)

def main():
    print("=" * 70)
    print("CYBER HASHIRA - BUG BOUNTY ADVANCED VERIFICATION SUITE (18 ENGINES)")
    print("=" * 70)

    tests = [
        ("Module: Race Condition & Concurrency Engine (CWE-367)", test_module_2_race_condition),
        ("Module: OAuth 2.0 & SSO Account Takeover Auditor (CWE-601/352)", test_module_3_oauth_account_takeover),
        ("Module: JavaScript Endpoint & Secret Miner", test_module_2_batch2_js_endpoint_miner),
        ("Module: Hidden Parameter & Debug Switch Miner", test_module_3_batch2_param_miner),
        ("Module: Prototype Pollution Detector (CWE-1321)", test_prototype_pollution),
        ("Module: NoSQL Injection & MongoDB Operators (CWE-943)", test_nosql_injection),
        ("Module: CRLF Injection & Response Splitting (CWE-113)", test_crlf_injection),
        ("Module: DOM XSS & postMessage Origin Security (CWE-79/345)", test_dom_xss_postmessage),
        ("Module: XML External Entity & DTD Injection (CWE-611)", test_xxe_injection),
        ("Module: gRPC & Protocol Buffers Security (CWE-306)", test_grpc_protobuf),
        ("Module: Open Redirect & OAuth Chaining (CWE-601)", test_open_redirect),
        ("Module: GraphQL Batching & Query Amplification (CWE-776)", test_graphql_batch_dos),
        ("Module: HTTP Request Smuggling & Desync (CWE-444)", test_http_request_smuggling),
        ("Module: Web Cache Poisoning & Cache Deception (CWE-444/524)", test_cache_poisoning),
        ("Module: Server-Side Template Injection Polyglot (CWE-1336)", test_ssti_polyglot),
        ("Module: JWT & Cryptographic Token Analyzer (CWE-347)", test_jwt_security),
        ("Module: SSRF & Cloud Metadata Defense (CWE-918)", test_ssrf_guard),
        ("Module: Subdomain Takeover & Dangling DNS (CWE-284)", test_subdomain_takeover),
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
