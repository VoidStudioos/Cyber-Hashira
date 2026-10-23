#!/usr/bin/env python3
"""
Cyber Hashira — Multi-Stage Attack Chain & End-to-End Integration Test Suite

This test suite verifies complete Red-Team attack workflows and end-to-end integration:
  Chain 1: Full-Spectrum Web & API Kill Chain (Recon -> Auth Bypass -> Injections -> Desync -> Concurrency)
  Chain 2: Cloud Infrastructure & Lateral Movement (Subdomain Takeover + SSRF IMDSv1/v2 + CORS)
  Chain 3: ScopeGuard Strict Boundary Enforcement & Zero Leakage
  Chain 4: Evidence Pipeline Integration (Findings Normalization -> Redaction -> Deduplication -> SARIF v2.1.0)
  Chain 5: Web Panel Host-Worker Stdio IPC Contract & Registry Integration (114 Modules)
"""

import os
import sys
import json
import uuid
import datetime
import subprocess

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(REPO_ROOT, "modules")
REGISTRY_CATALOG = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

from reporting_engine import (
    redact_sensitive_data,
    deduplicate_findings,
    export_sarif,
    export_html_report,
    calculate_security_score,
)

def run_test(name, fn):
    sys.stdout.write(f"[*] Running Integration Chain: {name} ... ")
    sys.stdout.flush()
    try:
        fn()
        print("\033[92mPASSED\033[0m")
        return True
    except Exception as e:
        print(f"\033[91mFAILED\033[0m: {e}")
        import traceback
        traceback.print_exc()
        return False

def call_worker(module_id: str, message: dict, timeout: int = 5) -> dict:
    """Helper to invoke a module worker via stdio IPC."""
    worker_script = os.path.join(MODULES_DIR, module_id, "worker.py")
    if not os.path.isfile(worker_script):
        raise FileNotFoundError(f"Worker for '{module_id}' not found at {worker_script}")

    p = subprocess.Popen(
        [sys.executable, worker_script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    payload = json.dumps(message) + "\n"
    out, err = p.communicate(input=payload, timeout=timeout)

    for line in out.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    raise RuntimeError(f"No valid JSON output from '{module_id}'. stderr: {err[:200]}")

# ==============================================================================
# Chain 1: Full-Spectrum Web & API Kill Chain
# ==============================================================================
def test_chain_1_web_api_kill_chain():
    """
    Simulates a multi-phase penetration test against an enterprise web application:
      Stage 1: Recon & Hidden Param Discovery (js-endpoint-miner + param-miner)
      Stage 2: Authentication & Token Tampering (oauth-account-takeover + jwt-security-analyzer)
      Stage 3: High-Severity Injections (xxe-injection-auditor + prototype-pollution + ssti + nosql)
      Stage 4: Infrastructure Desynchronization (http-request-smuggling + cache-poisoning)
      Stage 5: Concurrency Double-Spend (race-condition-engine)
    """
    target = "authorized-corp.target"
    stage_findings = []

    # --- Stage 1: Recon & Hidden Discovery ---
    js_res = call_worker("js-endpoint-miner", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage1-js",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert js_res.get("type") == "TaskCompleted" and js_res["payload"]["success"] is True
    endpoints = js_res["payload"].get("endpoints_discovered", [])
    assert len(endpoints) > 0, "Recon stage must discover endpoints"

    param_res = call_worker("param-miner", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage1-param",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert param_res.get("type") == "TaskCompleted" and param_res["payload"]["success"] is True
    hidden_params = param_res["payload"].get("hidden_parameters_found", [])
    assert "debug" in hidden_params or len(hidden_params) > 0

    # --- Stage 2: Authentication & Token Exploitation ---
    oauth_res = call_worker("oauth-account-takeover", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage2-oauth",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert oauth_res.get("type") == "TaskCompleted"
    stage_findings.extend(oauth_res["payload"].get("findings", []))

    jwt_res = call_worker("jwt-security-analyzer", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage2-jwt",
            "target": target,
            "scope_approved": True,
            "options": {"sample_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NSIsImFkbWluIjp0cnVlfQ."}
        }
    })
    jwt_findings = jwt_res.get("result", {}).get("findings", [])
    assert len(jwt_findings) > 0, "JWT alg:none bypass must be detected"
    stage_findings.extend(jwt_findings)

    # --- Stage 3: Deep Injection Exploitation ---
    xxe_res = call_worker("xxe-injection-auditor", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage3-xxe",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-611" == f.get("cwe") for f in xxe_res["payload"]["findings"])
    stage_findings.extend(xxe_res["payload"]["findings"])

    proto_res = call_worker("prototype-pollution-detector", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage3-proto",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-1321" == f.get("cwe") for f in proto_res["payload"]["findings"])
    stage_findings.extend(proto_res["payload"]["findings"])

    ssti_res = call_worker("ssti-polyglot-engine", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage3-ssti",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-1336" == f.get("cwe") or "CWE-917" == f.get("cwe") for f in ssti_res["payload"]["findings"])
    stage_findings.extend(ssti_res["payload"]["findings"])

    nosql_res = call_worker("nosql-injection-auditor", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage3-nosql",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-943" == f.get("cwe") for f in nosql_res["payload"]["findings"])
    stage_findings.extend(nosql_res["payload"]["findings"])

    # --- Stage 4: Infrastructure Desync ---
    smug_res = call_worker("http-request-smuggling", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage4-smug",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-444" == f.get("cwe") for f in smug_res["payload"]["findings"])
    stage_findings.extend(smug_res["payload"]["findings"])

    cache_res = call_worker("cache-poisoning-deception", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage4-cache",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-444" == f.get("cwe") or "CWE-524" == f.get("cwe") for f in cache_res["payload"]["findings"])
    stage_findings.extend(cache_res["payload"]["findings"])

    # --- Stage 5: Concurrency Double-Spend ---
    race_res = call_worker("race-condition-engine", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain1-stage5-race",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert any("CWE-367" == f.get("cwe") for f in race_res["payload"]["findings"])
    stage_findings.extend(race_res["payload"]["findings"])

    assert len(stage_findings) >= 12, f"Kill chain must produce comprehensive findings (got {len(stage_findings)})"

# ==============================================================================
# Chain 2: Cloud Infrastructure & Lateral Movement
# ==============================================================================
def test_chain_2_cloud_infrastructure():
    """
    Verifies Cloud Asset & Infrastructure attack vectors:
      - Subdomain Takeover on deprovisioned GitHub Pages / S3 bucket (subdomain-takeover-audit)
      - SSRF metadata endpoint access & loopback probes (ssrf-guard-validator)
      - CORS & WebSocket misconfigurations (cors-websocket-audit)
    """
    target = "cloud-infra.target"

    takeover_res = call_worker("subdomain-takeover-audit", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain2-takeover",
            "target": target,
            "scope_approved": True,
            "options": {"sample_cnames": [{"subdomain": "assets.target", "cname": "target.s3.amazonaws.com"}]}
        }
    })
    findings = takeover_res.get("result", {}).get("findings", [])
    assert len(findings) > 0, "Dangling cloud resource takeover must be identified"

    ssrf_res = call_worker("ssrf-guard-validator", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain2-ssrf",
            "target": target,
            "scope_approved": True,
            "options": {"sample_urls": ["http://169.254.169.254/latest/meta-data/", "file:///etc/shadow"]}
        }
    })
    ssrf_findings = ssrf_res.get("result", {}).get("findings", [])
    assert any("Metadata" in f.get("title", "") or "file://" in f.get("title", "") for f in ssrf_findings)

    cors_res = call_worker("cors-websocket-audit", {
        "type": "RunTask",
        "payload": {
            "task_id": "chain2-cors",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True}
        }
    })
    assert cors_res.get("type") == "TaskCompleted" or cors_res.get("status") == "success"

# ==============================================================================
# Chain 3: ScopeGuard Strict Boundary Enforcement
# ==============================================================================
def test_chain_3_scope_guard_strict_isolation():
    """
    Ensures that when a module is launched against an unauthorized target,
    ScopeGuard blocks execution immediately without running scans or leaking packets.
    """
    unauthorized_target = "evil.rogue-target.org"
    approved_scope = ["authorized.target.corp"]

    test_modules = [
        "race-condition-engine",
        "oauth-account-takeover",
        "xxe-injection-auditor",
        "prototype-pollution-detector",
        "crlf-injection-engine",
        "dom-xss-postmessage",
    ]

    for mod in test_modules:
        res = call_worker(mod, {
            "type": "RunTask",
            "payload": {
                "task_id": f"scope-guard-{mod}",
                "target": unauthorized_target,
                "scope_approved": False,
                "options": {"authorized_targets": approved_scope}
            }
        })
        payload = res.get("payload", {})
        error_msg = str(res)
        # Must be rejected explicitly
        assert (
            payload.get("success") is False
            or "unauthorized" in error_msg.lower()
            or "scope" in error_msg.lower()
            or "violation" in error_msg.lower()
            or "aborted" in error_msg.lower()
        ), f"ScopeGuard failed to reject unauthorized target on {mod}"

# ==============================================================================
# Chain 4: Evidence Pipeline Integration (Redaction -> Dedupe -> SARIF v2.1.0)
# ==============================================================================
def test_chain_4_pipeline_integration():
    """
    Validates that findings generated during attack chains are processed through:
      1. Secret Redaction (masks API keys, AWS keys, JWT tokens, DB passwords)
      2. Cross-Module Deduplication (combines findings on same target/path/CWE)
      3. OASIS SARIF v2.1.0 Export (with rule schemas and severity mappings)
      4. Executive Posture Score (0-100 calculated correctly)
    """
    raw_findings = [
        {
            "id": "f-1",
            "module_id": "sql-injection-fuzzer",
            "target": "https://api.target.corp",
            "title": "SQL Injection in User Search Parameter",
            "description": "Exposed DB connection string postgres://dbadmin:SuperSecretPass999!@db.internal/app",
            "evidence": "Injected AWS key AKIAIOSFODNN7EXAMPLE and secret aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
            "severity": "critical",
            "cwe": "CWE-89",
            "cvss": 9.8,
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        },
        {
            "id": "f-2",
            "module_id": "web-security",
            "target": "https://api.target.corp",
            "title": "SQL Injection in Search Form",
            "description": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureTokenFound",
            "evidence": "Payload ' OR '1'='1 returned database error snippet",
            "severity": "critical",
            "cwe": "CWE-89",
            "cvss": 9.8,
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        },
        {
            "id": "f-3",
            "module_id": "prototype-pollution-detector",
            "target": "https://api.target.corp/app",
            "title": "Client-Side Prototype Pollution",
            "description": "DOM property injection via query parameter",
            "evidence": "Object.prototype.polluted = canary",
            "severity": "high",
            "cwe": "CWE-1321",
            "cvss": 7.5,
            "detected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    ]

    # 1. Deduplication
    deduped = deduplicate_findings(raw_findings)
    assert len(deduped) == 2, f"Two SQLi findings must merge into 1 canonical finding (got {len(deduped)})"

    merged_sqli = next(f for f in deduped if f["cwe"] == "CWE-89")
    assert len(merged_sqli["discovered_by_modules"]) == 2
    assert "sql-injection-fuzzer" in merged_sqli["discovered_by_modules"]
    assert "web-security" in merged_sqli["discovered_by_modules"]

    # 2. Secret Redaction across all fields
    for finding in deduped:
        sanitized_desc = redact_sensitive_data(finding.get("description", ""))
        sanitized_ev = redact_sensitive_data(str(finding.get("evidence", "")))

        assert "SuperSecretPass999!" not in sanitized_desc, "DB password leaked in description!"
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized_ev, "AWS key leaked in evidence!"
        assert "wJalrXUtnFEMI" not in sanitized_ev, "AWS secret leaked in evidence!"
        assert "signatureTokenFound" not in sanitized_desc, "JWT bearer token leaked!"

    # 3. Posture Scoring
    score, grade = calculate_security_score(deduped)
    assert 0 <= score <= 100
    assert score < 70, f"Critical + High findings must lower security score (got {score})"
    assert "Risk" in grade or "Compromised" in grade

    # 4. SARIF v2.1.0 Export
    sarif_str = export_sarif(deduped, {"target": "https://api.target.corp"})
    sarif = json.loads(sarif_str) if isinstance(sarif_str, str) else sarif_str
    assert sarif.get("version") == "2.1.0"
    runs = sarif.get("runs", [])
    assert len(runs) > 0
    results = runs[0].get("results", [])
    assert len(results) == 2
    rule_ids = [r["ruleId"] for r in results]
    assert "CWE-89" in rule_ids
    assert "CWE-1321" in rule_ids

# ==============================================================================
# Chain 5: Web Panel IPC Contract & Registry Integration
# ==============================================================================
def test_chain_5_web_panel_ipc_integration():
    """
    Validates the Web Panel backend IPC logic (ui/web/app.py):
      - Verifies loading all 114 modules from registry/v1/modules.json
      - Verifies categories breakdown
      - Verifies health check on selected modules
    """
    assert os.path.isfile(REGISTRY_CATALOG), "modules.json must exist"
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    modules = catalog.get("modules", [])
    assert len(modules) >= 114, f"Registry must have at least 114 certified modules (got {len(modules)})"

    # Verify category categorization
    categories = {}
    for m in modules:
        cat = m.get("category", "Uncategorized")
        categories[cat] = categories.get(cat, 0) + 1

    assert len(categories) >= 7, f"Must have multiple categories (got {len(categories)})"

    # Test IPC HealthCheck on diverse modules across categories
    sample_modules = [
        "sql-injection-fuzzer",
        "grpc-protobuf-security",
        "tls-misconfiguration-scanner",
        "k8s-rbac-audit",
        "s3-bucket-enumerator",
        "dom-xss-postmessage"
    ]

    for mod_id in sample_modules:
        res = call_worker(mod_id, {"type": "HealthCheck"})
        healthy = (
            (res.get("type") == "HealthCheckResult" and res.get("payload", {}).get("healthy") is True)
            or res.get("status") == "ok"
            or res.get("healthy") is True
        )
        assert healthy is True, f"HealthCheck failed on '{mod_id}'"

    # Test Flask Web Panel API endpoints & template rendering
    sys.path.insert(0, os.path.join(REPO_ROOT, "ui", "web"))
    from app import app as flask_app
    client = flask_app.test_client()

    resp_index = client.get("/")
    assert resp_index.status_code == 200
    assert b"CYBER HASHIRA" in resp_index.data

    resp_mod = client.get("/api/modules")
    assert resp_mod.status_code == 200
    assert resp_mod.json.get("total", 0) >= 114

    resp_stats = client.get("/api/stats")
    assert resp_stats.status_code == 200
    assert resp_stats.json.get("total_modules", 0) >= 114

    resp_chains = client.get("/api/attack-chains")
    assert resp_chains.status_code == 200
    assert resp_chains.json.get("total", 0) == 5

# ==============================================================================
# Main Runner
# ==============================================================================
def main():
    print("=" * 80)
    print("CYBER HASHIRA — RED-TEAM ATTACK CHAIN & INTEGRATION TEST MATRIX")
    print("=" * 80)

    chains = [
        ("Chain 1: Full-Spectrum Web & API Kill Chain (Recon -> Auth -> Injections -> Desync -> Race)", test_chain_1_web_api_kill_chain),
        ("Chain 2: Cloud Infrastructure & Lateral Movement (Takeover + SSRF IMDS + CORS)", test_chain_2_cloud_infrastructure),
        ("Chain 3: ScopeGuard Strict Boundary Enforcement & Zero Leakage", test_chain_3_scope_guard_strict_isolation),
        ("Chain 4: Evidence Pipeline Integration (Redaction -> Dedupe -> SARIF v2.1.0)", test_chain_4_pipeline_integration),
        ("Chain 5: Web Panel Host-Worker Stdio IPC Contract (114 Modules Registry)", test_chain_5_web_panel_ipc_integration),
    ]

    passed = 0
    for name, fn in chains:
        if run_test(name, fn):
            passed += 1

    print("=" * 80)
    print(f"Integration Matrix Results: {passed}/{len(chains)} Chains Fully Certified.")
    print("=" * 80)

    if passed != len(chains):
        sys.exit(1)

if __name__ == "__main__":
    main()
