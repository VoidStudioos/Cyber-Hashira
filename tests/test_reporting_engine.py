#!/usr/bin/env python3
"""
Cyber Hashira — Automated Verification Suite for Reporting & Deduplication Engine
Tests:
  1. Secret Redaction (Bearer token, AWS key, Private key, Password in URL)
  2. Finding Deduplication across multiple modules
  3. OASIS SARIF v2.1.0 Schema compliance
  4. Executive HTML Report generation & Risk Score calculation
  5. CLI headless report generation
"""

import os
import sys
import json
import subprocess
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
from reporting_engine import (
    redact_sensitive_data,
    deduplicate_findings,
    export_sarif,
    export_html_report,
    calculate_security_score
)

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

def test_secret_redaction():
    leak_sample = (
        "Found hardcoded AWS key AKIAIOSFODNN7EXAMPLE and secret aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'. "
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature "
        "Database: postgres://dbadmin:SuperSecretPass123!@db.internal:5432/production"
    )
    sanitized = redact_sensitive_data(leak_sample)

    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized, "AWS key not redacted!"
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "wJalrXUtnFEMI" not in sanitized, "AWS secret not redacted!"
    assert "SuperSecretPass123!" not in sanitized, "DB password not redacted!"
    assert "[REDACTED_BEARER_TOKEN]" in sanitized or "[REDACTED_JWT_TOKEN]" in sanitized

def test_cross_module_deduplication():
    # Simulating 3 modules finding the same missing CSP / header issue
    raw_findings = [
        {
            "id": "find-1",
            "module_id": "web-security",
            "target": "https://api.example.com",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "description": "The response headers do not include CSP directive.",
            "severity": "Medium",
            "cwe": "CWE-693",
            "evidence": "Headers lack Content-Security-Policy"
        },
        {
            "id": "find-2",
            "module_id": "csp-headers-evaluator",
            "target": "https://api.example.com",
            "title": "Content-Security-Policy Missing in Response",
            "description": "Target endpoint lacks CSP protection.",
            "severity": "Medium",
            "cwe": "CWE-693",
            "evidence": "Missing CSP on https://api.example.com"
        },
        {
            "id": "find-3",
            "module_id": "secrets-leak-scanner",
            "target": "https://api.example.com",
            "title": "Exposed Production Database Password in Config",
            "description": "Database password leaked in public config: db_password='SecretP@ssword123'",
            "severity": "Critical",
            "cwe": "CWE-798",
            "evidence": "Found db_password='SecretP@ssword123'"
        }
    ]

    deduped = deduplicate_findings(raw_findings)
    assert len(deduped) == 2, f"Expected 2 deduplicated findings, got {len(deduped)}"

    # Check that CSP duplicates were merged into 1 finding with 2 contributing modules
    csp_finding = next((f for f in deduped if f.get("cwe") == "CWE-693"), None)
    assert csp_finding is not None
    assert csp_finding["duplicate_count"] == 2
    assert "web-security" in csp_finding["discovered_by_modules"]
    assert "csp-headers-evaluator" in csp_finding["discovered_by_modules"]

    # Check secret redaction on evidence
    secret_finding = next((f for f in deduped if f.get("cwe") == "CWE-798"), None)
    assert secret_finding is not None
    assert "SecretP@ssword123" not in secret_finding["evidence"]
    assert "[REDACTED_SECRET]" in secret_finding["evidence"] or "[REDACTED_PASSWORD]" in secret_finding["evidence"]

def test_sarif_v210_export():
    findings = [
        {
            "id": "vuln-01",
            "module_id": "api-security",
            "target": "https://api.target.com/users",
            "title": "Broken Object Level Authorization (BOLA)",
            "description": "API allows accessing user data without tenant claim verification.",
            "severity": "Critical",
            "cvss_v3": 9.1,
            "cwe": "CWE-639",
            "cve": "CVE-2026-TEST",
            "evidence": "GET /api/v1/users/1002 returned 200 OK under tenant 2",
            "remediation": "Validate tenant ID against active JWT claims."
        }
    ]

    sarif_str = export_sarif(findings, {"target": "https://api.target.com"})
    sarif_json = json.loads(sarif_str)

    assert sarif_json["version"] == "2.1.0"
    assert "runs" in sarif_json and len(sarif_json["runs"]) > 0
    run = sarif_json["runs"][0]
    assert run["tool"]["driver"]["name"].startswith("Cyber Hashira")
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["ruleId"] in ["CWE-639", "CVE-2026-TEST", "vuln-01"]
    assert result["properties"]["severity"] == "Critical"
    assert result["properties"]["cvssV3"] == 9.1

def test_html_report_and_scoring():
    findings = [
        {"severity": "Critical", "title": "RCE", "description": "Remote code execution"},
        {"severity": "High", "title": "SQLi", "description": "SQL Injection"},
        {"severity": "Medium", "title": "XSS", "description": "Cross-site scripting"}
    ]
    score, grade = calculate_security_score(findings)
    assert score < 60, f"Expected critical/high penalties to drop score below 60, got {score}"

    html = export_html_report(findings, {"project_name": "Audit Lab", "target": "10.0.0.1"})
    assert "CYBER HASHIRA" in html
    assert "DETAILED TECHNICAL FINDINGS" in html
    assert "RCE" in html
    assert "SQLi" in html

def test_cli_report_generation():
    findings = [
        {
            "id": "test-f1",
            "module_id": "sast-source-scanner",
            "title": "Command Injection Vulnerability",
            "description": "Unsanitized user input passed to os.system()",
            "severity": "High",
            "cwe": "CWE-78"
        }
    ]

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w", encoding="utf-8") as in_f:
        json.dump({"findings": findings}, in_f)
        in_path = in_f.name

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as out_f:
        out_path = out_f.name

    try:
        cmd = [
            sys.executable,
            os.path.join(REPO_ROOT, "scripts", "cyber_hashira_cli.py"),
            "report",
            "--input", in_path,
            "--format", "html",
            "--output", out_path,
            "--project-name", "Automated CI Pentest"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0, f"CLI report command failed: {res.stderr}"
        assert os.path.isfile(out_path)
        with open(out_path, "r", encoding="utf-8") as rf:
            c = rf.read()
        assert "Command Injection Vulnerability" in c
        assert "Automated CI Pentest" in c
    finally:
        if os.path.exists(in_path):
            os.remove(in_path)
        if os.path.exists(out_path):
            os.remove(out_path)

def main():
    print("=" * 70)
    print("CYBER HASHIRA - REPORTING, REDACTION & DEDUPLICATION TEST SUITE")
    print("=" * 70)

    tests = [
        ("Secret & Credential Redaction", test_secret_redaction),
        ("Cross-Module Finding Deduplication", test_cross_module_deduplication),
        ("OASIS SARIF v2.1.0 Export Compliance", test_sarif_v210_export),
        ("Executive HTML Report & Posture Scoring", test_html_report_and_scoring),
        ("Headless CLI Report Generation", test_cli_report_generation),
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
