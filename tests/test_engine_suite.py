# -*- coding: utf-8 -*-
"""
Tests for Cyber Hashira Advanced Autonomous Cybersecurity Engine Suite:
  1. PlaybookEngine (DAG attack chaining)
  2. AICorrelationEngine (CVSS v4.0 & multi-hop attack graphs)
  3. EnterpriseReportingEngine (HTML, PDF, SARIF)
  4. FleetManager & ProxyRotator
  5. ThreatIntelHub
"""

import os
import tempfile
from pathlib import Path
from engine.playbooks import PlaybookEngine
from engine.ai_correlation import AICorrelationEngine
from engine.reporting import EnterpriseReportingEngine, CVSSv4Calculator
from engine.distributed_fleet import FleetManager, ProxyRotator, ScannerNode
from engine.threat_feeds import ThreatIntelHub


def test_playbook_engine_registration_and_list():
    engine = PlaybookEngine()
    playbooks = engine.list_playbooks()
    assert len(playbooks) >= 6
    ids = [p["id"] for p in playbooks]
    assert "ad-zero-to-hero" in ids
    assert "owasp-llm-redteam" in ids
    assert "smart-contract-defi-audit" in ids
    assert "full-external-pentest" in ids
    assert "cloud-supply-chain-assurance" in ids
    assert "nextgen-protocols-audit" in ids


def test_playbook_execution_simulation():
    engine = PlaybookEngine()
    # Execute OWASP LLM Red Team Playbook with simulate=True
    res = engine.execute_playbook(
        playbook_id="owasp-llm-redteam",
        target="https://ai.target.internal/v1/chat",
        scope_approved=True,
        simulate=True
    )
    assert res["overall_success"] is True
    assert res["stages_executed"] == 5
    assert res["total_findings"] >= 1
    assert "findings" in res


def test_ai_correlation_and_cvss_v4():
    ai = AICorrelationEngine()

    # Test CVSS v4 calculation
    test_finding = {
        "title": "SQL Injection in User Login Endpoint",
        "description": "User supplied parameter injected into SQL query",
        "severity": "Critical"
    }
    cvss = ai.calculate_cvss_v4(test_finding)
    assert cvss["version"] == "4.0"
    assert cvss["score"] >= 9.0
    assert "CVSS:4.0" in cvss["vector"]

    # Test correlation with multi-hop findings
    findings = [
        {
            "title": "Server-Side Request Forgery in Webhook Generator",
            "description": "Unvalidated URL parameter allows fetching internal AWS metadata",
            "severity": "High"
        },
        {
            "title": "Leaked AWS Temporary Secret Key in Log Output",
            "description": "Found AKIA/ASIA key in application log dump",
            "severity": "Critical"
        }
    ]
    corr = ai.correlate(findings)
    assert corr.total_findings == 2
    assert corr.critical_count == 1
    assert corr.high_count == 1
    assert len(corr.chains) >= 1  # Should identify Cloud IMDS compromise chain
    assert len(corr.remediations) >= 1


def test_enterprise_reporting_engine_html_and_sarif():
    reporter = EnterpriseReportingEngine()
    findings = [
        {
            "module_id": "sql-injection-fuzzer",
            "title": "Polymorphic SQL Injection Vulnerability",
            "description": "Exploitable blind SQL injection on endpoint /api/v1/search",
            "severity": "Critical",
            "cwe": "CWE-89",
            "remediation": "Use parameterized prepared statements."
        }
    ]
    target = "https://finance.target.corp"

    # HTML test
    html = reporter.generate_html_report(findings, target)
    assert "<!DOCTYPE html>" in html
    assert "Polymorphic SQL Injection" in html
    assert "CVSS 4.0:" in html
    assert "PCI-DSS v4.0" in html

    # SARIF test
    sarif = reporter.export_sarif(findings, target)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 1


def test_enterprise_reporting_pdf():
    reporter = EnterpriseReportingEngine()
    findings = [
        {
            "module_id": "llm-prompt-injection-auditor",
            "title": "Indirect Prompt Injection Bypass",
            "description": "Autonomous agent executes unauthorized tool call",
            "severity": "High",
            "cwe": "CWE-74"
        }
    ]
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        ok = reporter.generate_pdf_report(findings, "https://ai.example.corp", tmp_path)
        assert os.path.exists(tmp_path)
        assert os.path.getsize(tmp_path) > 0
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_fleet_manager_and_proxy_rotator():
    fleet = FleetManager()
    nodes = fleet.list_nodes()
    assert len(nodes) >= 3

    # Dispatch task
    dispatch = fleet.dispatch_task("sql-injection-fuzzer", "target.com", {})
    assert dispatch["dispatched"] is True
    assert "proxy_used" in dispatch
    assert dispatch["assigned_node"] in [n["node_id"] for n in nodes]

    # Test proxy rotator
    rotator = ProxyRotator()
    p1 = rotator.get_proxy()
    assert p1 is not None
    rotator.report_result(p1, success=True)
    assert any(px["success_count"] > 0 for px in rotator.list_proxies())


def test_threat_intel_hub():
    hub = ThreatIntelHub()
    kevs = hub.get_kev_catalog()
    assert len(kevs) >= 4
    assert any("CVE-2024" in k["cve_id"] for k in kevs)

    polyglots = hub.get_polyglots()
    assert "sqli" in polyglots
    assert "xss" in polyglots
    assert "prompt_injection" in polyglots
