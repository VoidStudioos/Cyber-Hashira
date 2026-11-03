#!/usr/bin/env python3
"""
Cyber Hashira – Web Panel Backend
Flask API server that bridges the browser UI to module workers via stdio IPC.
"""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent.parent
MODULES_DIR = REPO_ROOT / "modules"
REGISTRY_CATALOG = REPO_ROOT / "registry" / "v1" / "modules.json"

app = Flask(__name__)
CORS(app)  # Enable CORS for local development

IPC_TIMEOUT = 5  # seconds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_catalog() -> dict:
    """Load the full modules catalog from the registry JSON file."""
    if not REGISTRY_CATALOG.is_file():
        return {}
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {m["id"]: m for m in data.get("modules", [])}


def get_worker_path(module_id: str) -> Path | None:
    """Return the path to a module's worker.py, or None if not found."""
    # Try direct module dir
    mod_dir = MODULES_DIR / module_id
    manifest_file = mod_dir / "manifest.json"
    if not manifest_file.is_file():
        return None
    try:
        with open(manifest_file, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        exe = manifest.get("entry_point", {}).get("executable", "worker.py")
        worker = mod_dir / exe
        return worker if worker.is_file() else None
    except Exception:
        return None


def ipc_call(module_id: str, message: dict) -> dict:
    """
    Run a module worker via subprocess, send a JSON message to stdin,
    and return the first parseable JSON line from stdout.
    Raises RuntimeError on failure or timeout.
    """
    worker = get_worker_path(module_id)
    if worker is None:
        raise RuntimeError(f"Worker script not found for module '{module_id}'")

    cmd = [sys.executable, str(worker)]
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(worker.parent),
        )
        payload_str = json.dumps(message) + "\n"
        stdout, stderr = proc.communicate(input=payload_str, timeout=IPC_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise RuntimeError(f"Module '{module_id}' timed out after {IPC_TIMEOUT}s")
    except Exception as exc:
        raise RuntimeError(f"IPC error for '{module_id}': {exc}") from exc

    # Parse the first valid JSON line from stdout
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue

    # If nothing parseable came back, include stderr in error
    err_preview = stderr.strip()[:300] if stderr else "(no stderr)"
    raise RuntimeError(f"No valid JSON from module '{module_id}'. stderr: {err_preview}")


# ---------------------------------------------------------------------------
# Sys path for scripts & tests & engine
# ---------------------------------------------------------------------------
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(REPO_ROOT / "tests"))

try:
    from engine import (
        PlaybookEngine,
        AICorrelationEngine,
        EnterpriseReportingEngine,
        FleetManager,
        ThreatIntelHub
    )
    playbook_engine = PlaybookEngine()
    ai_engine = AICorrelationEngine()
    reporting_engine = EnterpriseReportingEngine()
    fleet_manager = FleetManager()
    threat_intel = ThreatIntelHub()
except Exception as _eng_err:
    playbook_engine = None
    ai_engine = None
    reporting_engine = None
    fleet_manager = None
    threat_intel = None

try:
    from reporting_engine import (
        deduplicate_findings,
        export_sarif,
        export_html_report,
        calculate_security_score,
        redact_sensitive_data,
    )
except ImportError:
    deduplicate_findings = None
    export_sarif = None
    export_html_report = None
    calculate_security_score = None
    redact_sensitive_data = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/modules", methods=["GET"])
def api_modules():
    """Return the full list of modules from the registry catalog."""
    try:
        catalog = load_catalog()
        modules = list(catalog.values())
        return jsonify({"modules": modules, "total": len(modules)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/modules/<module_id>", methods=["GET"])
def api_module_detail(module_id: str):
    """Return details for a single module."""
    try:
        catalog = load_catalog()
        module = catalog.get(module_id)
        if module is None:
            return jsonify({"error": f"Module '{module_id}' not found"}), 404
        return jsonify(module)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/modules/<module_id>/health", methods=["POST"])
def api_module_health(module_id: str):
    """Run an IPC HealthCheck on the specified module worker."""
    try:
        result = ipc_call(module_id, {"type": "HealthCheck"})
        healthy = (
            (result.get("type") == "HealthCheckResult" and result.get("payload", {}).get("healthy") is True)
            or result.get("status") == "ok"
            or result.get("healthy") is True
        )
        return jsonify({
            "module_id": module_id,
            "healthy": healthy,
            "raw": result,
        })
    except RuntimeError as exc:
        return jsonify({"module_id": module_id, "healthy": False, "error": str(exc)}), 200
    except Exception as exc:
        return jsonify({"module_id": module_id, "healthy": False, "error": str(exc)}), 500


@app.route("/api/modules/<module_id>/run", methods=["POST"])
def api_module_run(module_id: str):
    """
    Run the module against a target.
    Expected JSON body: { "target": "<url>", "options": {} }
    """
    body = request.get_json(silent=True) or {}
    target = body.get("target", "example.com")
    options = body.get("options", {})

    message = {
        "type": "RunTask",
        "action": "execute",
        "target": target,
        "authorized_targets": [target],
        "payload": {
            "task_id": f"web-panel-{module_id}",
            "target": target,
            "scope_approved": True,
            "options": options,
        },
    }

    try:
        result = ipc_call(module_id, message)
        success = (
            (result.get("type") == "TaskCompleted" and result.get("payload", {}).get("success") is True)
            or result.get("status") == "success"
            or "findings" in str(result)
        )
        findings = []
        payload = result.get("payload", result.get("result", {}))
        if isinstance(payload, dict):
            findings = payload.get("findings", [])
        return jsonify({
            "module_id": module_id,
            "target": target,
            "success": success,
            "findings": findings,
            "raw": result,
        })
    except RuntimeError as exc:
        return jsonify({
            "module_id": module_id,
            "target": target,
            "success": False,
            "findings": [],
            "error": str(exc),
        }), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Return aggregate statistics about the module registry."""
    try:
        catalog = load_catalog()
        modules = list(catalog.values())
        categories: dict[str, int] = {}
        for mod in modules:
            cat = mod.get("category", "Uncategorized")
            categories[cat] = categories.get(cat, 0) + 1
        return jsonify({
            "total_modules": len(modules),
            "total_categories": len(categories),
            "categories": categories,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/attack-chains", methods=["GET"])
def api_attack_chains():
    """List available red team attack chains."""
    chains = [
        {
            "id": "chain-1",
            "name": "Full-Spectrum Web & API Kill Chain",
            "description": "Reconnaissance -> Broken Auth -> Polymorphic Injections -> Request Smuggling Desync -> Race Conditions",
            "modules": ["subdomain-takeover-audit", "oauth-account-takeover", "sql-injection-fuzzer", "nosql-injection-operator-tester", "http-request-smuggling", "race-condition-engine"],
            "target_type": "Web & Cloud APIs",
        },
        {
            "id": "chain-2",
            "name": "Cloud Infrastructure & Lateral Movement",
            "description": "Dangling DNS / Subdomain Takeover -> Cloud IMDS SSRF Exfiltration -> WebSocket / CORS Hijacking",
            "modules": ["subdomain-takeover-audit", "ssrf-guard-validator", "cors-websocket-audit"],
            "target_type": "Cloud Infrastructure",
        },
        {
            "id": "chain-3",
            "name": "ScopeGuard Strict Boundary Enforcement",
            "description": "Zero-leakage unauthorized target isolation across 6 attack modules",
            "modules": ["race-condition-engine", "oauth-account-takeover", "xxe-injection-auditor", "prototype-pollution-detector", "crlf-injection-engine", "dom-xss-postmessage"],
            "target_type": "Governance & Isolation",
        },
        {
            "id": "chain-4",
            "name": "Evidence Pipeline Integration",
            "description": "Credential Masking & Redaction -> Cross-Module Deduplication -> OASIS SARIF v2.1.0 -> Posture Scoring",
            "modules": ["reporting_engine", "sarif_exporter"],
            "target_type": "Compliance & CI/CD",
        },
        {
            "id": "chain-5",
            "name": "Web Panel IPC Contract Certification",
            "description": "Stdio JSON IPC protocol compliance check across 114 certified modules",
            "modules": ["all-114-modules"],
            "target_type": "Platform Architecture",
        },
    ]
    return jsonify({"chains": chains, "total": len(chains)})


@app.route("/api/attack-chains/run", methods=["POST"])
def api_run_attack_chain():
    """Execute a specific attack chain or all chains."""
    body = request.get_json(silent=True) or {}
    chain_id = body.get("chain_id", "all")
    
    try:
        import test_attack_chain_integration as taci
        chain_map = {
            "chain-1": ("Chain 1: Full-Spectrum Web & API Kill Chain", taci.test_chain_1_web_api_kill_chain),
            "chain-2": ("Chain 2: Cloud Infrastructure & Lateral Movement", taci.test_chain_2_cloud_infrastructure),
            "chain-3": ("Chain 3: ScopeGuard Strict Boundary Enforcement & Zero Leakage", taci.test_chain_3_scope_guard_strict_isolation),
            "chain-4": ("Chain 4: Evidence Pipeline Integration", taci.test_chain_4_pipeline_integration),
            "chain-5": ("Chain 5: Web Panel Host-Worker Stdio IPC Contract", taci.test_chain_5_web_panel_ipc_integration),
        }

        results = []
        if chain_id in chain_map:
            name, fn = chain_map[chain_id]
            fn()
            results.append({"chain_id": chain_id, "name": name, "status": "PASSED"})
        else:
            for cid, (name, fn) in chain_map.items():
                fn()
                results.append({"chain_id": cid, "name": name, "status": "PASSED"})

        return jsonify({
            "status": "success",
            "executed": len(results),
            "results": results,
        })
    except Exception as exc:
        return jsonify({
            "status": "failed",
            "error": str(exc),
        }), 500


@app.route("/api/reports/sarif", methods=["POST"])
def api_export_sarif():
    """Export findings as OASIS SARIF v2.1.0 JSON."""
    if export_sarif is None:
        return jsonify({"error": "reporting_engine not available"}), 500
    body = request.get_json(silent=True) or {}
    findings = body.get("findings", [])
    target = body.get("target", "https://api.target.corp")
    meta = {"target": target, "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    
    try:
        sarif_str = export_sarif(findings, meta)
        return app.response_class(sarif_str, mimetype="application/json")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/reports/html", methods=["POST"])
def api_export_html():
    """Export findings as printable executive HTML report."""
    if export_html_report is None:
        return jsonify({"error": "reporting_engine not available"}), 500
    body = request.get_json(silent=True) or {}
    findings = body.get("findings", [])
    target = body.get("target", "https://api.target.corp")
    meta = {"target": target, "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    
    try:
        html_str = export_html_report(findings, meta)
        return app.response_class(html_str, mimetype="text/html")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/playbooks", methods=["GET"])
def api_list_playbooks():
    """List all registered DAG attack and audit playbooks."""
    if not playbook_engine:
        return jsonify({"error": "Playbook engine not available"}), 500
    try:
        pbs = playbook_engine.list_playbooks()
        return jsonify({"playbooks": pbs, "total": len(pbs)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/playbooks/run", methods=["POST"])
def api_run_playbook():
    """Execute a mission playbook across stages."""
    if not playbook_engine:
        return jsonify({"error": "Playbook engine not available"}), 500
    body = request.get_json(silent=True) or {}
    playbook_id = body.get("playbook_id", "owasp-llm-redteam")
    target = body.get("target", "https://target.corp")
    simulate = body.get("simulate", True)

    try:
        res = playbook_engine.execute_playbook(
            playbook_id=playbook_id,
            target=target,
            scope_approved=True,
            simulate=simulate
        )
        return jsonify(res)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ai/correlate", methods=["POST"])
def api_ai_correlate():
    """Correlate findings into multi-hop attack graphs and calculate CVSS v4.0."""
    if not ai_engine:
        return jsonify({"error": "AI correlation engine not available"}), 500
    body = request.get_json(silent=True) or {}
    findings = body.get("findings", [])

    try:
        corr = ai_engine.correlate(findings)
        chains = [
            {
                "chain_id": c.chain_id,
                "title": c.title,
                "severity": c.severity,
                "impact": c.impact,
                "mitre_attack_tactics": c.mitre_attack_tactics,
                "attack_steps": c.attack_steps,
                "exploitability_score": c.exploitability_score,
                "recommended_action": c.recommended_action
            } for c in corr.chains
        ]
        return jsonify({
            "total_findings": corr.total_findings,
            "critical_count": corr.critical_count,
            "high_count": corr.high_count,
            "medium_count": corr.medium_count,
            "low_count": corr.low_count,
            "posture_score": corr.posture_score,
            "chains": chains,
            "remediations": corr.remediations
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/reports/pdf", methods=["POST"])
def api_export_pdf():
    """Export findings as executive printable PDF report."""
    if not reporting_engine:
        return jsonify({"error": "Enterprise reporting engine not available"}), 500
    body = request.get_json(silent=True) or {}
    findings = body.get("findings", [])
    target = body.get("target", "https://api.target.corp")
    title = body.get("title", "Cyber Hashira Security Assessment Report")

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        reporting_engine.generate_pdf_report(findings, target, tmp_path, title=title)
        with open(tmp_path, "rb") as f:
            pdf_bytes = f.read()
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return app.response_class(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=cyber-hashira-report.pdf"}
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/fleet/nodes", methods=["GET"])
def api_fleet_nodes():
    """Return active distributed scanner fleet nodes."""
    if not fleet_manager:
        return jsonify({"error": "Fleet manager not available"}), 500
    return jsonify({"nodes": fleet_manager.list_nodes()})


@app.route("/api/fleet/proxies", methods=["GET"])
def api_fleet_proxies():
    """Return proxy mesh status and latency telemetry."""
    if not fleet_manager:
        return jsonify({"error": "Fleet manager not available"}), 500
    return jsonify({"proxies": fleet_manager.proxy_rotator.list_proxies()})


@app.route("/api/threats/kev", methods=["GET"])
def api_threats_kev():
    """Return CISA Known Exploited Vulnerabilities catalog."""
    if not threat_intel:
        return jsonify({"error": "Threat intel hub not available"}), 500
    return jsonify({"kevs": threat_intel.get_kev_catalog()})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

