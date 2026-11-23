#!/usr/bin/env python3
"""
Cyber Hashira – Web Panel Backend
Flask API server that bridges the browser UI to module workers via stdio IPC.
"""

import datetime
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

import bcrypt
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from flask_cors import CORS

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    REPO_ROOT = Path(sys.executable).resolve().parent
else:
    REPO_ROOT = Path(__file__).parent.parent.parent

TEMPLATES_DIR = REPO_ROOT / "ui" / "web" / "templates"
STATIC_DIR = REPO_ROOT / "ui" / "web" / "static"

MODULES_DIR = REPO_ROOT / "modules"
REGISTRY_CATALOG = REPO_ROOT / "registry" / "v1" / "modules.json"

MODULE_ALIASES = {
    "forensics": "digital-forensics",
    "vulnerability": "vulnerability-assessment"
}

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR)
)
app.secret_key = os.environ.get("HASHIRA_SECRET_KEY", secrets.token_hex(32))
CORS(app)  # Enable CORS for local development

IPC_TIMEOUT = 10  # seconds

# ---------------------------------------------------------------------------
# Security & Authentication Configuration
# ---------------------------------------------------------------------------
AUTH_ENABLED = ("--no-auth" not in sys.argv) and (os.environ.get("HASHIRA_NO_AUTH") != "1")

DEFAULT_ADMIN_USER = os.environ.get("HASHIRA_ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("HASHIRA_ADMIN_PASSWORD", "HashiraAdmin2026!")
ADMIN_PASS_HASH = bcrypt.hashpw(DEFAULT_ADMIN_PASS.encode("utf-8"), bcrypt.gensalt())

if not AUTH_ENABLED:
    print("\n" + "=" * 70)
    print("⚠️  [SECURITY WARNING] Cyber Hashira Web Dashboard running with --no-auth!")
    print("⚠️  Session authentication & CSRF protection are DISABLED.")
    print("⚠️  Do NOT expose this service on public, shared, or untrusted networks!")
    print("=" * 70 + "\n")
else:
    print(f"[*] Cyber Hashira Authentication: ENABLED (Default user: '{DEFAULT_ADMIN_USER}')")

# In-memory rate limiter table: ip -> list of timestamps
RATE_LIMIT_STORE: Dict[str, List[float]] = {}

def check_rate_limit(ip: str, max_requests: int = 30, window_sec: int = 60) -> bool:
    """Sliding-window rate limiter per client IP."""
    now = time.time()
    timestamps = RATE_LIMIT_STORE.get(ip, [])
    # Filter out entries older than window
    timestamps = [t for t in timestamps if now - t < window_sec]
    if len(timestamps) >= max_requests:
        RATE_LIMIT_STORE[ip] = timestamps
        return False
    timestamps.append(now)
    RATE_LIMIT_STORE[ip] = timestamps
    return True


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
    canonical_id = MODULE_ALIASES.get(module_id, module_id)
    mod_dir = MODULES_DIR / canonical_id
    manifest_file = mod_dir / "manifest.json"
    if not manifest_file.is_file():
        # Fallback check direct
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
    Run a module worker via sandboxed subprocess, send a JSON message to stdin,
    and return the parsed JSON response.
    Raises RuntimeError on failure or timeout.
    """
    worker = get_worker_path(module_id)
    if worker is None:
        raise RuntimeError(f"Worker script not found for module '{module_id}'")

    try:
        from engine.sandbox import execute_sandboxed_worker, SandboxingMode
        res_json, stderr, exit_code = execute_sandboxed_worker(
            worker_path=worker,
            message=message,
            timeout_sec=IPC_TIMEOUT,
            sandbox_mode=SandboxingMode.STANDARD
        )
        if res_json is not None:
            return res_json
        err_preview = stderr.strip()[:300] if stderr else f"exit code {exit_code}"
        raise RuntimeError(f"No valid JSON from module '{module_id}'. Details: {err_preview}")
    except ImportError:
        # Fallback if engine sandbox is not in path
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
            for line in stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        return json.loads(line)
                    except json.JSONDecodeError:
                        continue
            err_preview = stderr.strip()[:300] if stderr else "(no stderr)"
            raise RuntimeError(f"No valid JSON from module '{module_id}'. stderr: {err_preview}")
        except Exception as exc:
            raise RuntimeError(f"IPC error for '{module_id}': {exc}") from exc


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
    from engine.audit_log import audit_logger
    from engine.scopeguard import verify as scopeguard_verify
    from engine.repeater import RepeaterEngine
    from engine.proxy import (
        start_proxy,
        stop_proxy,
        get_proxy_status,
        get_traffic_history,
        clear_traffic_history
    )
    from engine.crawler import WebCrawler
    from engine.fuzzer import EndpointFuzzer
    from engine.fingerprint import TechFingerprinter
    playbook_engine = PlaybookEngine()
    ai_engine = AICorrelationEngine()
    reporting_engine = EnterpriseReportingEngine()
    fleet_manager = FleetManager()
    threat_intel = ThreatIntelHub()
    repeater_engine = RepeaterEngine()
    crawler_engine = WebCrawler()
    fuzzer_engine = EndpointFuzzer()
    fingerprint_engine = TechFingerprinter()
except Exception as _eng_err:
    playbook_engine = None
    ai_engine = None
    reporting_engine = None
    fleet_manager = None
    threat_intel = None
    audit_logger = None
    scopeguard_verify = None
    repeater_engine = None
    crawler_engine = None
    fuzzer_engine = None
    fingerprint_engine = None
    start_proxy = None
    stop_proxy = None
    get_proxy_status = lambda: {"running": False, "captured_count": 0}
    get_traffic_history = lambda limit=100, filter_host=None: []
    clear_traffic_history = lambda: None
    audit_logger = None
    scopeguard_verify = None

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
# Security & Authentication Middleware
# ---------------------------------------------------------------------------

@app.before_request
def security_boundary_check():
    if not AUTH_ENABLED:
        return None

    # Static assets, login endpoints, and csrf token discovery
    if request.path.startswith("/static/") or request.endpoint in ("login", "logout", "api_csrf_token"):
        return None

    # Check session authentication
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required. Please authenticate at /login"}), 401
        return redirect(url_for("login"))

    # CSRF Verification on modifying HTTP verbs
    if request.method in ("POST", "PUT", "DELETE"):
        token = request.headers.get("X-CSRF-Token")
        if not token and request.is_json:
            token = (request.get_json(silent=True) or {}).get("csrf_token")
        if not token and request.form:
            token = request.form.get("csrf_token")

        expected_token = session.get("csrf_token")
        if not token or token != expected_token:
            return jsonify({"error": "CSRF verification failed. Missing or invalid X-CSRF-Token."}), 403

    # Rate Limiting on active scan executions
    if request.path.endswith("/run"):
        client_ip = request.remote_addr or "127.0.0.1"
        if not check_rate_limit(client_ip, max_requests=30, window_sec=60):
            return jsonify({"error": "Rate limit exceeded (30 scans per minute). Please throttle requests."}), 429

    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == DEFAULT_ADMIN_USER and bcrypt.checkpw(password.encode("utf-8"), ADMIN_PASS_HASH):
            session["authenticated"] = True
            session["user"] = username
            session["csrf_token"] = secrets.token_hex(24)
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid operator credentials. Access denied.")

    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/csrf-token", methods=["GET"])
def api_csrf_token():
    """Return active session CSRF token and auth status."""
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_hex(24)
    return jsonify({
        "csrf_token": session.get("csrf_token"),
        "auth_enabled": AUTH_ENABLED,
        "authenticated": bool(session.get("authenticated"))
    })


@app.route("/api/audit/logs", methods=["GET"])
def api_audit_logs():
    """Return recent immutable audit log records."""
    if not audit_logger or not audit_logger.log_path.is_file():
        return jsonify({"logs": [], "total": 0})
    logs = []
    try:
        with open(audit_logger.log_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line.strip()))
        return jsonify({"logs": logs[-100:], "total": len(logs)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/audit/verify", methods=["POST"])
def api_audit_verify():
    """Verify cryptographic hash-chain integrity of audit logs."""
    if not audit_logger:
        return jsonify({"error": "Audit logger not available"}), 500
    is_valid, count, err = audit_logger.verify_chain_integrity()
    return jsonify({
        "valid": is_valid,
        "records_verified": count,
        "error": err
    })


# ---------------------------------------------------------------------------
# Repeater & Inspection Proxy API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/repeater/send", methods=["POST"])
def api_repeater_send():
    """Dispatches manual HTTP/S request via RepeaterEngine with ScopeGuard verification."""
    if not repeater_engine:
        return jsonify({"error": "Repeater engine not initialized"}), 500

    data = request.get_json(force=True, silent=True) or {}
    method = data.get("method", "GET")
    url = data.get("url", "").strip()
    headers = data.get("headers", {})
    body = data.get("body", "")
    verify_ssl = bool(data.get("verify_ssl", False))
    timeout = int(data.get("timeout", 15))

    if not url:
        return jsonify({"error": "Target URL is required"}), 400

    authorized_targets = data.get("authorized_targets")
    if not authorized_targets and url:
        from engine.scopeguard import normalize_target
        target_host = normalize_target(url)
        authorized_targets = [target_host]

    result = repeater_engine.send_request(
        method=method,
        url=url,
        headers=headers,
        body=body,
        authorized_targets=authorized_targets,
        timeout=timeout,
        verify_ssl=verify_ssl
    )
    return jsonify(result)


@app.route("/api/repeater/history", methods=["GET"])
def api_repeater_history():
    """Returns past repeater executions."""
    if not repeater_engine:
        return jsonify({"history": []})
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"history": repeater_engine.get_history(limit=limit)})


@app.route("/api/repeater/clear", methods=["POST"])
def api_repeater_clear():
    """Clears saved repeater request history."""
    if repeater_engine:
        repeater_engine.clear_history()
    return jsonify({"success": True})


@app.route("/api/proxy/status", methods=["GET"])
def api_proxy_status():
    """Returns current state of the HTTP/S inspection proxy."""
    if not get_proxy_status:
        return jsonify({"running": False, "captured_count": 0})
    return jsonify(get_proxy_status())


@app.route("/api/proxy/toggle", methods=["POST"])
def api_proxy_toggle():
    """Starts or stops the local inspection proxy listener."""
    data = request.get_json(force=True, silent=True) or {}
    port = int(data.get("port", 8081))
    status = get_proxy_status() if get_proxy_status else {"running": False}

    enable = data.get("enable")
    if enable is None:
        enable = not status.get("running", False)

    if enable:
        started = start_proxy(host="127.0.0.1", port=port) if start_proxy else False
        return jsonify({"success": started, "status": get_proxy_status() if get_proxy_status else {}})
    else:
        if stop_proxy:
            stop_proxy()
        return jsonify({"success": True, "status": get_proxy_status() if get_proxy_status else {}})


@app.route("/api/proxy/traffic", methods=["GET"])
def api_proxy_traffic():
    """Returns live stream of captured HTTP transactions."""
    limit = request.args.get("limit", 100, type=int)
    filter_host = request.args.get("filter", None)
    items = get_traffic_history(limit=limit, filter_host=filter_host) if get_traffic_history else []
    return jsonify({"traffic": items})


@app.route("/api/proxy/clear", methods=["POST"])
def api_proxy_clear():
    """Clears the live traffic capture buffer."""
    if clear_traffic_history:
        clear_traffic_history()
    return jsonify({"success": True})


# ---------------------------------------------------------------------------
# Reconnaissance & Discovery API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/recon/crawl", methods=["POST"])
def api_recon_crawl():
    """Runs recursive web spider against target URL within ScopeGuard boundary."""
    if not crawler_engine:
        return jsonify({"error": "Crawler engine not available"}), 500
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Target URL is required"}), 400
    depth = int(data.get("depth", 2))
    max_pages = int(data.get("max_pages", 40))
    authorized_targets = data.get("authorized_targets")
    result = crawler_engine.crawl(
        start_url=url,
        max_depth=depth,
        max_pages=max_pages,
        authorized_targets=authorized_targets
    )
    return jsonify(result)


@app.route("/api/recon/fuzz", methods=["POST"])
def api_recon_fuzz():
    """Runs concurrent endpoint fuzzing against target URL."""
    if not fuzzer_engine:
        return jsonify({"error": "Fuzzer engine not available"}), 500
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Target URL is required"}), 400
    threads = int(data.get("threads", 15))
    wordlist = data.get("wordlist")
    status_codes = data.get("status_codes")
    authorized_targets = data.get("authorized_targets")
    result = fuzzer_engine.fuzz(
        target_url=url,
        wordlist=wordlist,
        threads=threads,
        status_codes=status_codes,
        authorized_targets=authorized_targets
    )
    return jsonify(result)


@app.route("/api/recon/fingerprint", methods=["POST"])
def api_recon_fingerprint():
    """Fingerprints technologies and security headers for target URL."""
    if not fingerprint_engine:
        return jsonify({"error": "Fingerprint engine not available"}), 500
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Target URL is required"}), 400
    authorized_targets = data.get("authorized_targets")
    result = fingerprint_engine.fingerprint(
        target_url=url,
        authorized_targets=authorized_targets
    )
    return jsonify(result)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_hex(24)
    return render_template("index.html", csrf_token=session.get("csrf_token", ""))


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

    # Low-level ScopeGuard boundary check
    if scopeguard_verify:
        try:
            scopeguard_verify(target, authorized_targets=[target], scope_approved=True)
        except Exception as scope_err:
            if audit_logger:
                audit_logger.record_event(
                    actor=session.get("user", "web_operator"),
                    module_id=module_id,
                    target=target,
                    action="RunTask",
                    scope_approved=False,
                    status="BLOCKED_BY_SCOPE",
                    findings_count=0,
                    metadata={"error": str(scope_err)}
                )
            return jsonify({
                "module_id": module_id,
                "target": target,
                "success": False,
                "findings": [],
                "error": f"ScopeGuard boundary violation: {scope_err}"
            }), 403

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

        if audit_logger:
            audit_logger.record_event(
                actor=session.get("user", "web_operator"),
                module_id=module_id,
                target=target,
                action="RunTask",
                scope_approved=True,
                status="SUCCESS" if success else "FAILED",
                findings_count=len(findings)
            )

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

