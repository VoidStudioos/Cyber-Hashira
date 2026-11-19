#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — Master Unified Cross-Platform Launcher
Supports Windows, Linux, and macOS.

Usage:
  python hashira.py web [--port 8080] [--host 0.0.0.0]
  python hashira.py tui
  python hashira.py desktop [--dev]
  python hashira.py proxy [--port 8081] [--host 127.0.0.1]
  python hashira.py matrix
  python hashira.py list [--category <name>]
  python hashira.py scan --module <id> --target <url/ip>
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

# Force UTF-8 stream handling for Windows console compatibility
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if getattr(sys, "frozen", False):
    REPO_ROOT = Path(sys.executable).resolve().parent
else:
    REPO_ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = REPO_ROOT / "registry" / "v1" / "modules.json"
MODULES_DIR = REPO_ROOT / "modules"

MODULE_ALIASES = {
    "forensics": "digital-forensics",
    "vulnerability": "vulnerability-assessment"
}


def resolve_module_id(mod_id: str) -> str:
    """Resolves deprecated aliases to canonical module IDs."""
    if mod_id in MODULE_ALIASES:
        canonical = MODULE_ALIASES[mod_id]
        print(f"[!] DEPRECATION WARNING: Module alias '{mod_id}' is deprecated. Redirecting to '{canonical}'.")
        return canonical
    return mod_id


def get_catalog():
    if not REGISTRY_PATH.is_file():
        print(f"[!] Registry catalog not found at {REGISTRY_PATH}")
        sys.exit(1)
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def cmd_web(args):
    """Launch the Web Dashboard."""
    print("=" * 70)
    print("⚔️  CYBER HASHIRA — Launching Web Security Dashboard")
    print(f"[*] Serving on http://{args.host}:{args.port}")
    if getattr(args, "no_auth", False):
        print("⚠️  [SECURITY WARNING] Authentication & CSRF protection are DISABLED via --no-auth!")
    else:
        print("[*] Operator Authentication: ENABLED (Default username: 'admin')")
    print("=" * 70)
    
    app_script = REPO_ROOT / "ui" / "web" / "app.py"
    if not app_script.is_file():
        print(f"[!] Error: Web application not found at {app_script}")
        sys.exit(1)

    env = os.environ.copy()
    env["FLASK_RUN_HOST"] = args.host
    env["FLASK_RUN_PORT"] = str(args.port)
    if getattr(args, "no_auth", False):
        env["HASHIRA_NO_AUTH"] = "1"
    
    if getattr(sys, "frozen", False):
        sys.path.insert(0, str(REPO_ROOT / "ui" / "web"))
        sys.path.insert(0, str(REPO_ROOT))
        try:
            from ui.web.app import app
            app.run(host=args.host, port=args.port, debug=False)
            return
        except Exception as e:
            print(f"[!] Frozen web app launch error: {e}")
            sys.exit(1)

    try:
        subprocess.run([sys.executable, str(app_script)], env=env)
    except KeyboardInterrupt:
        print("\n[*] Web dashboard stopped.")


def cmd_tui(args):
    """Launch the Terminal TUI Dashboard."""
    tui_script = REPO_ROOT / "ui" / "tui" / "dashboard.py"
    if not tui_script.is_file():
        print(f"[!] Error: TUI dashboard script not found at {tui_script}")
        sys.exit(1)

    try:
        subprocess.run([sys.executable, str(tui_script)])
    except KeyboardInterrupt:
        print("\n[*] TUI exited.")


def cmd_desktop(args):
    """Launch the dedicated Cyber Hashira Desktop Workstation Window."""
    print("=" * 70)
    print("⚔️  CYBER HASHIRA — Launching Standalone Desktop Workstation Window")
    print("=" * 70)

    if getattr(args, "tauri", False):
        desktop_dir = REPO_ROOT / "apps" / "desktop"
        npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
        try:
            subprocess.run([npm_cmd, "run", "tauri", "dev"], cwd=str(desktop_dir))
        except Exception as e:
            print(f"[!] Tauri run error: {e}")
        return

    # Native Dedicated Desktop Window Mode (Edge/Chrome Standalone App Mode)
    import threading
    import time
    import webbrowser

    app_script = REPO_ROOT / "ui" / "web" / "app.py"
    port = getattr(args, "port", 8080)
    url = f"http://127.0.0.1:{port}"

    # Start Flask web server in a separate background process
    print(f"[*] Starting local backend daemon on {url}...")
    proc = None
    if getattr(sys, "frozen", False):
        sys.path.insert(0, str(REPO_ROOT / "ui" / "web"))
        sys.path.insert(0, str(REPO_ROOT))
        try:
            from ui.web.app import app
            server_thread = threading.Thread(
                target=lambda: app.run(host="127.0.0.1", port=port, debug=False),
                daemon=True
            )
            server_thread.start()
            time.sleep(1.5)
        except Exception as e:
            print(f"[!] Frozen desktop server start error: {e}")
    else:
        proc = subprocess.Popen([sys.executable, str(app_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.8)

    # Search for standalone desktop application runners
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]

    browser_bin = None
    for p in edge_paths + chrome_paths:
        if os.path.isfile(p):
            browser_bin = p
            break

    profile_dir = Path(os.environ.get("TEMP", "/tmp")) / "hashira-desktop-profile"

    try:
        if browser_bin:
            print(f"[*] Launching dedicated window using native WebView ({Path(browser_bin).name})...")
            cmd = [
                browser_bin,
                f"--app={url}",
                "--window-size=1440,900",
                f"--user-data-dir={profile_dir}"
            ]
            subprocess.run(cmd)
        else:
            print(f"[*] Opening desktop interface in default browser: {url}")
            webbrowser.open(url)
            proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Exiting desktop application...")
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()


def cmd_matrix(args):
    """Run the 200-Module Verification Test Matrix."""
    matrix_script = REPO_ROOT / "tests" / "test_all_modules_matrix.py"
    if not matrix_script.is_file():
        print(f"[!] Error: Matrix test script not found at {matrix_script}")
        sys.exit(1)

    subprocess.run([sys.executable, str(matrix_script)])


def cmd_playbook(args):
    """Orchestrate DAG attack and security mission playbooks."""
    sys.path.insert(0, str(REPO_ROOT))
    from engine.playbooks import PlaybookEngine

    engine = PlaybookEngine()
    if args.action == "list":
        pbs = engine.list_playbooks()
        print("=" * 85)
        print(f"⚔️  CYBER HASHIRA — REGISTERED MISSION PLAYBOOKS ({len(pbs)} Campaigns)")
        print("=" * 85)
        print(f"{'#':<3} | {'PLAYBOOK ID':<30} | {'CATEGORY':<25} | {'STAGES'}")
        print("-" * 85)
        for idx, p in enumerate(pbs, start=1):
            print(f"{idx:<3} | {p['id']:<30} | {p['category']:<25} | {p['stage_count']} Stages")
        print("=" * 85)
    elif args.action == "run":
        target = args.target or "https://target.corp"
        print(f"[*] Launching Playbook '{args.id}' against '{target}'...")
        res = engine.execute_playbook(
            playbook_id=args.id,
            target=target,
            scope_approved=True,
            simulate=not args.live
        )
        print(f"[+] Campaign Finished in {res['total_duration_sec']}s. Success: {res['overall_success']}")
        print(f"[+] Total Discovered Findings: {res['total_findings']}")
        for s_id, s_info in res["stages"].items():
            status_symbol = "✔" if s_info["success"] else "✖"
            print(f"    [{status_symbol}] {s_info['name']} ({s_info['module_id']}): {s_info['findings_count']} findings [{s_info['duration_ms']}ms]")


def cmd_report(args):
    """Generate executive PDF, HTML, or SARIF assessment report."""
    sys.path.insert(0, str(REPO_ROOT))
    from engine.reporting import EnterpriseReportingEngine

    reporter = EnterpriseReportingEngine()
    findings_file = Path(args.findings) if args.findings else None
    findings = []
    if findings_file and findings_file.is_file():
        with open(findings_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            findings = data if isinstance(data, list) else data.get("findings", [])
    else:
        # Sample findings for demonstration
        findings = [
            {"module_id": "llm-prompt-injection-auditor", "title": "Indirect Prompt Injection in Autonomous Agent", "severity": "Critical", "cwe": "CWE-74"},
            {"module_id": "adcs-esc-template-auditor", "title": "AD CS Certificate Template Privilege Escalation (ESC1)", "severity": "Critical", "cwe": "CWE-269"},
            {"module_id": "ssrf-guard-validator", "title": "IMDSv1 Cloud Metadata SSRF Egress", "severity": "High", "cwe": "CWE-918"}
        ]

    output = args.output or "cyber-hashira-report.pdf"
    target = args.target or "https://target.internal"

    if output.endswith(".pdf"):
        ok = reporter.generate_pdf_report(findings, target, output, title=args.title or "Cyber Hashira Security Assessment")
        print(f"[+] PDF Report successfully written to {output}")
    elif output.endswith(".sarif") or output.endswith(".json"):
        sarif = reporter.export_sarif(findings, target)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        print(f"[+] SARIF v2.1.0 Report written to {output}")
    else:
        html = reporter.generate_html_report(findings, target, title=args.title or "Cyber Hashira Security Assessment")
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Standalone Executive HTML Report written to {output}")


def cmd_fleet(args):
    """Manage distributed scanner nodes and rotating proxy mesh."""
    sys.path.insert(0, str(REPO_ROOT))
    from engine.distributed_fleet import FleetManager

    fleet = FleetManager()
    nodes = fleet.list_nodes()
    proxies = fleet.proxy_rotator.list_proxies()

    print("=" * 80)
    print(f"⚔️  CYBER HASHIRA — DISTRIBUTED FLEET CLUSTER ({len(nodes)} Nodes)")
    print("=" * 80)
    for n in nodes:
        print(f"[*] Node: {n['node_id']} | Host: {n['hostname']} ({n['ip_address']}) | Region: {n['region']} | Status: {n['status']}")
    print("\n" + "=" * 80)
    print(f"🌐 PROXY MESH & EGRESS ROUTING ({len(proxies)} Active Proxies)")
    print("=" * 80)
    for p in proxies:
        ban_tag = "[BANNED]" if p['banned'] else "[ACTIVE]"
        print(f"[*] {p['proxy_url']:<40} | Latency: {p['latency_ms']}ms | Success: {p['success_count']} | {ban_tag}")
    print("=" * 80)


def cmd_list(args):
    """List all certified modules."""
    catalog = get_catalog()
    modules = catalog.get("modules", [])
    if args.category:
        modules = [m for m in modules if args.category.lower() in m.get("category", "").lower()]

    print("=" * 85)
    print(f"CYBER HASHIRA — CERTIFIED MODULE CATALOG ({len(modules)} Modules)")
    print("=" * 85)
    print(f"{'#':<4} | {'MODULE ID':<32} | {'CATEGORY':<24} | {'VERSION'}")
    print("-" * 85)
    for idx, m in enumerate(modules, start=1):
        print(f"{idx:<4} | {m['id']:<32} | {m.get('category', 'Generic'):<24} | {m.get('version', '1.0.0')}")
    print("=" * 85)


def cmd_scan(args):
    """Execute a single module directly on a target."""
    canonical_id = resolve_module_id(args.module)
    catalog = get_catalog()
    mod = next((m for m in catalog.get("modules", []) if m["id"] == canonical_id), None)
    if not mod:
        print(f"[!] Error: Module '{args.module}' (canonical: '{canonical_id}') not found in registry.")
        sys.exit(1)

    worker_script = MODULES_DIR / canonical_id / "worker.py"
    if not worker_script.is_file():
        print(f"[!] Error: Module worker not found at {worker_script}")
        sys.exit(1)

    task_payload = {
        "type": "RunTask",
        "action": "execute",
        "target": args.target,
        "authorized_targets": [args.target],
        "payload": {
            "task_id": "cli-scan-001",
            "target": args.target,
            "scope_approved": True,
            "options": {"simulate_vulnerabilities": args.simulate}
        }
    }

    print(f"[*] Executing '{canonical_id}' against target '{args.target}'...")
    try:
        proc = subprocess.Popen(
            [sys.executable, str(worker_script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate(input=json.dumps(task_payload) + "\n", timeout=15)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    print(json.dumps(data, indent=2, ensure_ascii=False))
                    return
                except Exception:
                    continue
        if stderr:
            print(f"[!] Stderr: {stderr}")
    except Exception as e:
        print(f"[!] Execution failed: {e}")


def cmd_proxy(args):
    """Start the standalone HTTP/HTTPS inspection proxy server."""
    from engine.proxy import start_proxy, stop_proxy
    import time
    print("=" * 70)
    print("⚔️  CYBER HASHIRA — HTTP/S Inspection Proxy Server")
    print("=" * 70)
    print(f"[*] Binding proxy listener to http://{args.host}:{args.port}")
    print(f"[*] Configure your browser / HTTP client to use proxy {args.host}:{args.port}")
    print("[*] Captured requests and TLS CONNECT tunnels stream to the Repeater Studio.")
    print("[*] Press Ctrl+C to stop the proxy server.")
    print("=" * 70)

    started = start_proxy(host=args.host, port=args.port)
    if not started:
        print(f"[!] Failed to bind proxy to {args.host}:{args.port}")
        sys.exit(1)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down proxy server...")
        stop_proxy()
        print("[+] Proxy stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Hashira — Master Security Platform Launcher (Windows & Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available interface or action")

    # Proxy
    p_proxy = subparsers.add_parser("proxy", help="Start the standalone HTTP/S traffic inspection proxy")
    p_proxy.add_argument("--port", type=int, default=8081, help="Proxy listen port (default: 8081)")
    p_proxy.add_argument("--host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    p_proxy.set_defaults(func=cmd_proxy)

    # Web
    p_web = subparsers.add_parser("web", help="Start the Web Dashboard UI (Flask)")
    p_web.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p_web.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    p_web.add_argument("--no-auth", action="store_true", help="Disable web dashboard authentication and CSRF (Insecure)")
    p_web.set_defaults(func=cmd_web)

    # TUI
    p_tui = subparsers.add_parser("tui", help="Start the Interactive Terminal Console TUI")
    p_tui.set_defaults(func=cmd_tui)

    # Desktop
    p_desk = subparsers.add_parser("desktop", help="Start the Native Dedicated Desktop App Window")
    p_desk.add_argument("--tauri", action="store_true", help="Launch via Tauri dev runner")
    p_desk.add_argument("--port", type=int, default=8080, help="Local port (default: 8080)")
    p_desk.set_defaults(func=cmd_desktop)

    # Matrix
    p_matrix = subparsers.add_parser("matrix", help="Run the full 200-module verification test matrix")
    p_matrix.set_defaults(func=cmd_matrix)

    # Playbook (DAG Attack Chaining)
    p_playbook = subparsers.add_parser("playbook", help="Orchestrate DAG attack and security mission playbooks")
    p_pb_sub = p_playbook.add_subparsers(dest="action", required=True)
    p_pb_list = p_pb_sub.add_parser("list", help="List all available battle playbooks")
    p_pb_run = p_pb_sub.add_parser("run", help="Execute a multi-stage attack playbook")
    p_pb_run.add_argument("--id", required=True, help="Playbook ID (e.g. owasp-llm-redteam, ad-zero-to-hero)")
    p_pb_run.add_argument("--target", required=True, help="Target host, FQDN or endpoint")
    p_pb_run.add_argument("--live", action="store_true", help="Perform live tests instead of simulated audits")
    p_playbook.set_defaults(func=cmd_playbook)

    # Report (Enterprise Reporting & CVSS v4)
    p_report = subparsers.add_parser("report", help="Generate executive PDF, HTML, or SARIF assessment report")
    p_report.add_argument("--target", default="https://target.internal", help="Target domain or system")
    p_report.add_argument("--findings", help="Path to findings JSON file")
    p_report.add_argument("--output", default="cyber-hashira-report.pdf", help="Output file path (.pdf, .html, .sarif)")
    p_report.add_argument("--title", default="Cyber Hashira Security Assessment Report", help="Report document title")
    p_report.set_defaults(func=cmd_report)

    # Fleet (Distributed Scanner Mesh)
    p_fleet = subparsers.add_parser("fleet", help="View distributed scanner fleet and rotating proxy mesh")
    p_fleet.set_defaults(func=cmd_fleet)

    # List
    p_list = subparsers.add_parser("list", help="List registered modules")
    p_list.add_argument("--category", help="Filter by category")
    p_list.set_defaults(func=cmd_list)

    # Scan
    p_scan = subparsers.add_parser("scan", help="Run a security module scan directly")
    p_scan.add_argument("--module", required=True, help="Module ID")
    p_scan.add_argument("--target", required=True, help="Target URL or Host")
    p_scan.add_argument("--simulate", action="store_true", help="Simulate findings safely")
    p_scan.set_defaults(func=cmd_scan)

    if len(sys.argv) == 1:
        print("=" * 70)
        print("⚔️  CYBER HASHIRA — Modular Cybersecurity Workstation")
        print("=" * 70)
        print("[*] No CLI arguments specified. Launching Desktop Workstation Window...")
        print("[*] Tip: Run 'cyber-hashira.exe --help' to view all CLI & scanning commands.")
        print("=" * 70)
        sys.argv.append("desktop")

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
