#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — Master Unified Cross-Platform Launcher
Supports Windows, Linux, and macOS.

Usage:
  python hashira.py web [--port 8080] [--host 0.0.0.0]
  python hashira.py tui
  python hashira.py desktop [--dev]
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

REPO_ROOT = Path(__file__).resolve().parent
REGISTRY_PATH = REPO_ROOT / "registry" / "v1" / "modules.json"
MODULES_DIR = REPO_ROOT / "modules"


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
    print("=" * 70)
    
    app_script = REPO_ROOT / "ui" / "web" / "app.py"
    if not app_script.is_file():
        print(f"[!] Error: Web application not found at {app_script}")
        sys.exit(1)

    env = os.environ.copy()
    env["FLASK_RUN_HOST"] = args.host
    env["FLASK_RUN_PORT"] = str(args.port)
    
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
    """Launch or build the Tauri Desktop Application."""
    desktop_dir = REPO_ROOT / "apps" / "desktop"
    if not desktop_dir.is_dir():
        print(f"[!] Error: Desktop app directory not found at {desktop_dir}")
        sys.exit(1)

    print("=" * 70)
    print("⚔️  CYBER HASHIRA — Launching Native Desktop App (Tauri / React)")
    print("=" * 70)

    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    subcmd = ["run", "tauri", "dev"] if args.dev else ["run", "tauri", "dev"]

    try:
        subprocess.run([npm_cmd] + subcmd, cwd=str(desktop_dir))
    except FileNotFoundError:
        print("[!] Error: npm is not installed or not in PATH.")
        print("[*] You can still run the Web Panel (python hashira.py web) or Terminal TUI (python hashira.py tui).")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Desktop app terminated.")


def cmd_matrix(args):
    """Run the 120-Module Verification Matrix."""
    matrix_script = REPO_ROOT / "tests" / "test_all_modules_matrix.py"
    if not matrix_script.is_file():
        print(f"[!] Error: Matrix test script not found at {matrix_script}")
        sys.exit(1)

    subprocess.run([sys.executable, str(matrix_script)])


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
    catalog = get_catalog()
    mod = next((m for m in catalog.get("modules", []) if m["id"] == args.module), None)
    if not mod:
        print(f"[!] Error: Module '{args.module}' not found in registry.")
        sys.exit(1)

    worker_script = MODULES_DIR / args.module / "worker.py"
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

    print(f"[*] Executing '{args.module}' against target '{args.target}'...")
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


def main():
    parser = argparse.ArgumentParser(
        description="Cyber Hashira — Master Security Platform Launcher (Windows & Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available interface or action")

    # Web
    p_web = subparsers.add_parser("web", help="Start the Web Dashboard UI (Flask)")
    p_web.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    p_web.add_argument("--host", default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    p_web.set_defaults(func=cmd_web)

    # TUI
    p_tui = subparsers.add_parser("tui", help="Start the Interactive Terminal Console TUI")
    p_tui.set_defaults(func=cmd_tui)

    # Desktop
    p_desk = subparsers.add_parser("desktop", help="Start the Native Desktop App (Tauri / React)")
    p_desk.add_argument("--dev", action="store_true", help="Run in dev mode")
    p_desk.set_defaults(func=cmd_desktop)

    # Matrix
    p_matrix = subparsers.add_parser("matrix", help="Run the full 120-module verification test matrix")
    p_matrix.set_defaults(func=cmd_matrix)

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
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
