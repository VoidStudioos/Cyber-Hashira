#!/usr/bin/env python3
"""
Cyber Hashira — Interactive Terminal User Interface (TUI) Dashboard
A fast, lightweight, zero-dependency ANSI console interface for:
  - Exploring the 200 certified security modules
  - Running instant IPC HealthChecks
  - Executing target scans through ScopeGuard
  - Launching DAG Battle Playbooks & Red-Team Chains
  - Generating and viewing OASIS SARIF & Executive PDF reports
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path

# Force UTF-8 encoding in Windows Terminal
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Paths
REPO_ROOT = Path(__file__).parent.parent.parent
MODULES_DIR = REPO_ROOT / "modules"
REGISTRY_CATALOG = REPO_ROOT / "registry" / "v1" / "modules.json"
SCRIPTS_DIR = REPO_ROOT / "scripts"
TESTS_DIR = REPO_ROOT / "tests"

sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(TESTS_DIR))

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    clear_screen()
    print(f"""{CYAN}{BOLD}
   ██████╗██╗   ██╗██████╗ ███████╗██████╗     ██╗  ██╗ █████╗ ███████╗██╗  ██╗██╗██████╗  █████╗ 
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██║  ██║██╔══██╗██╔════╝██║  ██║██║██╔══██╗██╔══██╗
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ███████║███████║███████╗███████║██║██████╔╝███████║
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██╔══██║██╔══██║╚════██║██╔══██║██║██╔══██╗██╔══██║
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ██║  ██║██║  ██║███████║██║  ██║██║██║  ██║██║  ██║
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
{RESET}{DIM}     :: Advanced Security Assessment Workstation — Terminal Console v1.0.0 ::{RESET}
    """)


def load_catalog():
    if not REGISTRY_CATALOG.is_file():
        return []
    with open(REGISTRY_CATALOG, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("modules", [])


def ipc_call(module_id: str, message: dict, timeout: int = 5):
    worker = MODULES_DIR / module_id / "worker.py"
    if not worker.is_file():
        return {"error": f"Worker not found for '{module_id}'"}
    try:
        proc = subprocess.Popen(
            [sys.executable, str(worker)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(worker.parent),
        )
        stdout, stderr = proc.communicate(input=json.dumps(message) + "\n", timeout=timeout)
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {"error": f"Invalid worker output: {stderr[:200]}"}
    except Exception as exc:
        return {"error": str(exc)}


def list_modules():
    modules = load_catalog()
    print_banner()
    print(f"{BOLD}[*] CERTIFIED MODULE REGISTRY ({len(modules)} Modules){RESET}\n")
    print(f"{BOLD}{'#':<4} | {'MODULE ID':<30} | {'CATEGORY':<22} | {'VERSION'}{RESET}")
    print("-" * 75)
    for idx, m in enumerate(modules, 1):
        cat = m.get("category", "General")
        print(f"{idx:<4} | {CYAN}{m['id']:<30}{RESET} | {YELLOW}{cat:<22}{RESET} | v{m.get('version', '1.0.0')}")
        if idx % 25 == 0 and idx < len(modules):
            val = input(f"\n{DIM}[Press Enter for more, or 'q' to return to menu]{RESET} ")
            if val.strip().lower() == "q":
                break
            print_banner()
    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def run_health_checks():
    modules = load_catalog()
    print_banner()
    print(f"{BOLD}[*] BATCH IPC HEALTHCHECK (Sample across categories){RESET}\n")

    sample_ids = [
        "sql-injection-fuzzer",
        "oauth-account-takeover",
        "http-request-smuggling",
        "race-condition-engine",
        "ssrf-guard-validator",
        "subdomain-takeover-audit",
        "cache-poisoning-deception",
        "jwt-security-analyzer",
        "grpc-protobuf-security",
        "dom-xss-postmessage",
        "k8s-rbac-audit",
        "s3-bucket-enumerator",
    ]

    print(f"{BOLD}{'MODULE ID':<32} | {'IPC STATUS':<14} | {'LATENCY'}{RESET}")
    print("-" * 65)

    for mod_id in sample_ids:
        t0 = time.time()
        res = ipc_call(mod_id, {"type": "HealthCheck"})
        dur = (time.time() - t0) * 1000
        healthy = (
            (res.get("type") == "HealthCheckResult" and res.get("payload", {}).get("healthy") is True)
            or res.get("status") == "ok"
            or res.get("healthy") is True
        )
        status_str = f"{GREEN}[PASS] OK{RESET}" if healthy else f"{RED}[FAIL]{RESET}"
        print(f"{mod_id:<32} | {status_str:<23} | {dur:.1f}ms")

    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def run_target_scan():
    print_banner()
    print(f"{BOLD}[*] SCOPEGUARD TARGET SCANNER{RESET}\n")

    target = input(f"Enter target host/URL {CYAN}[default: https://api.target.corp]{RESET}: ").strip()
    if not target:
        target = "https://api.target.corp"

    print(f"\nTarget set to: {GREEN}{target}{RESET}")
    confirm = input("Confirm this target is authorized in ScopeGuard (y/N)? ").strip().lower()
    if confirm != "y":
        print(f"\n{RED}[ABORTED] ScopeGuard blocked unconfirmed target.{RESET}")
        input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")
        return

    print("\nSelect module to execute:")
    print("  1. sql-injection-fuzzer (CWE-89)")
    print("  2. http-request-smuggling (CWE-444)")
    print("  3. oauth-account-takeover (CWE-601/352)")
    print("  4. ssrf-guard-validator (CWE-918)")
    print("  5. subdomain-takeover-audit (CWE-284)")
    choice = input("Choice [1-5]: ").strip()

    mod_map = {
        "1": "sql-injection-fuzzer",
        "2": "http-request-smuggling",
        "3": "oauth-account-takeover",
        "4": "ssrf-guard-validator",
        "5": "subdomain-takeover-audit",
    }
    mod_id = mod_map.get(choice, "sql-injection-fuzzer")

    print(f"\n{CYAN}[+] Dispatching Stdio IPC RunTask -> {mod_id}...{RESET}")
    res = ipc_call(mod_id, {
        "type": "RunTask",
        "action": "execute",
        "target": target,
        "authorized_targets": [target],
        "payload": {
            "task_id": f"tui-{mod_id}",
            "target": target,
            "scope_approved": True,
            "options": {"simulation": True},
        },
    })

    print(f"\n{GREEN}[+] Worker Response:{RESET}")
    print(json.dumps(res, indent=2))
    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def run_attack_chains():
    print_banner()
    print(f"{BOLD}[*] RED-TEAM ATTACK CHAIN MATRIX (5 Chains){RESET}\n")

    try:
        import test_attack_chain_integration as taci
        chains = [
            ("Chain 1: Full-Spectrum Web & API Kill Chain", taci.test_chain_1_web_api_kill_chain),
            ("Chain 2: Cloud Infrastructure & Lateral Movement", taci.test_chain_2_cloud_infrastructure),
            ("Chain 3: ScopeGuard Strict Boundary Enforcement", taci.test_chain_3_scope_guard_strict_isolation),
            ("Chain 4: Evidence Pipeline Integration", taci.test_chain_4_pipeline_integration),
            ("Chain 5: Web Panel IPC Contract Certification", taci.test_chain_5_web_panel_ipc_integration),
        ]

        passed = 0
        for name, fn in chains:
            print(f"[*] Executing {name} ... ", end="", flush=True)
            t0 = time.time()
            try:
                fn()
                dur = time.time() - t0
                print(f"{GREEN}[PASS]{RESET} ({dur:.2f}s)")
                passed += 1
            except Exception as e:
                print(f"{RED}[FAIL]{RESET} ({e})")

        print(f"\n{BOLD}Result: {passed}/{len(chains)} Chains Fully Certified.{RESET}")
    except Exception as exc:
        print(f"{RED}Error loading attack chains: {exc}{RESET}")

    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def generate_sarif_report():
    print_banner()
    print(f"{BOLD}[*] GENERATE OASIS SARIF v2.1.0 AUDIT REPORT{RESET}\n")

    try:
        from reporting_engine import export_sarif, deduplicate_findings
        sample_findings = [
            {
                "id": "tui-f1",
                "cwe": "CWE-89",
                "title": "SQL Injection in User Search Parameter",
                "description": "DB connection string postgres://dbadmin:Secret123@db.internal/app",
                "evidence": "Injected payload verified",
                "severity": "critical",
                "module_id": "sql-injection-fuzzer",
            },
            {
                "id": "tui-f2",
                "cwe": "CWE-444",
                "title": "HTTP Request Smuggling Desync",
                "description": "CL.TE desync verified",
                "evidence": "Dual Transfer-Encoding discrepancy",
                "severity": "critical",
                "module_id": "http-request-smuggling",
            },
        ]

        deduped = deduplicate_findings(sample_findings)
        sarif_str = export_sarif(deduped, {"target": "https://api.target.corp"})
        out_file = REPO_ROOT / f"cyber_hashira_report_{int(time.time())}.sarif"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(sarif_str)

        print(f"{GREEN}[+] SARIF v2.1.0 report generated successfully!{RESET}")
        print(f"    Path: {CYAN}{out_file}{RESET}")
    except Exception as exc:
        print(f"{RED}Error generating SARIF: {exc}{RESET}")

    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def launch_web_panel():
    print_banner()
    print(f"{BOLD}[*] LAUNCHING CYBER HASHIRA WEB PANEL{RESET}\n")
    print(f"{CYAN}Web Panel starting on: http://localhost:8080{RESET}")
    print(f"{DIM}Press Ctrl+C to stop the web server.{RESET}\n")
    try:
        from app import app
        app.run(host="127.0.0.1", port=8080, debug=False)
    except Exception as exc:
        print(f"{RED}Failed to run web panel: {exc}{RESET}")
        input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def run_mission_playbooks():
    print_banner()
    print(f"{BOLD}[*] LAUNCH DAG BATTLE MISSION PLAYBOOKS{RESET}\n")

    sys.path.insert(0, str(REPO_ROOT))
    from engine.playbooks import PlaybookEngine

    engine = PlaybookEngine()
    playbooks = engine.list_playbooks()

    for idx, p in enumerate(playbooks, start=1):
        print(f"  {CYAN}{idx}.{RESET} {BOLD}{p['name']}{RESET} [{YELLOW}{p['category']}{RESET}] - {p['stage_count']} Stages")

    print(f"\n  {DIM}Target: https://target.corp (Simulated Campaign){RESET}")
    pb_idx = input(f"\n{BOLD}Select Playbook [1-{len(playbooks)}] (or Enter to cancel): {RESET}").strip()
    if not pb_idx or not pb_idx.isdigit() or int(pb_idx) < 1 or int(pb_idx) > len(playbooks):
        return

    chosen = playbooks[int(pb_idx) - 1]
    print(f"\n[*] Executing '{chosen['name']}'...")
    res = engine.execute_playbook(chosen['id'], target="https://target.corp", scope_approved=True, simulate=True)

    print(f"\n{GREEN}[+] Campaign Completed in {res['total_duration_sec']}s! Success: {res['overall_success']}{RESET}")
    print(f"{BOLD}Total Discovered Vulnerabilities: {res['total_findings']}{RESET}\n")
    for s_id, s_info in res["stages"].items():
        sym = f"{GREEN}[PASS]{RESET}" if s_info["success"] else f"{RED}[FAIL]{RESET}"
        print(f"  {sym} {s_info['name']}: {s_info['findings_count']} findings ({s_info['duration_ms']}ms)")

    input(f"\n{DIM}[Press Enter to return to main menu]{RESET}")


def main_menu():
    while True:
        print_banner()
        print(f"""
  {BOLD}MAIN MENU (200 CERTIFIED MODULES MATRIX){RESET}
  {CYAN}1.{RESET} List All Certified Security Modules (200)
  {CYAN}2.{RESET} Run Batch IPC HealthChecks
  {CYAN}3.{RESET} Run Target Security Scan (ScopeGuard Protected)
  {CYAN}4.{RESET} Execute Red-Team Attack Chains Matrix (5 Chains)
  {CYAN}5.{RESET} Launch DAG Battle Mission Playbooks (6 Campaigns)
  {CYAN}6.{RESET} Generate Executive PDF & OASIS SARIF Reports
  {CYAN}7.{RESET} Launch Modern Web Panel UI (http://localhost:8080)
  {CYAN}0.{RESET} Exit

        """)
        choice = input(f"{BOLD}Cyber-Hashira > {RESET}").strip()

        if choice == "1":
            list_modules()
        elif choice == "2":
            run_health_checks()
        elif choice == "3":
            run_target_scan()
        elif choice == "4":
            run_attack_chains()
        elif choice == "5":
            run_mission_playbooks()
        elif choice == "6":
            generate_sarif_report()
        elif choice == "7":
            launch_web_panel()
        elif choice in ("0", "q", "exit"):
            print(f"\n{GREEN}[*] Exiting Cyber Hashira. Stay secure!{RESET}\n")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[*] Interrupted by user.{RESET}\n")
        sys.exit(0)
