#!/usr/bin/env python3
"""
Cyber Hashira — Headless CLI Runner & CI/CD Security Gate
Allows running any of the 30 Cyber Hashira modules directly in automated CI/CD pipelines
without the graphical desktop interface.

Usage Examples:
  # List all 30 modules
  python scripts/cyber_hashira_cli.py list

  # Run SAST scan on source code
  python scripts/cyber_hashira_cli.py run --module sast-source-scanner --input-file src/main.py --format sarif --output report.sarif --fail-on critical

  # Run Secrets scanner
  python scripts/cyber_hashira_cli.py run --module secrets-leak-scanner --input-file .env.example --fail-on high

  # Run Cloud IaC auditor
  python scripts/cyber_hashira_cli.py run --module cloud-iac-security --input-file main.tf --format markdown
"""

import os
import sys
import json
import argparse
import subprocess
import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REGISTRY_PATH = os.path.join(REPO_ROOT, "registry", "v1", "modules.json")
MODULES_DIR = os.path.join(REPO_ROOT, "modules")

def load_catalog():
    if not os.path.isfile(REGISTRY_PATH):
        print(f"[!] Error: Registry catalog not found at {REGISTRY_PATH}")
        sys.exit(1)
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def cmd_list(args):
    catalog = load_catalog()
    modules = catalog.get("modules", [])
    print("=" * 80)
    print(f"CYBER HASHIRA \u2014 REGISTRY MODULE CATALOG ({len(modules)} Modules)")
    print("=" * 80)
    print(f"{'ID':<28} | {'CATEGORY':<20} | {'NAME'}")
    print("-" * 80)
    for m in modules:
        print(f"{m['id']:<28} | {m.get('category', 'Generic'):<20} | {m['name']}")
    print("=" * 80)

def cmd_run(args):
    catalog = load_catalog()
    mod_meta = next((m for m in catalog.get("modules", []) if m["id"] == args.module), None)
    if not mod_meta:
        print(f"[!] Error: Module '{args.module}' not found in registry.")
        sys.exit(1)

    worker_path = os.path.join(MODULES_DIR, args.module, "worker.py")
    if not os.path.isfile(worker_path):
        print(f"[!] Error: Module worker not found at {worker_path}")
        sys.exit(1)

    # Read input payload
    content = ""
    if args.input_file:
        if not os.path.isfile(args.input_file):
            print(f"[!] Error: Input file not found: {args.input_file}")
            sys.exit(1)
        with open(args.input_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    # ScopeGuard setup
    auth_targets = [t.strip() for t in args.authorized_targets.split(",") if t.strip()] if args.authorized_targets else []
    if args.target and not auth_targets:
        auth_targets = [args.target]

    req_payload = {
        "type": "Execute",
        "target": args.target or (args.input_file if args.input_file else ""),
        "content": content,
        "source_code": content,
        "options": {
            "authorized_targets": auth_targets,
            "content": content,
        }
    }

    # Execute worker via stdio JSON-RPC
    proc = subprocess.Popen(
        [sys.executable, worker_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    stdout, stderr = proc.communicate(json.dumps(req_payload) + "\n", timeout=30)
    if proc.returncode != 0:
        print(f"[!] Worker exited with code {proc.returncode}: {stderr}")
        sys.exit(proc.returncode)

    try:
        response = json.loads(stdout.strip())
    except Exception as e:
        print(f"[!] Malformed worker output: {stdout.strip()} ({e})")
        sys.exit(1)

    if response.get("status") == "error":
        print(f"[!] Execution failed: {response.get('message')}")
        sys.exit(1)

    result = response.get("result", {})
    findings = result.get("findings", [])

    # Format output using reporting engine
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from reporting_engine import deduplicate_findings, export_sarif, export_html_report, redact_sensitive_data

    deduped = deduplicate_findings(findings)
    meta = {
        "project_name": f"Cyber Hashira Audit ({mod_meta['name']})",
        "target": args.target or (args.input_file if args.input_file else "Authorized Scope"),
        "module_id": args.module
    }

    output_text = ""
    if args.format == "sarif":
        output_text = export_sarif(deduped, meta)
    elif args.format == "html":
        output_text = export_html_report(deduped, meta)
    elif args.format == "markdown":
        output_text = f"# Audit Report: {mod_meta['name']}\n\n"
        output_text += f"- **Module:** `{args.module}`\n"
        output_text += f"- **Total Findings (Deduplicated):** {len(deduped)}\n\n"
        for idx, f in enumerate(deduped, 1):
            output_text += f"### {idx}. [{f.get('severity', 'MEDIUM').upper()}] {f.get('title', 'Finding')}\n"
            output_text += f"{f.get('description', '')}\n\n"
            if f.get("evidence"):
                output_text += f"```text\n{f['evidence']}\n```\n\n"
            if "remediation" in f:
                output_text += f"> **Remediation:** {f['remediation']}\n\n"
    else:
        output_text = json.dumps({"module": args.module, "total_findings": len(deduped), "findings": deduped}, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_f:
            out_f.write(output_text)
        print(f"[+] Output saved to {args.output}")
    else:
        print(output_text)

    # Check CI gate failure threshold
    if args.fail_on:
        crit_count = sum(1 for f in deduped if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in deduped if f.get("severity", "").lower() in ["critical", "high"])

        if args.fail_on.lower() == "critical" and crit_count > 0:
            print(f"\n[!] CI Gate Blocked: {crit_count} Critical vulnerabilities discovered!")
            sys.exit(2)
        elif args.fail_on.lower() == "high" and high_count > 0:
            print(f"\n[!] CI Gate Blocked: {high_count} Critical/High vulnerabilities discovered!")
            sys.exit(2)

    print(f"\n[+] Scan succeeded without blocking thresholds ({len(deduped)} deduplicated findings).")

def cmd_report(args):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from reporting_engine import deduplicate_findings, export_sarif, export_html_report

    if not os.path.isfile(args.input):
        print(f"[!] Error: Findings input file not found: {args.input}")
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data if isinstance(data, list) else data.get("findings", [])
    deduped = deduplicate_findings(findings)

    meta = {
        "project_name": args.project_name,
        "target": args.target
    }

    if args.format == "sarif":
        content = export_sarif(deduped, meta)
    elif args.format == "html":
        content = export_html_report(deduped, meta)
    else:
        content = json.dumps({"findings": deduped, "total": len(deduped)}, indent=2)

    with open(args.output, "w", encoding="utf-8") as out_f:
        out_f.write(content)

    print(f"[+] Generated {args.format.upper()} report -> {args.output} ({len(deduped)} findings)")

def main():
    parser = argparse.ArgumentParser(description="Cyber Hashira Headless CLI & CI Gate Runner")
    subparsers = parser.add_subparsers(dest="command")

    # List
    subparsers.add_parser("list", help="List all 30 security modules in catalog")

    # Run
    run_parser = subparsers.add_parser("run", help="Run a security module headlessly")
    run_parser.add_argument("--module", required=True, help="Module ID to run")
    run_parser.add_argument("--target", default="", help="Target domain, IP, or URL")
    run_parser.add_argument("--input-file", default="", help="File path to inspect")
    run_parser.add_argument("--authorized-targets", default="", help="Comma-separated allowlist for ScopeGuard")
    run_parser.add_argument("--format", choices=["json", "sarif", "markdown", "html"], default="json", help="Output format")
    run_parser.add_argument("--output", default="", help="Save output to file")
    run_parser.add_argument("--fail-on", choices=["critical", "high"], default="", help="Exit with code 2 if matching severity findings are found")

    # Report
    rep_parser = subparsers.add_parser("report", help="Generate SARIF, HTML or JSON report from findings")
    rep_parser.add_argument("--input", required=True, help="Input JSON findings file")
    rep_parser.add_argument("--format", choices=["html", "sarif", "json"], default="html", help="Report format")
    rep_parser.add_argument("--output", required=True, help="Output file path")
    rep_parser.add_argument("--project-name", default="Cyber Hashira Penetration Test", help="Project title")
    rep_parser.add_argument("--target", default="Enterprise Attack Surface", help="Target label")

    args = parser.parse_args()
    if args.command == "list":
        cmd_list(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
