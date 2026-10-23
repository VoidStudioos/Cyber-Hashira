#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""worker.py for password-reuse-detector

Scans a list of files for reused passwords across multiple files.
Implements the Cyber-Hashira IPC stdio protocol (JSON lines on stdin/stdout).
"""
import sys
import json
import datetime
import pathlib
from collections import defaultdict


def handle_health_check(_msg):
    return {"type": "HealthCheckResult", "payload": {"healthy": True, "status": "ok"}}


def handle_run_task(msg):
    # --- Scope guard ---
    payload = msg.get("payload", {})
    target = msg.get("target") or payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    authorized_targets = msg.get("authorized_targets") or payload.get("options", {}).get("authorized_targets", [])

    if not scope_approved or (authorized_targets and target not in authorized_targets):
        return {
            "type": "TaskCompleted",
            "payload": {
                "success": False,
                "error": "unauthorized: target not in approved scope",
                "findings": []
            }
        }

    # --- Core logic ---
    try:
        opts = payload.get("options", {})
        paths = opts.get("paths", [])

        password_map = defaultdict(set)
        for p in paths:
            f = pathlib.Path(p)
            if not f.is_file():
                continue
            for line in f.read_text().splitlines():
                pwd = line.strip()
                if pwd:
                    password_map[pwd].add(str(f))

        findings = []
        for pwd, files in password_map.items():
            if len(files) > 1:
                findings.append({
                    "cwe": "CWE-613",
                    "title": "Reused password across multiple files",
                    "description": f"The same password appears in {len(files)} files.",
                    "evidence": f"Password: '{pwd}' found in: {', '.join(sorted(files))}",
                    "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
                })

        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": findings,
                "summary": f"{len(findings)} reuse finding(s) detected"
            }
        }
    except Exception as e:
        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": [],
                "summary": f"Error during scan: {e}"
            }
        }


def main():
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except Exception:
            sys.stdout.write(json.dumps({"type": "Error", "error": "invalid JSON"}) + "\n")
            sys.stdout.flush()
            continue

        msg_type = msg.get("type", "")
        if msg_type == "HealthCheck":
            response = handle_health_check(msg)
        elif msg_type in ("RunTask", "Execute"):
            response = handle_run_task(msg)
        else:
            response = {"type": "Error", "error": f"unknown message type: {msg_type}"}

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
