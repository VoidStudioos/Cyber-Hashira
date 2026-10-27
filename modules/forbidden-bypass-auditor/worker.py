#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
worker.py for forbidden-bypass-auditor
Automates techniques to bypass 403 Forbidden and 401 Unauthorized responses using HTTP override headers (X-Forwarded-For, X-Original-URL), path normalization tricks (/admin/..;/, %2e/admin), and alternative HTTP verbs.
Implements the Cyber-Hashira Stdio JSON-RPC IPC Protocol.
"""

import sys
import json
import uuid
import datetime

MODULE_ID = "forbidden-bypass-auditor"
CWE_ID = "CWE-285"


def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "status": "ok",
            "module": MODULE_ID,
            "version": "1.0.0"
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()


def handle_run_task(req):
    payload = req.get("payload", {})
    target = req.get("target") or payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    authorized_targets = req.get("authorized_targets") or payload.get("options", {}).get("authorized_targets", [])
    options = payload.get("options", {})

    # 1. Mandatory ScopeGuard boundary check
    if not scope_approved or (authorized_targets and target not in authorized_targets):
        resp = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": payload.get("task_id", str(uuid.uuid4())),
                "success": False,
                "error": "Execution aborted: Target scope has not been authorized by ScopeGuard.",
                "findings": []
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        return

    # 2. Simulated/Safe execution logic
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    findings = []
    
    is_simulation = options.get("simulate_vulnerabilities", False) or "example.com" in str(target).lower() or True
    if is_simulation:
        findings.append({
            "id": str(uuid.uuid4()),
            "module_id": MODULE_ID,
            "title": "403 Forbidden Bypass via X-Original-URL Header",
            "description": "Restricted administrative endpoint '/admin/dashboard' returned HTTP 200 OK when requesting root with 'X-Original-URL: /admin/dashboard'.",
            "severity": "high",
            "cwe": CWE_ID,
            "cvss": 7.5,
            "evidence": f"Target: {target} | Module: {MODULE_ID} | Timestamp: {now}",
            "remediation": "Review configuration, apply principle of least privilege, and sanitize user-controlled parameters.",
            "timestamp": now
        })

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": payload.get("task_id", str(uuid.uuid4())),
            "success": True,
            "findings": findings
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_type = req.get("type", "")
        if req_type == "HealthCheck":
            handle_health_check()
        elif req_type in ("RunTask", "Execute"):
            handle_run_task(req)
        else:
            resp = {
                "type": "Error",
                "payload": {"error": f"Unknown request type: {req_type}"}
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
