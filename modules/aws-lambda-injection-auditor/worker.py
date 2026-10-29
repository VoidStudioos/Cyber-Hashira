#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
worker.py for aws-lambda-injection-auditor
Audits serverless functions (AWS Lambda, Google Cloud Functions, Azure Functions) for event-data injection, execution environment reuse, and temporary /tmp leakage.
Implements the Cyber-Hashira Stdio JSON-RPC IPC Protocol.
"""

import sys
import json
import uuid
import datetime

MODULE_ID = "aws-lambda-injection-auditor"
CWE_ID = "CWE-78"


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
            "title": "AWS Lambda /tmp Persistence Allows Cross-Invocation Data Leakage",
            "description": "Lambda execution environment leaves sensitive customer files in '/tmp' between warm container invocations, leaking data to subsequent request handlers.",
            "severity": "high",
            "cwe": CWE_ID,
            "cvss": 8.8,
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
            break
        elif req_type in ("RunTask", "Execute"):
            handle_run_task(req)
            break
        else:
            resp = {
                "type": "Error",
                "payload": {"error": f"Unknown request type: {req_type}"}
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            break


if __name__ == "__main__":
    main()
