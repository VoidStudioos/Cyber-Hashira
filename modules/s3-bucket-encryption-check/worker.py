#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""worker.py for s3-bucket-encryption-check

Check if S3 buckets use SSE-AES256 or KMS server-side encryption.
Implements the Cyber-Hashira IPC stdio protocol (JSON lines on stdin/stdout).
"""
import sys
import json
import datetime
import re

CWE_ID = "CWE-311"
MODULE_ID = "s3-bucket-encryption-check"


def _scan(target: str, options: dict) -> list:
    """Core scanning logic. Returns a list of finding dicts."""
    findings = []
    # ── rule-based checks ────────────────────────────────────────────────────
    # TODO: add real detection logic here
    # Example structure:
    # findings.append({
    #     "cwe": CWE_ID,
    #     "title": "Example Finding",
    #     "description": "Details about the finding.",
    #     "evidence": target,
    #     "severity": "medium",
    #     "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
    # })
    return findings


def handle_health_check(_msg: dict) -> dict:
    return {"type": "HealthCheckResult", "payload": {"healthy": True, "status": "ok"}}


def handle_run_task(msg: dict) -> dict:
    payload = msg.get("payload", {})
    target = msg.get("target") or payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    authorized_targets = (
        msg.get("authorized_targets")
        or payload.get("options", {}).get("authorized_targets", [])
    )

    # Scope guard
    if not scope_approved or (authorized_targets and target not in authorized_targets):
        return {
            "type": "TaskCompleted",
            "payload": {
                "success": False,
                "error": "unauthorized: target not in approved scope",
                "findings": []
            }
        }

    try:
        opts = payload.get("options", {})
        findings = _scan(target, opts)
        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": findings,
                "summary": f"{len(findings)} finding(s) detected for {MODULE_ID}"
            }
        }
    except Exception as exc:
        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": [],
                "summary": f"Scan error: {exc}"
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
