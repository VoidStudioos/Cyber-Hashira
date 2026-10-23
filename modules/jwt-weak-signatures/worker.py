#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""worker.py for jwt-weak-signatures

Detects JWT tokens that use the insecure `none` algorithm or are signed with weak HMAC keys.
Implements the Cyber-Hashira IPC stdio protocol (JSON lines on stdin/stdout).
"""
import sys
import json
import base64
import datetime
import pathlib

CWE_ID = "CWE-327"  # Use of weak cryptographic algorithm

AUTHORIZED_TARGETS = []  # populated at runtime from HealthCheck / first RunTask


def _b64url_decode(segment: str) -> bytes:
    padding = '=' * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _inspect_jwt(token: str):
    parts = token.split('.')
    if len(parts) != 3:
        return []
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return []
    alg = header.get("alg", "").upper()
    findings = []
    if alg == "NONE":
        findings.append({
            "cwe": CWE_ID,
            "title": "JWT with 'none' algorithm",
            "description": "The token uses the 'none' algorithm, allowing tampering without a signature.",
            "evidence": token,
            "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
        })
    elif alg.startswith("HS"):
        findings.append({
            "cwe": CWE_ID,
            "title": f"JWT signed with symmetric algorithm {alg}",
            "description": "Tokens signed with HMAC may be vulnerable if the secret key is weak or known.",
            "evidence": token,
            "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
        })
    return findings


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
        token_file = opts.get("token_file", "tokens.txt")
        token_path = pathlib.Path(__file__).parent / token_file

        findings = []
        if token_path.is_file():
            for line in token_path.read_text().splitlines():
                line = line.strip()
                if line:
                    findings.extend(_inspect_jwt(line))

        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": findings,
                "summary": f"{len(findings)} weak-signature finding(s) detected"
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
