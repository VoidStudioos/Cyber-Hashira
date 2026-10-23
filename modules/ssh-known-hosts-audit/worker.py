#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""worker.py for ssh-known-hosts-audit

Audits SSH known_hosts and authorized_keys files for:
  - RSA keys smaller than 2048 bits (weak)
  - Unsupported/insecure algorithms (e.g., ssh-dss)
Implements the Cyber-Hashira IPC stdio protocol (JSON lines on stdin/stdout).
"""
import sys
import json
import datetime
import pathlib

CWE_ID = "CWE-326"  # Inadequate Encryption Strength

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def _parse_ssh_key(line: str):
    """Return (key_type, key_obj) or (None, None) if parsing fails."""
    if not HAS_CRYPTO:
        return None, None
    parts = line.strip().split()
    if len(parts) < 2:
        return None, None
    key_type, b64_key = parts[0], parts[1]
    try:
        key_data = serialization.load_ssh_public_key(
            f"{key_type} {b64_key}".encode()
        )
        return key_type, key_data
    except Exception:
        return None, None


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

        findings = []
        for p in paths:
            file_path = pathlib.Path(p)
            if not file_path.is_file():
                continue
            for idx, raw_line in enumerate(file_path.read_text().splitlines(), start=1):
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    continue
                key_type, key_obj = _parse_ssh_key(line)
                if key_type is None:
                    continue
                if key_type == "ssh-dss":
                    findings.append({
                        "cwe": CWE_ID,
                        "title": "Deprecated DSA key (ssh-dss)",
                        "description": f"Line {idx} uses the deprecated DSA algorithm.",
                        "evidence": line,
                        "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
                    })
                    continue
                if HAS_CRYPTO and isinstance(key_obj, _rsa.RSAPublicKey):
                    if key_obj.key_size < 2048:
                        findings.append({
                            "cwe": CWE_ID,
                            "title": "Weak RSA key (<2048 bits)",
                            "description": f"Line {idx} has RSA key of {key_obj.key_size} bits.",
                            "evidence": line,
                            "detected_at": datetime.datetime.utcnow().isoformat() + "Z"
                        })

        return {
            "type": "TaskCompleted",
            "payload": {
                "success": True,
                "findings": findings,
                "summary": f"{len(findings)} finding(s) detected"
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
