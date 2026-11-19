# -*- coding: utf-8 -*-
"""
Cyber Hashira — Interactive Repeater & HTTP Request Dispatcher Subsystem
Enables manual and interactive crafting, sending, and diffing of HTTP/HTTPS requests
for web security analysis and authorized bug bounty research.
Strictly enforced by ScopeGuard and logged in the immutable cryptographic AuditLog.
"""

import os
import sys
import json
import time
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.parse
import requests

from engine.scopeguard import verify as verify_scope, ScopeViolationError, normalize_target
from engine.audit_log import AuditLogger

REPO_ROOT = Path(__file__).resolve().parent.parent
HISTORY_FILE = REPO_ROOT / "evidence_vault" / "repeater_history.json"


class RepeaterEngine:
    """Manages crafting, sending, and history of interactive security requests."""

    def __init__(self, history_file: Optional[Path] = None):
        self.history_file = history_file or HISTORY_FILE
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        self.audit_logger = AuditLogger()
        self._history: List[Dict[str, Any]] = self._load_history()

    def _load_history(self) -> List[Dict[str, Any]]:
        """Loads past repeater sessions from disk."""
        if not self.history_file.is_file():
            return []
        try:
            with open(self.history_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            return []

    def _save_history(self):
        """Persists repeater sessions to disk (capped at last 100 items)."""
        try:
            with open(self.history_file, "w", encoding="utf-8") as f:
                json.dump(self._history[-100:], f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[!] Warning: Failed to save repeater history: {e}")

    def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        authorized_targets: Optional[List[str]] = None,
        timeout: int = 15,
        verify_ssl: bool = False,
        allow_redirects: bool = True
    ) -> Dict[str, Any]:
        """
        Validates target authorization with ScopeGuard and dispatches the HTTP request.
        Returns detailed telemetry, status code, response headers, and body.
        """
        method = (method or "GET").upper().strip()
        url = (url or "").strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        # 1. ScopeGuard Verification
        target_host = normalize_target(url)
        try:
            verify_scope(
                target=target_host,
                authorized_targets=authorized_targets,
                scope_approved=True,
                allow_metadata_probes=False
            )
        except ScopeViolationError as sve:
            self.audit_logger.record_event(
                actor="repeater-operator",
                module_id="repeater-studio",
                target=target_host,
                action=f"{method} {url}",
                scope_approved=False,
                status="BLOCKED_BY_SCOPEGUARD",
                findings_count=0,
                metadata={"reason": str(sve)}
            )
            return {
                "success": False,
                "error": f"ScopeGuard Violation: Target '{target_host}' is not in authorized project scope.",
                "status_code": 403,
                "scope_blocked": True
            }

        # 2. Prepare headers & body
        prepared_headers = headers or {}
        if "User-Agent" not in prepared_headers and "user-agent" not in prepared_headers:
            prepared_headers["User-Agent"] = "CyberHashira-SecurityWorkstation/1.2"

        data_bytes = None
        if body is not None and method in ["POST", "PUT", "PATCH", "DELETE"]:
            data_bytes = body.encode("utf-8", errors="replace")

        # 3. Dispatch HTTP request with latency profiling
        start_time = time.perf_counter()
        try:
            # Disable urllib3 insecure request warnings for self-signed certificates
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            resp = requests.request(
                method=method,
                url=url,
                headers=prepared_headers,
                data=data_bytes,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=allow_redirects
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            resp_headers = dict(resp.headers)
            content_length = len(resp.content)
            
            # Safe body text extraction (handle binary vs text)
            try:
                body_text = resp.text
            except Exception:
                body_text = f"[Binary payload: {content_length} bytes]"

            result_item = {
                "id": str(uuid.uuid4())[:8],
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "success": True,
                "request": {
                    "method": method,
                    "url": url,
                    "headers": prepared_headers,
                    "body": body or "",
                    "size_bytes": len(data_bytes) if data_bytes else 0
                },
                "response": {
                    "status_code": resp.status_code,
                    "reason": resp.reason,
                    "headers": resp_headers,
                    "body": body_text,
                    "size_bytes": content_length,
                    "elapsed_ms": elapsed_ms
                }
            }

            # 4. Record to Audit Log & History
            self.audit_logger.record_event(
                actor="repeater-operator",
                module_id="repeater-studio",
                target=target_host,
                action=f"{method} {url}",
                scope_approved=True,
                status=f"HTTP_{resp.status_code}",
                findings_count=0,
                metadata={"elapsed_ms": elapsed_ms, "status_code": resp.status_code}
            )

            self._history.append(result_item)
            self._save_history()

            return result_item

        except requests.exceptions.Timeout:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "success": False,
                "error": f"Request Timed Out after {timeout} seconds",
                "status_code": 504,
                "elapsed_ms": elapsed_ms
            }
        except requests.exceptions.SSLError as ssl_err:
            return {
                "success": False,
                "error": f"SSL/TLS Certificate Error: {ssl_err}. Try disabling 'Verify SSL' for test labs.",
                "status_code": 495
            }
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "success": False,
                "error": f"Connection Failure: {str(e)}",
                "status_code": 502,
                "elapsed_ms": elapsed_ms
            }

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns the list of past repeater executions."""
        return list(reversed(self._history[-limit:]))

    def clear_history(self):
        """Clears stored session history."""
        self._history = []
        self._save_history()
