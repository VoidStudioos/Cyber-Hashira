# -*- coding: utf-8 -*-
"""
Cyber Hashira — Immutable Cryptographic Audit Log Subsystem
Records all scan executions, actor actions, target interactions, and outcomes
in an append-only JSONL log with tamper-evident cryptographic hash chaining.
"""

import os
import sys
import json
import time
import uuid
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOG_PATH = REPO_ROOT / "logs" / "audit.jsonl"


class AuditLogger:
    """Manages an append-only cryptographic hash-chained security audit log."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path or DEFAULT_LOG_PATH
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._get_last_record_hash()

    def _get_last_record_hash(self) -> str:
        """Reads the hash of the last recorded log entry, or returns genesis hash."""
        if not self.log_path.is_file() or self.log_path.stat().st_size == 0:
            return "0" * 64

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                last_line = ""
                for line in f:
                    if line.strip():
                        last_line = line.strip()
                if last_line:
                    data = json.loads(last_line)
                    return data.get("record_hash", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def record_event(
        self,
        actor: str,
        module_id: str,
        target: str,
        action: str,
        scope_approved: bool,
        status: str,
        findings_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Appends an event to the immutable audit log and computes its chained SHA-256 hash.
        """
        event_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        record = {
            "event_id": event_id,
            "timestamp": now_iso,
            "actor": actor or "system_operator",
            "module_id": module_id,
            "target": target,
            "action": action,
            "scope_approved": scope_approved,
            "status": status,
            "findings_count": findings_count,
            "metadata": metadata or {},
            "prev_hash": self._last_hash
        }

        # Calculate cryptographic hash over canonical record
        canonical_str = json.dumps(record, sort_keys=True)
        record_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        record["record_hash"] = record_hash

        # Atomic append to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        self._last_hash = record_hash
        return record

    def verify_chain_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """
        Verifies the cryptographic hash-chain across all recorded audit entries.
        Returns: (is_valid, records_verified, error_message)
        """
        if not self.log_path.is_file():
            return True, 0, None

        records_count = 0
        expected_prev_hash = "0" * 64

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except Exception as e:
                    return False, records_count, f"Line {line_no} malformed JSON: {e}"

                stored_hash = entry.get("record_hash")
                stored_prev = entry.get("prev_hash")

                if stored_prev != expected_prev_hash:
                    return False, records_count, f"Line {line_no} hash break! Expected prev_hash {expected_prev_hash}, got {stored_prev}"

                # Recompute hash
                check_entry = dict(entry)
                check_entry.pop("record_hash", None)
                recomputed = hashlib.sha256(json.dumps(check_entry, sort_keys=True).encode("utf-8")).hexdigest()

                if recomputed != stored_hash:
                    return False, records_count, f"Line {line_no} signature mismatch! Tampered record."

                expected_prev_hash = stored_hash
                records_count += 1

        return True, records_count, None


# Singleton instance
audit_logger = AuditLogger()
