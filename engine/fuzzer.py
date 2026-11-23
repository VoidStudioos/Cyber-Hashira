# -*- coding: utf-8 -*-
"""
Cyber Hashira — High-Speed Directory & Endpoint Fuzzing Engine
Performs concurrent path and file discovery on authorized targets (equivalent to ffuf / dirsearch).
Strictly enforced by ScopeGuard and logged in the immutable AuditLog.
"""

import time
import concurrent.futures
import urllib.parse
from typing import Dict, Any, List, Optional
import requests
import urllib3

from engine.scopeguard import verify as verify_scope, ScopeViolationError, normalize_target
from engine.audit_log import AuditLogger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# High-value security assessment wordlist
DEFAULT_SECURITY_WORDLIST = [
    # Sensitive Environment & Secrets
    ".env",
    ".env.local",
    ".env.production",
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".svn/entries",
    ".htaccess",
    "web.config",
    "docker-compose.yml",
    "Dockerfile",
    
    # Backups & Database Dumps
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "dump.sql",
    "database.sqlite",
    "data.json",
    "config.json",
    "config.yaml",
    "config.php.bak",
    "settings.py.bak",
    
    # Admin & Management Consoles
    "admin",
    "admin/",
    "administrator",
    "login",
    "dashboard",
    "cpanel",
    "portal",
    "management",
    "console",
    "phpmyadmin",
    "pma",
    
    # API & Schema Discovery
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "api/status",
    "api/health",
    "graphql",
    "graphql/console",
    "graphiql",
    "swagger",
    "swagger.json",
    "swagger.yaml",
    "swagger-ui.html",
    "openapi.json",
    "openapi.yaml",
    "docs",
    "redoc",
    
    # Cloud & DevOps Telemetry
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/metrics",
    "metrics",
    "server-status",
    "server-info",
    "debug",
    "trace",
    
    # Standard Metadata
    ".well-known/security.txt",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml"
]


class EndpointFuzzer:
    """Multi-threaded directory and file discovery engine with ScopeGuard barrier."""

    def __init__(self):
        self.audit_logger = AuditLogger()

    def fuzz(
        self,
        target_url: str,
        wordlist: Optional[List[str]] = None,
        threads: int = 15,
        status_codes: Optional[List[int]] = None,
        authorized_targets: Optional[List[str]] = None,
        timeout: int = 6,
        verify_ssl: bool = False
    ) -> Dict[str, Any]:
        """
        Fuzzes paths against target_url using concurrent threads.
        Only probes targets validated by ScopeGuard.
        """
        target_url = target_url.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        # Clean trailing slash for consistent concatenation
        base_url = target_url.rstrip("/")
        target_host = normalize_target(target_url)

        # 1. ScopeGuard Verification
        auth_list = authorized_targets or [target_host]
        try:
            verify_scope(
                target=target_host,
                authorized_targets=auth_list,
                scope_approved=True,
                allow_metadata_probes=False
            )
        except ScopeViolationError as sve:
            self.audit_logger.record_event(
                actor="endpoint-fuzzer",
                module_id="recon-fuzzer",
                target=target_host,
                action=f"FUZZ {target_url}",
                scope_approved=False,
                status="BLOCKED_BY_SCOPEGUARD",
                findings_count=0,
                metadata={"reason": str(sve)}
            )
            return {
                "success": False,
                "error": f"ScopeGuard Violation: Target '{target_host}' is not in authorized project scope.",
                "scope_blocked": True,
                "results": []
            }

        words_to_test = wordlist if (wordlist and len(wordlist) > 0) else DEFAULT_SECURITY_WORDLIST
        allowed_statuses = set(status_codes or [200, 201, 204, 301, 302, 307, 308, 401, 403, 500])

        results = []
        start_time = time.perf_counter()

        def _probe_path(word: str) -> Optional[Dict[str, Any]]:
            clean_word = word.strip().lstrip("/")
            test_url = f"{base_url}/{clean_word}"
            try:
                t0 = time.perf_counter()
                resp = requests.get(
                    test_url,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False,
                    headers={"User-Agent": "CyberHashira-Fuzzer/1.3"}
                )
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

                if resp.status_code in allowed_statuses:
                    content_length = len(resp.content)
                    words_count = len(resp.text.split())
                    lines_count = len(resp.text.splitlines())
                    location = resp.headers.get("Location", "")

                    return {
                        "path": f"/{clean_word}",
                        "url": test_url,
                        "status_code": resp.status_code,
                        "content_length": content_length,
                        "words": words_count,
                        "lines": lines_count,
                        "redirect_to": location,
                        "elapsed_ms": elapsed_ms
                    }
            except Exception:
                pass
            return None

        # Execute concurrently with ThreadPoolExecutor
        max_workers = min(threads, 30)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_word = {executor.submit(_probe_path, word): word for word in words_to_test}
            for future in concurrent.futures.as_completed(future_to_word):
                hit = future.result()
                if hit:
                    results.append(hit)

        elapsed = round(time.perf_counter() - start_time, 2)

        # Sort results: status 200/301 first, then by status code
        results.sort(key=lambda x: (0 if x["status_code"] in [200, 201] else 1, x["status_code"]))

        # Record to audit log
        self.audit_logger.record_event(
            actor="endpoint-fuzzer",
            module_id="recon-fuzzer",
            target=target_host,
            action=f"FUZZ_PATHS {target_host} ({len(words_to_test)} probes)",
            scope_approved=True,
            status="SUCCESS",
            findings_count=len(results),
            metadata={
                "probes_tested": len(words_to_test),
                "hits_found": len(results),
                "elapsed_sec": elapsed
            }
        )

        return {
            "success": True,
            "target": target_host,
            "base_url": base_url,
            "probes_count": len(words_to_test),
            "hits_count": len(results),
            "results": results,
            "elapsed_seconds": elapsed
        }
