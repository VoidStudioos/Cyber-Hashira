# -*- coding: utf-8 -*-
"""
Cyber Hashira — Technology & Security Header Fingerprinting Engine
Identifies web frameworks, servers, CMS, and missing defensive headers on authorized targets.
Strictly enforced by ScopeGuard and logged in the immutable AuditLog.
"""

import re
import time
import urllib.parse
from typing import Dict, Any, List, Optional
import requests
import urllib3
from bs4 import BeautifulSoup

from engine.scopeguard import verify as verify_scope, ScopeViolationError, normalize_target
from engine.audit_log import AuditLogger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TechFingerprinter:
    """Detects web application technologies, frameworks, and security header posture."""

    def __init__(self):
        self.audit_logger = AuditLogger()

    def fingerprint(
        self,
        target_url: str,
        authorized_targets: Optional[List[str]] = None,
        timeout: int = 8,
        verify_ssl: bool = False
    ) -> Dict[str, Any]:
        """Analyzes HTTP headers and HTML markup to identify software stack and defensive posture."""
        target_url = target_url.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

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
                actor="fingerprint-engine",
                module_id="recon-fingerprint",
                target=target_host,
                action=f"FINGERPRINT {target_url}",
                scope_approved=False,
                status="BLOCKED_BY_SCOPEGUARD",
                findings_count=0,
                metadata={"reason": str(sve)}
            )
            return {
                "success": False,
                "error": f"ScopeGuard Violation: Target '{target_host}' is not in authorized project scope.",
                "scope_blocked": True,
                "technologies": [],
                "security_headers": {}
            }

        start_time = time.perf_counter()
        technologies = set()
        detected_details: Dict[str, str] = {}

        try:
            resp = requests.get(
                target_url,
                timeout=timeout,
                verify=verify_ssl,
                headers={"User-Agent": "CyberHashira-Fingerprint/1.3"}
            )
        except Exception as e:
            return {
                "success": False,
                "error": f"Connection failed to target '{target_host}': {str(e)}",
                "scope_blocked": False
            }

        headers = resp.headers
        html_text = resp.text

        # 1. Header-based detection
        server_header = headers.get("Server", "")
        if server_header:
            technologies.add("Web Server: " + server_header.split("/")[0])
            detected_details["Server"] = server_header

        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            technologies.add("Framework/Language: " + powered_by)
            detected_details["X-Powered-By"] = powered_by

        if "X-AspNet-Version" in headers or "X-AspNetMvc-Version" in headers:
            technologies.add("Framework: ASP.NET")
        if "X-Generator" in headers:
            technologies.add("Generator: " + headers["X-Generator"])

        # Cloud & CDN
        if "CF-RAY" in headers or "cloudflare" in server_header.lower():
            technologies.add("CDN/Proxy: Cloudflare")
        if "X-Amz-Cf-Id" in headers:
            technologies.add("CDN: AWS CloudFront")
        if "X-Varnish" in headers:
            technologies.add("Cache: Varnish")
        if "X-Cache" in headers:
            detected_details["Cache"] = headers["X-Cache"]

        # 2. HTML Markup & Metadata
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            meta_gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
            if meta_gen and meta_gen.get("content"):
                gen_val = meta_gen.get("content").strip()
                technologies.add(f"CMS/Platform: {gen_val}")

            # Common signatures in HTML
            if "wp-content" in html_text or "wp-includes" in html_text:
                technologies.add("CMS: WordPress")
            if "drupal.js" in html_text or "Drupal.settings" in html_text:
                technologies.add("CMS: Drupal")
            if "laravel" in html_text.lower():
                technologies.add("Framework: Laravel")
            if "__NEXT_DATA__" in html_text:
                technologies.add("Framework: Next.js (React)")
            if "__NUXT__" in html_text:
                technologies.add("Framework: Nuxt.js (Vue)")
            if "ng-version" in html_text or "ng-app" in html_text:
                technologies.add("Framework: Angular")
            if "react-root" in html_text or "_reactListening" in html_text:
                technologies.add("Library: React")
            if "bootstrap.min.css" in html_text:
                technologies.add("UI Framework: Bootstrap")
            if "tailwind" in html_text.lower():
                technologies.add("UI Framework: Tailwind CSS")
        except Exception:
            pass

        # 3. Security Headers Posture Audit
        expected_sec_headers = [
            ("Strict-Transport-Security", "Enforces HTTPS connections and prevents MITM downgrade attacks."),
            ("Content-Security-Policy", "Restricts resource loading to mitigate XSS and data injection."),
            ("X-Content-Type-Options", "Prevents MIME-sniffing vulnerabilities (expected: nosniff)."),
            ("X-Frame-Options", "Defends against clickjacking (expected: DENY or SAMEORIGIN)."),
            ("Referrer-Policy", "Limits referrer leakage in HTTP headers."),
            ("Permissions-Policy", "Restricts browser feature delegations (camera, microphone, geolocation).")
        ]

        sec_header_audit = []
        for name, desc in expected_sec_headers:
            present = name in headers
            val = headers.get(name, "")
            sec_header_audit.append({
                "header": name,
                "status": "PASS" if present else "MISSING",
                "value": val,
                "description": desc
            })

        # Calculate security posture score
        passed_count = sum(1 for h in sec_header_audit if h["status"] == "PASS")
        total_sec = len(expected_sec_headers)
        posture_score = int((passed_count / total_sec) * 100)

        elapsed = round(time.perf_counter() - start_time, 2)

        # Record to audit log
        self.audit_logger.record_event(
            actor="fingerprint-engine",
            module_id="recon-fingerprint",
            target=target_host,
            action=f"TECH_FINGERPRINT {target_host} ({len(technologies)} techs)",
            scope_approved=True,
            status="SUCCESS",
            findings_count=len(technologies),
            metadata={
                "technologies_found": list(technologies),
                "posture_score": posture_score,
                "elapsed_sec": elapsed
            }
        )

        return {
            "success": True,
            "target": target_host,
            "url": target_url,
            "technologies": sorted(list(technologies)),
            "server_details": detected_details,
            "security_headers": sec_header_audit,
            "posture_score": posture_score,
            "elapsed_seconds": elapsed
        }
