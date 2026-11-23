# -*- coding: utf-8 -*-
"""
Cyber Hashira — Target Web Spider & Endpoint Crawler Engine
Recursively discovers endpoints, forms, scripts, and parameters on authorized targets.
Strictly enforced by ScopeGuard and logged in the immutable AuditLog.
"""

import re
import time
import urllib.parse
from typing import Dict, Any, List, Set, Optional
from bs4 import BeautifulSoup
import requests
import urllib3

from engine.scopeguard import verify as verify_scope, ScopeViolationError, normalize_target
from engine.audit_log import AuditLogger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebCrawler:
    """Fast, ScopeGuard-protected web spider for web asset & endpoint mapping."""

    def __init__(self):
        self.audit_logger = AuditLogger()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CyberHashira-AssetCrawler/1.3 (+https://github.com/VoidStudioos/Cyber-Hashira)"
        })

    def crawl(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 40,
        authorized_targets: Optional[List[str]] = None,
        timeout: int = 8,
        verify_ssl: bool = False
    ) -> Dict[str, Any]:
        """
        Spiders the given start_url within ScopeGuard boundaries.
        Returns mapped endpoints, query parameters, HTML forms, and API routes.
        """
        start_url = start_url.strip()
        if not start_url.startswith("http://") and not start_url.startswith("https://"):
            start_url = f"https://{start_url}"

        parsed_start = urllib.parse.urlparse(start_url)
        target_host = normalize_target(start_url)
        base_origin = f"{parsed_start.scheme}://{parsed_start.netloc}"

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
                actor="spider-crawler",
                module_id="recon-crawler",
                target=target_host,
                action=f"CRAWL {start_url}",
                scope_approved=False,
                status="BLOCKED_BY_SCOPEGUARD",
                findings_count=0,
                metadata={"reason": str(sve)}
            )
            return {
                "success": False,
                "error": f"ScopeGuard Violation: Target '{target_host}' is not in authorized project scope.",
                "scope_blocked": True,
                "endpoints": [],
                "parameters": [],
                "forms": []
            }

        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(start_url, 0)]
        discovered_endpoints: Set[str] = set()
        discovered_params: Set[str] = set()
        discovered_forms: List[Dict[str, Any]] = []
        seen_forms: Set[tuple[str, str]] = set()
        discovered_scripts: Set[str] = set()

        start_time = time.perf_counter()

        while queue and len(visited) < max_pages:
            current_url, depth = queue.pop(0)
            if current_url in visited:
                continue
            if depth > max_depth:
                continue

            # Ensure URL belongs to the authorized target host
            curr_host = normalize_target(current_url)
            if curr_host != target_host:
                continue

            visited.add(current_url)
            discovered_endpoints.add(urllib.parse.urlparse(current_url).path or "/")

            # Extract any query parameters from current URL
            query_str = urllib.parse.urlparse(current_url).query
            if query_str:
                for k in urllib.parse.parse_qs(query_str).keys():
                    discovered_params.add(k)

            try:
                resp = self.session.get(
                    current_url,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=True
                )
                content_type = resp.headers.get("Content-Type", "").lower()

                # Parse HTML content
                if "html" in content_type:
                    soup = BeautifulSoup(resp.text, "html.parser")

                    # 1. Extract Links
                    for tag in soup.find_all("a", href=True):
                        href = tag["href"].strip()
                        if href.startswith("mailto:") or href.startswith("javascript:") or href.startswith("#"):
                            continue
                        full_url = urllib.parse.urljoin(current_url, href)
                        parsed_href = urllib.parse.urlparse(full_url)
                        if normalize_target(full_url) == target_host:
                            clean_url = urllib.parse.urldefrag(full_url)[0]
                            discovered_endpoints.add(parsed_href.path or "/")
                            if clean_url not in visited and (depth + 1) <= max_depth:
                                queue.append((clean_url, depth + 1))

                    # 2. Extract Forms (vital for CSRF, XSS, and SQLi testing)
                    for form in soup.find_all("form"):
                        action = form.get("action", "")
                        form_url = urllib.parse.urljoin(current_url, action)
                        method = form.get("method", "GET").upper()
                        form_key = (form_url, method)
                        inputs = []
                        for inp in form.find_all(["input", "textarea", "select"]):
                            name = inp.get("name")
                            if name:
                                inputs.append({
                                    "name": name,
                                    "type": inp.get("type", "text"),
                                    "value": inp.get("value", "")
                                })
                                discovered_params.add(name)
                        if form_key not in seen_forms:
                            seen_forms.add(form_key)
                            discovered_forms.append({
                                "action": form_url,
                                "method": method,
                                "inputs": inputs,
                                "source_page": current_url
                            })

                    # 3. Extract Script sources & inline API endpoints
                    for script in soup.find_all("script"):
                        src = script.get("src")
                        if src:
                            script_url = urllib.parse.urljoin(current_url, src)
                            discovered_scripts.add(script_url)
                        elif script.string:
                            # Regex scan inline JS for relative API routes like "/api/v1/users"
                            matches = re.findall(r'["\'](/api/[\w\-/]+|/v\d/[\w\-/]+)["\']', script.string)
                            for m in matches:
                                discovered_endpoints.add(m)

                # Parse JSON responses for API routes
                elif "json" in content_type:
                    discovered_endpoints.add(urllib.parse.urlparse(current_url).path)

            except Exception:
                continue

        elapsed = round(time.perf_counter() - start_time, 2)

        # Record to audit log
        self.audit_logger.record_event(
            actor="spider-crawler",
            module_id="recon-crawler",
            target=target_host,
            action=f"SPIDER_CRAWL {target_host} ({len(visited)} pages)",
            scope_approved=True,
            status="SUCCESS",
            findings_count=len(discovered_endpoints),
            metadata={
                "endpoints_count": len(discovered_endpoints),
                "forms_count": len(discovered_forms),
                "params_count": len(discovered_params),
                "elapsed_sec": elapsed
            }
        )

        return {
            "success": True,
            "target": target_host,
            "base_url": base_origin,
            "pages_crawled": len(visited),
            "visited_urls": sorted(list(visited)),
            "endpoints": sorted(list(discovered_endpoints)),
            "parameters": sorted(list(discovered_params)),
            "forms": discovered_forms,
            "scripts": sorted(list(discovered_scripts)),
            "elapsed_seconds": elapsed
        }
