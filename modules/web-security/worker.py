#!/usr/bin/env python3
"""
Cyber Hashira - Web Application Security Suite Worker Process
Provides:
  - Scope-aware Repeater Engine (HTTP/1.1 & HTTP/2 request dispatcher)
  - Passive Security & Header Vulnerability Scanner
  - Request/Response Inspector & Normalizer
Communicates via standard Host Stdio JSON-RPC IPC.
"""

import sys
import json
import time
import uuid
import datetime
import urllib.request
import urllib.error
import urllib.parse
import ssl

def log_err(msg):
    sys.stderr.write(f"[web-security] {msg}\n")
    sys.stderr.flush()

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "Web security engine, HTTP repeater, and passive scanner are operational.",
            "details": {
                "ssl_version": ssl.OPENSSL_VERSION,
                "engine": "cyber_hashira_web_core"
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def analyze_headers(target_url, status_code, headers_dict):
    """
    Passive Vulnerability Analysis on HTTP Response Headers:
    Checks for missing HSTS, CSP, X-Frame-Options, Cookie security flags, and banner leakage.
    """
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    norm_headers = {k.lower(): v for k, v in headers_dict.items()}

    # 1. Missing Content-Security-Policy (CSP)
    if "content-security-policy" not in norm_headers:
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "web-security",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "description": f"The endpoint '{target_url}' does not implement a Content-Security-Policy header, leaving the application susceptible to Cross-Site Scripting (XSS) and code injection attacks.",
            "severity": "Medium",
            "cvss_v3": 5.4,
            "cve": None,
            "cwe": "CWE-1021",
            "evidence": "Header 'Content-Security-Policy' is absent from response.",
            "timestamp": now,
            "status": "Open",
            "remediation": "Define a robust Content-Security-Policy restricting allowed sources for scripts, styles, and frames (e.g., default-src 'self').",
            "analyst_notes": "Passive inspection of response headers."
        })

    # 2. Missing Strict-Transport-Security (HSTS) on HTTPS
    is_https = target_url.lower().startswith("https://")
    if is_https and "strict-transport-security" not in norm_headers:
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "web-security",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "description": f"The HTTPS endpoint '{target_url}' lacks the Strict-Transport-Security header, allowing potential SSL-stripping and man-in-the-middle downgrade attacks.",
            "severity": "Medium",
            "cvss_v3": 5.9,
            "cve": None,
            "cwe": "CWE-319",
            "evidence": "Header 'Strict-Transport-Security' is absent from HTTPS response.",
            "timestamp": now,
            "status": "Open",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            "analyst_notes": "Passive check for transport encryption enforcement."
        })

    # 3. Missing X-Frame-Options (Clickjacking)
    if "x-frame-options" not in norm_headers and "content-security-policy" not in norm_headers:
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "web-security",
            "title": "Missing Anti-Clickjacking Protection (X-Frame-Options)",
            "description": f"The page at '{target_url}' can potentially be embedded within an unauthorized iframe, enabling UI redressing and clickjacking attacks.",
            "severity": "Low",
            "cvss_v3": 4.3,
            "cve": None,
            "cwe": "CWE-1021",
            "evidence": "Neither 'X-Frame-Options' nor 'frame-ancestors' directive was found.",
            "timestamp": now,
            "status": "Open",
            "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'.",
            "analyst_notes": "UI redressing defense validation."
        })

    # 4. Missing X-Content-Type-Options
    if "x-content-type-options" not in norm_headers or norm_headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "web-security",
            "title": "Missing X-Content-Type-Options: nosniff",
            "description": f"The response from '{target_url}' does not enforce 'nosniff', allowing legacy browsers to execute MIME sniffing attacks.",
            "severity": "Low",
            "cvss_v3": 3.7,
            "cve": None,
            "cwe": "CWE-79",
            "evidence": f"X-Content-Type-Options: {headers_dict.get('X-Content-Type-Options', 'missing')}",
            "timestamp": now,
            "status": "Open",
            "remediation": "Configure web server to return 'X-Content-Type-Options: nosniff'.",
            "analyst_notes": "MIME confusion prevention check."
        })

    # 5. Information Disclosure in Server or X-Powered-By
    banners = []
    if "server" in norm_headers:
        banners.append(f"Server: {norm_headers['server']}")
    if "x-powered-by" in norm_headers:
        banners.append(f"X-Powered-By: {norm_headers['x-powered-by']}")

    if banners:
        findings.append({
            "id": str(uuid.uuid4()),
            "project_id": None,
            "target_id": None,
            "module_id": "web-security",
            "title": "Web Server Version Banner Disclosure",
            "description": f"The server discloses technology and software version details at '{target_url}': {', '.join(banners)}.",
            "severity": "Informational",
            "cvss_v3": 2.6,
            "cve": None,
            "cwe": "CWE-200",
            "evidence": " / ".join(banners),
            "timestamp": now,
            "status": "Open",
            "remediation": "Suppress detailed version banners in web server configuration files.",
            "analyst_notes": "Passive banner fingerprinting."
        })

    # 6. Cookie Security Inspection (Set-Cookie)
    set_cookies = [v for k, v in headers_dict.items() if k.lower() == "set-cookie"]
    for cookie_header in set_cookies:
        cookie_lower = cookie_header.lower()
        cookie_name = cookie_header.split("=")[0].strip() if "=" in cookie_header else "unknown"

        issues = []
        if "secure" not in cookie_lower and is_https:
            issues.append("Missing 'Secure' flag")
        if "httponly" not in cookie_lower:
            issues.append("Missing 'HttpOnly' flag")
        if "samesite" not in cookie_lower:
            issues.append("Missing 'SameSite' attribute")

        if issues:
            findings.append({
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "web-security",
                "title": f"Insecure Cookie Configuration: {cookie_name}",
                "description": f"Cookie '{cookie_name}' at '{target_url}' lacks recommended security attributes: {', '.join(issues)}.",
                "severity": "Medium",
                "cvss_v3": 5.0,
                "cve": None,
                "cwe": "CWE-614",
                "evidence": f"Set-Cookie: {cookie_header}",
                "timestamp": now,
                "status": "Open",
                "remediation": "Ensure all sensitive session cookies include Secure, HttpOnly, and SameSite=Lax (or Strict).",
                "analyst_notes": "Cookie security flags audit."
            })

    return findings

def execute_repeater_request(target_url, method, req_headers, body_str, timeout_sec=15):
    """Executes an HTTP request and measures timing, returning status, headers, and body preview"""
    start_time = time.time()

    # Create unverified SSL context for authorized security testing
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    data_bytes = body_str.encode("utf-8") if body_str else None
    req = urllib.request.Request(target_url, data=data_bytes, method=method)

    for k, v in req_headers.items():
        req.add_header(k, str(v))

    if "User-Agent" not in req_headers:
        req.add_header("User-Agent", "CyberHashira-SecurityWorkstation/0.1.0")

    status_code = 0
    resp_headers = {}
    resp_body = ""
    error_msg = None

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec, context=ctx) as response:
            status_code = response.status
            resp_headers = dict(response.headers)
            raw_bytes = response.read(65536) # Read up to 64KB
            resp_body = raw_bytes.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status_code = e.code
        resp_headers = dict(e.headers)
        raw_bytes = e.read(65536)
        resp_body = raw_bytes.decode("utf-8", errors="replace")
    except Exception as e:
        error_msg = str(e)

    elapsed_ms = int((time.time() - start_time) * 1000)

    # Automatically analyze response headers for passive security vulnerabilities
    findings = []
    if status_code > 0:
        findings = analyze_headers(target_url, status_code, resp_headers)

    return {
        "status_code": status_code,
        "elapsed_ms": elapsed_ms,
        "headers": resp_headers,
        "body": resp_body,
        "error": error_msg,
        "findings": findings
    }

def handle_run_task(payload):
    task_id = payload.get("task_id", str(uuid.uuid4()))
    target = payload.get("target", "").strip()
    scope_approved = payload.get("scope_approved", False)
    options = payload.get("options", {})

    # 1. Mandatory scope check enforcement
    if not scope_approved:
        resp = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "findings": [],
                "raw_output": None,
                "error": "Execution aborted: Target scope has not been authorized by ScopeGuard."
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        return

    # Normalize target URL
    target_url = target
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"https://{target_url}"

    action = options.get("action", "passive_scan")

    if action == "repeater":
        rep_req = options.get("repeater_request", {})
        method = rep_req.get("method", "GET").upper()
        custom_url = rep_req.get("url", target_url)
        headers = rep_req.get("headers", {})
        body = rep_req.get("body", "")

        result = execute_repeater_request(custom_url, method, headers, body)
        raw_output = f"HTTP {result['status_code']} ({result['elapsed_ms']} ms)\n\nResponse Headers:\n"
        for k, v in result["headers"].items():
            raw_output += f"{k}: {v}\n"
        raw_output += f"\nBody:\n{result['body'][:1000]}"

        resp = {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": result["error"] is None or result["status_code"] > 0,
                "findings": result["findings"],
                "raw_output": raw_output,
                "error": result["error"]
            }
        }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
        return

    if options.get("simulate_vulnerabilities"):
        findings = [
            {
                "id": str(uuid.uuid4()),
                "project_id": None,
                "target_id": None,
                "module_id": "web-security",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "description": f"Target '{target_url}' does not enforce a Content-Security-Policy header.",
                "severity": "Medium",
                "cvss_v3": 5.4,
                "cve": None,
                "cwe": "CWE-693",
                "evidence": "Response headers lack 'Content-Security-Policy'",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "status": "Open",
                "remediation": "Deploy a robust Content-Security-Policy header.",
                "analyst_notes": "Deterministic lab test fixture."
            }
        ]
        probe_result = {"status_code": 200, "elapsed_ms": 15, "error": None}
    else:
        # Default action: Full passive web security inspection
        probe_result = execute_repeater_request(target_url, "GET", {})
        findings = probe_result.get("findings", [])

    raw_output = (
        f"=== Cyber Hashira Passive Web Security Assessment for {target_url} ===\n"
        f"Status: HTTP {probe_result['status_code']} in {probe_result['elapsed_ms']} ms\n"
        f"Passive Vulnerabilities Detected: {len(findings)}\n"
    )
    for idx, f in enumerate(findings, 1):
        raw_output += f" [{idx}] [{f['severity']}] {f['title']}\n"

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": findings,
            "raw_output": raw_output,
            "error": probe_result.get("error")
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
            req_type = req.get("type")
            payload = req.get("payload", {})

            if req_type == "HealthCheck":
                handle_health_check()
                break
            elif req_type == "RunTask":
                handle_run_task(payload)
                break
            else:
                err_resp = {
                    "type": "Error",
                    "payload": {
                        "message": f"Unknown request type: {req_type}",
                        "code": "INVALID_REQUEST"
                    }
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                break
        except Exception as e:
            err_resp = {
                "type": "Error",
                "payload": {
                    "message": str(e),
                    "code": "EXCEPTION"
                }
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
            break

if __name__ == "__main__":
    main()
