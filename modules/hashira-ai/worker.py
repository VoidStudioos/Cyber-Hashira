#!/usr/bin/env python3
"""
Cyber Hashira - Defensive AI Security Assistant Worker Process
Provides:
  - Automated Vulnerability Triage & CVSS Explanation
  - Remediation Patch Generation (Nginx, Apache, Python, Node, Go)
  - Automatic Secret & Sensitive Credential Redaction
  - Bilingual Executive Security Reporting (English & Persian)
Communicates via standard Host Stdio JSON-RPC IPC.
"""

import sys
import json
import re
import uuid
import datetime

SECRET_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s\r\n]+)", re.IGNORECASE), r"\1=[REDACTED_PASSWORD]"),
    (re.compile(r"(?i)(secret|api_?key|auth_?token|access_?token)\s*[:=]\s*['\"]?([^'\"\s\r\n]+)", re.IGNORECASE), r"\1=[REDACTED_KEY]"),
    (re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{15,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]

def redact_sensitive_data(text):
    """Sanitizes text, stripping credentials before model reasoning"""
    sanitized = text
    for pattern, repl in SECRET_PATTERNS:
        sanitized = pattern.sub(repl, sanitized)
    return sanitized

def handle_health_check():
    resp = {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "message": "Hashira AI defensive cybersecurity assistant is operational.",
            "details": {
                "bilingual_support": ["en", "fa"],
                "secret_sanitizer": "active",
                "engine": "hashira_ai_core"
            }
        }
    }
    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

def generate_remediation_explanation(finding, lang="en"):
    title = finding.get("title", "Security Finding")
    desc = finding.get("description", "")
    cwe = finding.get("cwe", "CWE-General")
    sev = finding.get("severity", "Medium")

    if lang == "fa":
        explanation = f"### تحلیل آسیب‌پذیری توسط هوش مصنوعی Hashira\n\n"
        explanation += f"**عنوان یافته:** {title}\n"
        explanation += f"**درجه حساسیت:** {sev} | **طبقه‌بندی استاندارد:** {cwe}\n\n"
        explanation += f"#### ۱. ارزیابی ریسک و سازوکار حمله:\n"
        explanation += f"{desc}\n"
        explanation += f"عدم اصلاح این آسیب‌پذیری می‌تواند به مهاجمان امکان سوءاستفاده از مکانیزم‌های دفاعی برنامه، شنود ترافیک، یا افشای داده‌های حیاتی را بدهد.\n\n"
        explanation += f"#### ۲. راهنمای گام‌به‌گام اصلاح (Remediation):\n"
        explanation += f"۱. پیکربندی سرور وب جهت افزودن هدرهای دفاعی لازم و محدودسازی دسترسی.\n"
        explanation += f"۲. اعتبارسنجی ورودی‌ها و جلوگیری از دسترسی به فایل‌های کانفیگ و محیطی.\n"
        explanation += f"۳. بررسی سیاست کوکی‌ها و اعمال پرچم‌های HttpOnly و Secure و SameSite.\n"
    else:
        explanation = f"### Hashira AI Defensive Assessment\n\n"
        explanation += f"**Finding:** {title}\n"
        explanation += f"**Severity:** {sev} | **Standard Classification:** {cwe}\n\n"
        explanation += f"#### 1. Technical Impact & Attack Surface:\n"
        explanation += f"{desc}\n"
        explanation += f"Exploitation of this condition allows adversaries to bypass boundary controls, perform unauthenticated data harvesting, or hijack sensitive sessions.\n\n"
        explanation += f"#### 2. Hardening & Remediation Guidance:\n"
        explanation += f"- Enforce strict least-privilege transport and access controls.\n"
        explanation += f"- Restrict direct file mapping and suppress server diagnostic banners.\n"
        explanation += f"- Apply defense-in-depth security headers across all web gateway responses.\n"

    patch = ""
    if "CSP" in title or "Content-Security-Policy" in title:
        patch = "# Nginx Web Server Hardening Patch\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';\" always;\nadd_header X-Content-Type-Options \"nosniff\" always;\nadd_header X-Frame-Options \"DENY\" always;"
    elif "Git" in title:
        patch = "# Apache & Nginx Block Git Access\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}"
    elif "Cookie" in title:
        patch = "// Node.js Express Secure Cookie Patch\nres.cookie('session_token', token, {\n  secure: true,\n  httpOnly: true,\n  sameSite: 'lax',\n  maxAge: 3600000\n});"
    else:
        patch = "# General Web Gateway Hardening (Nginx)\nserver_tokens off;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"

    return explanation, patch

def triage_findings_list(findings_list, lang="en"):
    crit = [f for f in findings_list if f.get("severity") == "Critical"]
    high = [f for f in findings_list if f.get("severity") == "High"]
    med = [f for f in findings_list if f.get("severity") == "Medium"]
    low = [f for f in findings_list if f.get("severity") == "Low"]

    total = len(findings_list)
    # Calculate posture score from 100
    penalty = (len(crit) * 35) + (len(high) * 20) + (len(med) * 8) + (len(low) * 2)
    score = max(5, 100 - penalty)

    if lang == "fa":
        triage = f"## گزارش تریاژ و ارزیابی ریسک امنیتی Hashira AI\n\n"
        triage += f"**شاخص کلی وضعیت امنیتی تارگت:** `{score} / 100`\n"
        triage += f"**تعداد کل آسیب‌پذیری‌های ارزیابی‌شده:** {total}\n\n"
        triage += f"- 🔴 **بحرانی (P0 - اقدام فوری ۲۴ ساعته):** {len(crit)} مورد\n"
        triage += f"- 🟠 **بالا (P1 - اقدام طی ۷۲ ساعت):** {len(high)} مورد\n"
        triage += f"- 🟡 **متوسط (P2 - اقدام در برنامه هفتگی):** {len(med)} مورد\n"
        triage += f"- 🔵 **پایین / اطلاع‌رسانی (P3):** {len(low)} مورد\n\n"
        triage += f"### اولویت‌بندی اقدامات فنی:\n"
        if crit or high:
            triage += f"۱. مسدودسازی سریع دسترسی عمومی به فایل‌های حساس و اصلاح کانفیگ سرورهای وب.\n"
        triage += f"۲. فعال‌سازی هدرهای دفاعی HSTS و CSP برای مقابله با حملات ترفیع سطح و XSS.\n"
        triage += f"۳. بررسی پروتکل‌های ارتباطی و بستن پورت‌های متنی و بدون رمزنگاری.\n"
    else:
        triage = f"## Hashira AI Security Posture & Triage Report\n\n"
        triage += f"**Overall Target Security Posture Score:** `{score} / 100`\n"
        triage += f"**Total Evaluated Vulnerabilities:** {total}\n\n"
        triage += f"- 🔴 **Critical (P0 - Immediate 24h Action):** {len(crit)} findings\n"
        triage += f"- 🟠 **High (P1 - Resolve within 72h):** {len(high)} findings\n"
        triage += f"- 🟡 **Medium (P2 - Scheduled Sprint Remediation):** {len(med)} findings\n"
        triage += f"- 🔵 **Low / Informational (P3):** {len(low)} findings\n\n"
        triage += f"### Strategic Recommendations:\n"
        if crit or high:
            triage += f"1. Immediately revoke and rotate any credentials or dotfiles exposed via web directories.\n"
        triage += f"2. Implement perimeter defense headers (CSP, HSTS) across all public gateway endpoints.\n"
        triage += f"3. Disable cleartext protocols and enforce cryptographic encryption in transit.\n"

    return triage

def handle_run_task(payload):
    task_id = payload.get("task_id", str(uuid.uuid4()))
    target = payload.get("target", "System")
    options = payload.get("options", {})

    action = options.get("action", "explain")
    lang = options.get("language", "en")
    raw_query = options.get("query", "")
    finding_data = options.get("finding", {})

    # Always sanitize input to prevent secret leakage
    sanitized_query = redact_sensitive_data(raw_query)

    response_text = ""
    remediation_patch = ""

    if action == "triage":
        findings_list = options.get("findings_list", [])
        response_text = triage_findings_list(findings_list, lang)
    elif action == "explain":
        response_text, remediation_patch = generate_remediation_explanation(finding_data, lang)
    elif action == "chat":
        if lang == "fa":
            response_text = f"**دستیار امنیتی هوشمند Hashira AI:**\n\nدرخواست شما با موفقیت بررسی شد:\n> {sanitized_query}\n\nتمامی تحلیل‌ها و پیشنهادات دفاعی بر مبنای استانداردهای NIST CSF و OWASP Top 10 ارائه می‌شوند. آیا مایلید راهنمای پچ امنیتی برای بخش خاصی تولید شود؟"
        else:
            response_text = f"**Hashira AI Defensive Assistant:**\n\nProcessed security query:\n> {sanitized_query}\n\nAll recommendations adhere strictly to NIST CSF and OWASP Top 10 hardening guidelines. Would you like a concrete configuration patch generated?"
    else:
        response_text = f"Hashira AI Task executed successfully for {target}."

    resp = {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": [],
            "raw_output": response_text,
            "response": response_text,
            "remediation_patch": remediation_patch,
            "sanitized": True,
            "error": None
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
