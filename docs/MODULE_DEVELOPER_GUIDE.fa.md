# سایبر هاشیرا — راهنمای جامع توسعه و گواهی‌نامه ماژول‌ها

این سند، استاندارد رسمی و مرجع فنی جهت توسعه، بسته‌بندی، تست و اخذ تاییدیه کیفی (Certification) برای ماژول‌های امنیتی در اکوسیستم سایبر هاشیرا است.

---

## ۱. اصول معماری و پروتکل ارتباطی ماژول‌ها

سایبر هاشیرا یک **معماری ماژولار سخت‌گیرانه و مستقل از زبان برنامه‌نویسی** را پیاده‌سازی می‌کند:
- **ایزوله‌سازی فرآیند (Process Isolation):** ماژول‌ها به صورت زیرفرآیندهای (Subprocess) کاملاً مجزا اجرا می‌شوند. هسته مرکزی پلتفرم هرگز کتابخانه‌های اشتراکی محلی و ناشناس (`.so`, `.dll`, `.dylib`) را مستقیماً وارد فضای حافظه خود نمی‌کند.
- **پروتکل Stdio JSON-RPC IPC:** تبادل داده بین هسته و ماژول‌ها منحصراً از طریق ورودی استاندارد (`stdin`) و خروجی استاندارد (`stdout`) با خطوط تک‌خطی فرمت JSON صورت می‌پذیرد.
- **مرز حفاظتی اسکوپ‌گارد (ScopeGuard Boundary):** هرگونه پویش، فازینگ یا ارسال پکت فعال به شبکه یا اهداف ابری ملزم به بررسی و اعتبارسنجی سطح دسترسی هدف در مرز ScopeGuard است.
- **پایداری آفلاین (Offline-First):** کلیه ماژول‌ها باید بدون وابستگی اجباری به اینترنت یا سرورهای خارجی قابل اجرا باشند.

---

## ۲. ساختار پوشه‌ها و قوانین نام‌گذاری

### ۲.۱ چیدمان پوشه ماژول
هر ماژول باید در پوشه‌ای اختصاصی داخل مسیر `modules/<module-id>/` قرار گیرد:

```text
modules/<module-id>/
├── manifest.json       # مانیفست رسمی و قراردادهای داده‌ای ماژول
├── worker.py           # نقطه ورود اجرایی (پایتون، راست، گو یا نود)
└── README.md           # مستندات فنی و ابزارهای مرجع
```

### ۲.۲ قوانین نام‌گذاری
1. **شناسه ماژول (`id`):** باید دقیقاً با حروف کوچک و ساختار **kebab-case** نوشته شود (مثال: `firmware-binary-unpacker`, `modbus-tcp-security-auditor`).
2. **انطباق نام پوشه:** نام پوشه در مسیر `modules/` **باید دقیقاً با فیلد `id` در فایل `manifest.json` یکسان باشد**.
3. **ممنوعیت نام‌های دوگانه و عمومی:** استفاده از نام‌های کلی تک‌کلمه‌ای (مانند `forensics` یا `vulnerability`) ممنوع است. فقط شناسه‌های دقیق و استاندارد مجاز هستند (`digital-forensics`, `vulnerability-assessment`).
4. **دسته‌بندی الزامی:** هر ماژول باید یک دسته‌بندی رسمی معتبر را اعلام کند:
   - `Web Application Security`
   - `API & Microservices`
   - `Network & Infrastructure`
   - `Cloud & Container Security`
   - `Identity & Access Management`
   - `Active Directory & Enterprise`
   - `AI & LLM Security`
   - `IoT & Firmware Security`
   - `ICS & SCADA Security`
   - `Blockchain & Web3`
   - `Supply Chain & DevSecOps`
   - `Purple Team & Adversary Simulation`
   - `Blue Team & Threat Hunting`
   - `Compliance & Governance`

---

## ۳. مشخصات کامل ساختار `manifest.json`

فایل `manifest.json` هویت، قابلیت‌ها، سطوح دسترسی، نقطه ورود اجرایی و ساختار ورودی/خروجی ماژول را توصیف می‌کند.

### ۳.۱ نمونه کامل مانیفست

```json
{
  "id": "iot-mqtt-security-auditor",
  "name": "IoT MQTT Broker Security Auditor",
  "description": "Audits MQTT v3.1.1/v5 broker endpoints for anonymous read/write access, wildcards subscription leaks, cleartext transport, and weak credentials.",
  "author": "Cyber Hashira Security Team",
  "version": "1.0.0",
  "min_host_version": "0.1.0",
  "category": "IoT & Firmware Security",
  "supported_os": [
    "windows",
    "linux",
    "macos"
  ],
  "supported_arch": [
    "x86_64",
    "aarch64"
  ],
  "required_permissions": [
    "network:connect",
    "findings:write"
  ],
  "optional_permissions": [
    "evidence:write"
  ],
  "entry_point": {
    "runtime": "python",
    "executable": "worker.py",
    "default_args": []
  },
  "config_schema": {
    "type": "object",
    "properties": {
      "port": {
        "type": "integer",
        "default": 1883,
        "description": "پورت هدف بروکر MQTT"
      },
      "test_wildcard": {
        "type": "boolean",
        "default": true,
        "description": "تست اشتراک در تاپیک‌های وایلدکارد # و $SYS/# جهت نشت داده"
      }
    }
  },
  "contracts": {
    "input_schema": {
      "type": "object",
      "required": ["task_id", "target"],
      "properties": {
        "task_id": { "type": "string" },
        "target": { "type": "string" },
        "scope_approved": { "type": "boolean" },
        "options": { "type": "object" }
      }
    },
    "output_schema": {
      "type": "object",
      "required": ["task_id", "success", "findings"],
      "properties": {
        "task_id": { "type": "string" },
        "success": { "type": "boolean" },
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["title", "severity"],
            "properties": {
              "id": { "type": "string" },
              "title": { "type": "string" },
              "severity": { "type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"] },
              "description": { "type": "string" },
              "cwe": { "type": "string" },
              "remediation": { "type": "string" }
            }
          }
        }
      }
    }
  }
}
```

### ۳.۲ جدول تشریح فیلدهای مانیفست
| نام فیلد | نوع داده | الزامی | شرح فنی |
|---|---|---|---|
| `id` | رشته (String) | **بله** | شناسه منحصربه‌فرد با حروف کوچک و kebab-case (دقیقاً منطبق بر نام پوشه). |
| `name` | رشته (String) | **بله** | عنوان خوانا و استاندارد جهت نمایش در داشبورد و گزارش‌ها. |
| `description` | رشته (String) | **بله** | شرح فنی قابلیت‌ها با ذکر ابزارها یا الگوهای مرجع در انتها. |
| `author` | رشته (String) | **بله** | نام توسعه‌دهنده یا تیم نگه‌دارنده ماژول. |
| `version` | رشته (String) | **بله** | نسخه ماژول بر پایه استاندارد SemVer (مثال: `1.0.0`). |
| `min_host_version` | رشته (String) | **بله** | حداقل نسخه پلتفرم سایبر هاشیرا برای اجرای این ماژول. |
| `category` | رشته (String) | **بله** | دسته‌بندی امنیتی رسمی ماژول. |
| `supported_os` | آرایه (Array) | **بله** | سیستم‌عامل‌های پشتیبانی‌شده: `["windows", "linux", "macos"]`. |
| `supported_arch`| آرایه (Array) | **بله** | معماری‌های پردازنده: `["x86_64", "aarch64"]`. |
| `required_permissions` | آرایه (Array) | **بله** | دسترسی‌های مورد نیاز در سندباکس (`network:connect`, `evidence:write` و غیره). |
| `entry_point` | شیء (Object) | **بله** | شامل `runtime` (پایتون، باینری محلی و...) و مسیر فایل `executable`. |
| `config_schema`| شیء (Object) | **بله** | اسکیمای استاندارد JSON-Schema برای تنظیمات قابل تغییر توسط کاربر. |
| `contracts` | شیء (Object) | **بله** | تعریف قراردادهای اعتبارسنجی `input_schema` و `output_schema`. |

---

## ۴. پیاده‌سازی پروتکل ارتباطی Stdio JSON-RPC

ماژول‌ها از طریق جریان استاندارد ورودی و خروجی با لانچر صحبت می‌کنند. هر پیام یک خط با ساختار معتبر JSON است که با `\n` پایان می‌یابد.

### ۴.۱ پیام‌های ورودی از سمت هسته (Host Requests)

#### ۱. بررسی سلامت (`HealthCheck`)
جهت بررسی در دسترس بودن و سلامت محیط اجرای ماژول ارسال می‌شود:
```json
{"type": "HealthCheck"}
```

#### ۲. اجرای مأموریت (`RunTask`)
جهت اجرای پایش یا تست روی هدف مجاز ارسال می‌گردد:
```json
{
  "type": "RunTask",
  "action": "execute",
  "target": "mqtt.target.corp",
  "authorized_targets": ["mqtt.target.corp"],
  "payload": {
    "task_id": "scan-170001",
    "target": "mqtt.target.corp",
    "scope_approved": true,
    "options": {
      "port": 1883,
      "simulate_vulnerabilities": false
    }
  }
}
```

### ۴.۲ پیام‌های خروجی ماژول به هسته (Module Responses)

#### ۱. پاسخ بررسی سلامت (`HealthCheckResult`)
```json
{
  "type": "HealthCheckResult",
  "payload": {
    "healthy": true,
    "version": "1.0.0",
    "message": "Module initialized and ready for execution."
  }
}
```

#### ۲. گزارش اتمام مأموریت (`TaskCompleted`)
```json
{
  "type": "TaskCompleted",
  "payload": {
    "task_id": "scan-170001",
    "success": true,
    "findings": [
      {
        "id": "finding-mqtt-anon-01",
        "title": "Unauthenticated Anonymous MQTT Broker Access",
        "severity": "High",
        "description": "The MQTT broker allows anonymous client connections without authentication.",
        "cwe": "CWE-306",
        "remediation": "Configure 'allow_anonymous false' and require client X.509 certificate or credentials."
      }
    ],
    "telemetry": {
      "duration_ms": 142.5,
      "checks_performed": 6
    }
  }
}
```

---

## ۵. کد مرجع استاندارد برای ماژول (الگوی پایتون)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Hashira — کد نمونه استاندارد ماژول امنیتی
"""

import sys
import json
import time

def handle_health_check():
    """پاسخ وضعیت سلامت ماژول."""
    return {
        "type": "HealthCheckResult",
        "payload": {
            "healthy": True,
            "version": "1.0.0",
            "message": "ماژول فعال و آماده مأموریت است."
        }
    }

def handle_run_task(message):
    """اجرای عملیات ممیزی همراه با اعتبارسنجی اجباری ScopeGuard."""
    payload = message.get("payload", {})
    task_id = payload.get("task_id", "task-default")
    target = payload.get("target", "")
    scope_approved = payload.get("scope_approved", False)
    options = payload.get("options", {})

    # اعتبارسنجی سطح پایین اسکوپ‌گارد (الزامی)
    if not scope_approved:
        return {
            "type": "TaskCompleted",
            "payload": {
                "task_id": task_id,
                "success": False,
                "error": "Target authorization denied by ScopeGuard boundary.",
                "findings": []
            }
        }

    start_time = time.time()
    findings = []

    # منطق پویش یا شبیه‌سازی ایمن
    simulate = options.get("simulate_vulnerabilities", False)
    if simulate:
        findings.append({
            "id": f"{task_id}-f1",
            "title": "یافته امنیتی نمونه",
            "severity": "Medium",
            "description": f"هدف {target} ممیزی شد و این مورد شناسایی گردید.",
            "cwe": "CWE-200",
            "remediation": "اعمال پچ‌های امنیتی توصیه شده."
        })

    duration_ms = round((time.time() - start_time) * 1000, 2)
    return {
        "type": "TaskCompleted",
        "payload": {
            "task_id": task_id,
            "success": True,
            "findings": findings,
            "telemetry": {
                "duration_ms": duration_ms,
                "target": target
            }
        }
    }

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_type = req.get("type", "")

            if req_type == "HealthCheck":
                resp = handle_health_check()
            elif req_type in ("RunTask", "Execute"):
                resp = handle_run_task(req)
            else:
                resp = {"error": f"Unknown request type: {req_type}"}

            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as exc:
            err_resp = {"error": str(exc), "healthy": False, "success": False}
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
```

---

## ۶. ثبت ماژول در رجیستری و تولید آرتیفکت SHA-256

پس از ایجاد پوشه ماژول:
1. **تولید خودکار آرتیفکت و کاتالوگ رجیستری:**
   دستور زیر تمام ماژول‌ها را فشرده کرده، در `registry/artifacts/` با هش دقیق SHA-256 ذخیره می‌کند و فایل `registry/v1/modules.json` را همگام می‌سازد:
   ```bash
   python scripts/package_all_modules.py
   ```

---

## ۷. چک‌لیست گیت‌های آزمون و تاییدیه کیفی (Certification Gates)

پیش از ایجاد هرگونه Pull Request، ماژول باید تمامی گیت‌های آزمون ماتریکس را با وضعیت `[PASS]` سپری کند:

| گیت | نام گیت | شرط قبولی |
|---|---|---|
| **گیت ۱** | **Manifest** | وجود فایل `manifest.json` معتبر با فیلدهای اجباری (`id`, `version`, `category`, `entry_point`). |
| **گیت ۲** | **Artifact** | وجود فایل تاربال در `registry/artifacts/` با هش تطبیقی SHA-256 در فایل `registry/v1/modules.json`. |
| **گیت ۳** | **Health** | اجرای موفق دستور `HealthCheck` و دریافت خروجی `healthy: true` از طریق IPC. |
| **گیت ۴** | **Scope** | ارسال درخواست با `scope_approved: false`. ماژول **باید** درخواست را رد کند و هیچ پکت فعالی به شبکه نفرستد. |
| **گیت ۵** | **RunTask** | ارسال درخواست با `scope_approved: true`. ماژول مأموریت را با موفقیت خاتمه داده و داده ساختاریافته برگرداند. |
| **گیت ۶** | **Regression** | ارزیابی عملکرد ماژول در برابر داده‌های ورودی نمونه و مقایسه با نتایج قطعی مورد انتظار. |

### اجرای آزمون محلی ماتریکس:
```bash
python hashira.py matrix
# یا به صورت مستقیم:
python tests/test_all_modules_matrix.py
```
تمام ماژول‌ها باید تاییدیه کامل `200/200 [PASS]` را کسب نمایند.
