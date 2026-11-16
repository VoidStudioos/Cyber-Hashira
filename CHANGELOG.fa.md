# گزارش تغییرات (Changelog)

تمام تغییرات مهم و نسخه‌های منتشرشده‌ی پروژه‌ی **Cyber Hashira** در این سند ثبت می‌شوند.

فرمت این گزارش بر اساس استانداردهای [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) بوده و از قوانین [نسخه‌گذاری معنایی (Semantic Versioning)](https://semver.org/spec/v2.0.0.html) پیروی می‌کند.

---

## [1.2.0] - ۲۶ آبان ۱۴۰۵ (2026-11-16)

### 🚀 افزوده‌شده‌ها (Added)
- **افزودن ۶۰ ماژول تخصصی امنیتی جدید (رسیدن به مجموع دقیق ۲۶۰ ماژول):**
  - **امنیت اینترنت اشیاء و سفت‌افزار (IoT & Embedded Firmware - ۶ ماژول):** `iot-firmware-extractor`, `jtag-uart-pinout-identifier`, `ble-firmware-ota-auditor`, `mqtt-broker-exploit-tester`, `coap-iot-protocol-fuzzer`, `zigbee-zwave-recon`.
  - **امنیت سیستم‌های صنعتی و اسکادا (ICS & SCADA Security - ۴ ماژول):** `modbus-plc-auditor`, `s7comm-siemens-scanner`, `dnp3-outstation-fuzzer`, `opc-ua-security-linter`.
  - **زیرساخت ابری و سازمانی (Cloud & Sovereign Infrastructure - ۱۰ ماژول):** `azure-ad-service-principal-auditor`, `gcp-workload-identity-validator`, `oci-iam-policy-linter`, `aws-lambda-runtime-security`, `terraform-drift-detector`, `kubernetes-admission-controller-auditor`, `cilium-ebpf-network-policy-auditor`, `harbor-container-registry-auditor`, `istio-service-mesh-authorization`, `openstack-keystone-policy-checker`.
  - **هویت و دایرکتوری سازمانی (Identity & Enterprise Directory - ۴ ماژول):** `okta-idp-hygiene-auditor`, `ping-identity-federation-auditor`, `azure-entra-conditional-access-auditor`, `active-directory-shadow-admin-finder`.
  - **امنیت هوش مصنوعی و مدل‌های زبانی (AI & LLM Adversarial Security - ۶ ماژول):** `llm-rag-context-injection-auditor`, `model-inversion-privacy-auditor`, `adversarial-patch-detector`, `ai-agent-sandbox-escape-tester`, `onnx-model-backdoor-scanner`, `huggingface-repo-security-auditor`.
  - **فناوری‌های نوظهور و مخابرات (Emerging Tech & Telecom - ۳ ماژول):** `5g-telecom-core-security-auditor`, `gnss-gps-spoofing-detector`, `satellite-link-protocol-auditor`.
  - **امنیت وب، کلاینت و API (Web, API & Client Security - ۶ ماژول):** `fido2-webauthn-implementation-auditor`, `http-cache-smuggling-auditor`, `quic-tls-handshake-auditor`, `wasm-tamper-memory-protection`, `passkey-credential-binding-auditor`, `jwt-confusion-cross-key-auditor`.
  - **امنیت زنجیره تأمین نرم‌افزار و بیلد (Supply-Chain & Build Security - ۵ ماژول):** `slsa-provenance-verifier`, `npm-typosquatting-malware-detector`, `pypi-supply-chain-sentinel`, `docker-bake-multistage-linter`, `gradle-maven-dependency-integrity`.
  - **تیم ارغوانی و مهندسی شناسایی (Purple Team & Detection Engineering - ۵ ماژول):** `atomic-red-team-coverage-mapper`, `mitre-attack-navigator-generator`, `threat-hunting-hypothesis-evaluator`, `edr-telemetry-blindspot-detector`, `detection-as-code-rule-validator`.
  - **انطباق و چارچوب‌های قانونی (Compliance & Regulatory Posture - ۵ ماژول):** `iso27001-annex-a-posture-auditor`, `soc2-type2-trust-criteria-evaluator`, `hipaa-hitech-security-auditor`, `pci-dss-v4-readiness-scanner`, `nist-sp-800-53-control-assessor`.
  - **تیم آبی و پاسخ به رخداد (Blue Team & Threat Response - ۶ ماژول):** `memory-dump-volatility-triager`, `pcap-dns-tunnel-exfiltration-detector`, `windows-event-log-anomaly-detector`, `linux-auditd-syscall-monitor`, `honeypot-telemetry-aggregator`, `compromised-credential-spill-cleaner`.
- **مقاوم‌سازی و سخت‌سازی امنیتی خودِ ابزار (Tool Self-Hardening):**
  - `engine/sandbox.py`: پاک‌سازی متغیرهای محیطی حساس، محدودسازی منابع POSIX (`rlimits` برای پردازنده، حافظه و تعداد فایل‌ها) و کاهش سطح دسترسی پردازه‌ها.
  - `engine/audit_log.py`: لاگر رویدادنگاری تغییرناپذیر با زنجیره هش SHA-256 (Hash-chained Audit Log) برای ردگیری غیرقابل دستکاری رخدادها.
  - `engine/scopeguard.py`: اعتبارسنجی پیش‌پرواز دامنه‌های هدف در سطح هسته و فراخوانی ماژول‌ها.
  - ایمن‌سازی پنل وب با هش‌کردن رمز عبور با `bcrypt`، محافظت در برابر حملات جعل درخواست میان‌سایتی (CSRF)، و محدودکننده نرخ ارسال (Rate Limiting - ۳۰ درخواست در دقیقه).
- **ارتقای ماتریس تست و کیفیت‌سنجی:**
  - افزودن **گیت ششم (Regression Gate)** به ماتریس ارزیابی در `tests/test_all_modules_matrix.py`.
  - تست خودکار همخوانی رجیستری و آرتیفکت‌ها (`tests/test_registry_consistency.py`).
  - اعتبارسنجی خودکار همگام‌سازی مستندات دوزبانه (`tests/test_bilingual_docs_sync.py`).
  - خط لوله گیت‌هاب اکشنز (`.github/workflows/ci.yml`).
- **مستندسازی:**
  - راهنمای توسعه‌دهندگان ماژول: `docs/MODULE_DEVELOPER_GUIDE.md` و `docs/MODULE_DEVELOPER_GUIDE.fa.md`.
  - مستندات مهاجرت رجیستری: `registry/MIGRATIONS.md` و `registry/MIGRATIONS.fa.md`.
  - مستندات جعبه شنی امنیتی: `docs/SANDBOXING.md` و `docs/SANDBOXING.fa.md`.

### 🔄 تغییرات (Changed)
- یکپارچه‌سازی نام‌های مستعار ماژول‌ها (Alias Consolidation):
  - انتقال و تغییر نام `modules/forensics` به شناسه استاندارد `modules/digital-forensics`.
  - انتقال و تغییر نام `modules/vulnerability` به شناسه استاندارد `modules/vulnerability-assessment`.
  - افزودن مسیردهی خودکار نام‌های قدیمی به شناسه استاندارد با هشدار منسوخ‌شدن (Deprecation Notice) در `hashira.py` و پنل وب.
- بازسازی و بسته‌بندی آرتیفکت‌های نصب مجزا در `dist/packages/` برای هر ۲۶۰ ماژول معتبر.
- به‌روزرسانی نشان‌ها (Badges)، شمارنده‌ها و کاتالوگ ماژول‌ها به عدد ۲۶۰ در `README.md` و `README.fa.md`.

---

## [1.1.0] - ۴ آبان ۱۴۰۵ (2026-10-25)

### 🚀 افزوده‌شده‌ها (Added)
- افزودن ۸۰ ماژول جدید در حوزه‌های API، ابری، وب۳ و موبایل (رسیدن به مجموع ۲۰۰ ماژول).
- راه‌اندازی ماتریس اعتبارسنجی ۵-گیتی برای تمام ماژول‌ها (`tests/test_all_modules_matrix.py`).
- اسکریپت ساخت پکیج‌های نصبی مجزا (`scripts/build_installers.py`).
- نسخه کامل فارسی مستندات مخزن (`README.fa.md`).

---

## [1.0.0] - ۲۷ مهر ۱۴۰۵ (2026-10-18)

### 🚀 انتشار اولیه (Initial Release)
- لانچر یکپارچه (`hashira.py`) برای اجرای داشبورد وب، ترمینال TUI و نرم‌افزار دسکتاپ (Tauri 2).
- معماری ماژولار تحت پروتکل Stdio JSON-RPC IPC.
- ۱۲۰ ماژول پایه با گواهی رسمی.
- فایروال محدوده هدف (ScopeGuard).
- موتور گزارش‌گیری خروجی استاندارد OASIS SARIF v2.1.0 و قالب‌های HTML/PDF.
