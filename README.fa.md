# سایبر هاشیرا (Cyber Hashira)

> **ورک‌استیشن جامع و ماژولار امنیت سایبری، تست نفوذ و تیم قرمز**  
> *۲۰۰ ماژول معتبر • ۳ رابط کاربری (وب پنل، ترمینال، دسکتاپ) • ویندوز و لینوکس • آماده برای داکر • کاملاً آفلاین و ایزوله*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Certification Matrix](https://img.shields.io/badge/ماژول‌های%20تایید%20شده-200%2F200%20PASS-brightgreen.svg)](tests/test_all_modules_matrix.py)
[![Interfaces](https://img.shields.io/badge/رابط‌های%20کاربری-وب%20%7C%20ترمینال%20%7C%20دسکتاپ-purple.svg)](#-رابط‌های-کاربری-۳-فرمت)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](#-استقرار-با-داکر-docker)
[![Documentation](https://img.shields.io/badge/English-Documentation-blue.svg)](README.md)

<p align="center">
  <img src="assets/web_dashboard_preview.svg" alt="پیش‌نمایش وب‌پنل امنیتی سایبر هاشیرا" width="100%">
</p>
<p align="center">
  <img src="assets/terminal_tui_preview.svg" alt="پیش‌نمایش کنسول متنی ترمینال سایبر هاشیرا" width="85%">
</p>

---

## 📖 فهرست مطالب
1. [معرفی کلی](#-معرفی-کلی)
2. [رابط‌های کاربری (۳ فرمت گرافیکی و متنی)](#-رابط‌های-کاربری-۳-فرمت)
3. [راهنمای سریع و لانچر یکپارچه (`hashira.py`)](#-راهنمای-سریع-و-لانچر-یکپارچه-hashirapy)
4. [استقرار با داکر (Docker & Docker-Compose)](#-استقرار-با-داکر-docker)
5. [بسته‌های نصبی مستقل (Windows & Linux)](#-بسته‌های-نصبی-مستقل-windows--linux)
6. [دسته‌بندی ۲۰۰ ماژول رسمی](#-دسته‌بندی-۲۰۰-ماژول-رسمی)
7. [ماتریکس آزمون و اعتبارسنجی ۲۰۰/۲۰۰](#-ماتریکس-آزمون-و-اعتبارسنجی-۲۰۰۲۰۰)
8. [اصول امنیتی و معماری](#-اصول-امنیتی-و-معماری)
9. [لایسنس و قوانین اخلاقی](#-لایسنس-و-قوانین-اخلاقی)

---

## 🌟 معرفی کلی

**سایبر هاشیرا (Cyber Hashira)** یک پلتفرم پیشرفته و ماژولار برای تست نفوذ مجاز، ارزیابی وضعیت امنیتی، جرم‌شناسی دیجیتال، و مهندسی دفاعی است.

برخلاف ابزارهای حجیم و یکپارچه قدیمی، سایبر هاشیرا بر پایه **معماری ماژولار دقیق** طراحی شده است:

- **۳ رابط کاربری همزمان:** قابلیت اجرا به صورت **وب‌پنل مدرن**، **کنسول متنی ترمینال (TUI)**، یا **اپلیکیشن نیتیو دسکتاپ**.
- **۲۰۰ ماژول امنیتی تخصصی:** پوشش فراگیر شناسایی (Reconnaissance)، امنیت وب و API، باگ بانتی، ابری، کوبرنتیز، امنیت هوش مصنوعی (AI & LLM Security)، قراردادهای هوشمند (Web3)، اکتیو دایرکتوری پیشرفته سازمانی، مهندسی معکوس و زنجیره تامین.
- **موتور محافظتی ScopeGuard:** جلوگیری قطعی از اسکن تصادفی یا غیرمجاز دامنه‌ها و آی‌پی‌های خارج از محدوده.
- **کاملاً آفلاین و بدون تله‌متری:** هیچ داده‌ای به هیچ سرور خارجی ارسال نمی‌شود؛ تمام شواهد و یافته‌ها در دیتابیس لوکال شما ذخیره می‌گردند.
- **خروجی استاندارد OASIS SARIF v2.1.0:** حذف خودکار اطلاعات حساس (Redaction)، تجمیع یافته‌های تکراری و تولید گزارش‌های اجرایی HTML و PDF.

---

## 🖥️ رابط‌های کاربری (۳ فرمت)

سایبر هاشیرا برای انعطاف کامل در محیط‌های گوناگون ویندوز، لینوکس و مک به سه فرمت مجهز است:

| رابط | فناوری | مناسب برای | دستور اجرا |
|---|---|---|---|
| **🌐 وب‌پنل (Web Dashboard)** | Flask + Tailwind CSS | کارهای روزمره، مرورگرها، سرورهای ابری و کانتینرها | `python hashira.py web` |
| **💻 ترمینال (Terminal TUI)** | Zero-Dependency ANSI Console | ارتباط SSH، سرورهای بدون مانیتور (Headless)، نشست‌های tmux | `python hashira.py tui` |
| **🖥️ اپلیکیشن دسکتاپ** | Tauri 2 (Rust) + React 18 | محیط کاری کامل دسکتاپ با ابزارهای بصری | `python hashira.py desktop` |

---

## ⚡ راهنمای سریع و لانچر یکپارچه (`hashira.py`)

لانچر اصلی `hashira.py` در ریشه پروژه تمام عملیات را با یک دستور مدیریت می‌کند:

### ۱. اجرای وب‌پنل امنیتی
```bash
python hashira.py web
# با پورت و آدرس دلخواه:
python hashira.py web --host 0.0.0.0 --port 8080
```
سپس آدرس [http://localhost:8080](http://localhost:8080) را در مرورگر باز کنید.

### ۲. اجرای رابط متنی ترمینال (TUI)
```bash
python hashira.py tui
```

### ۳. اجرای اپلیکیشن دسکتاپ
```bash
python hashira.py desktop
```

### ۴. اسکن مستقیم یک هدف از خط فرمان (CI/CD)
```bash
# اسکن ای‌پی‌آی هدف با تست شبیه‌سازی ایمن:
python hashira.py scan --module api-security --target https://api.example.com --simulate

# اسکن شبکه و پورت‌ها:
python hashira.py scan --module network-security --target 192.168.1.10
```

### ۵. لیست ماژول‌های تایید شده
```bash
# مشاهده تمام ۲۰۰ ماژول:
python hashira.py list

# فیلتر بر اساس دسته‌بندی (مثلاً کلود یا وب):
python hashira.py list --category "Cloud"
python hashira.py list --category "Web"
```

### ۶. اجرای آزمون ماتریکس ۲۰۰ ماژول
```bash
python hashira.py matrix
```

---

## 🐳 استقرار با داکر (Docker)

اجرای آسان سایبر هاشیرا در کانتینر ایزوله بدون نیاز به نصب پکیج‌های لوکال:

### با استفاده از Docker Compose (توصیه شده)
```bash
# ۱. کلون کردن ریپازیتوری
git clone https://github.com/VoidStudioos/Cyber-Hashira.git
cd Cyber-Hashira

# ۲. راه‌اندازی کانتینر در پس‌زمینه
docker-compose up -d

# ۳. مشاهده وضعیت لاگ‌ها
docker-compose logs -f
```
داشبورد وب بلافاصله روی پورت `http://localhost:8080` در دسترس خواهد بود. پوشه‌های `./reports` و `./evidence` به صورت خودکار مانت می‌شوند.

### اجرای محیط ترمینالی (TUI) در داکر
```bash
docker-compose run --rm tui
```

---

## 📦 بسته‌های نصبی مستقل (Windows & Linux)

برای تولید بسته‌های آماده، فشرده و پرتابل برای توزیع روی سیستم‌های کلاینت:

```bash
python scripts/build_installers.py
```

### خروجی‌های تولید شده در `dist/packages/`:
- **نسخه پرتابل ویندوز:** `cyber-hashira-windows-x64-v1.0.0.zip`  
  همراه با فایل‌های اجرایی تک‌کلیک `Launch-Web-Panel.bat` و `Launch-Terminal-TUI.bat` و اسکریپت آزمون جامع `Verify-All-Modules.bat`.
- **نسخه پرتابل لینوکس:** `cyber-hashira-linux-x64-v1.0.0.tar.gz`  
  همراه با اسکریپت‌های اجرایی `launch-web.sh` و `launch-tui.sh` و فایل منوی برنامه لینوکس `cyber-hashira.desktop`.

---

## 🛡️ دسته‌بندی ۲۰۰ ماژول رسمی

۲۰۰ ماژول پروژه در حوزه‌های تخصصی زیر دسته‌بندی شده‌اند:
1. **امنیت وب، API و باگ بانتی (بیش از ۷۵ ماژول):** قاچاق درخواست HTTP/2 بر پایه HPACK (`http2-smuggling-hpack-auditor`)، فازینگ بلادرنگ وب‌سوکت (`websocket-realtime-fuzzer`)، دورزدن کوئری‌های ذخیره‌شده در گراف‌کیوال (`graphql-persisted-query-auditor`)، تزریق در هدرهای JKU/X5U توکن‌های JWT (`jwt-jku-x5u-injection-auditor`)، اسکن پیشرفته آپلود فایل و بایپس MIME، بایپس خطای 403 Forbidden با بازنویسی هدرها، تبدیل نوع محتوا، انحراف قرارداد وب‌سرویس با Dredd، ممیزی Spectral، انگشت‌نگاری Hasura/Apollo با graphw00f، تولید پی‌لودهای Gopher برای SSRF، و LFI عمیق با LFImap.
2. **امنیت هوش مصنوعی و مدل‌های زبانی بزرگ (۵ ماژول - OWASP LLM Top 10):** پرامپت اینجکشن مستقیم و غیرمستقیم (`llm-prompt-injection-auditor`)، استخراج پرامپت سیستمی و قوانین محرمانه (`llm-system-prompt-extractor`)، ارزیابی آسیب‌پذیری‌های ناشی از خروجی خام مدل‌ها نظیر XSS (`llm-insecure-output-handling`)، مسموم‌سازی و نفوذ به وکتور دیتابیس‌ها در معماری‌های RAG (`rag-vector-poisoning-scanner`)، و کنترل اختیارات و رفتارهای بدون تایید ایجنت‌های مستقل (`llm-excessive-agency-auditor`).
3. **اکتیو دایرکتوری پیشرفته سازمانی و تیم قرمز (۲۰ ماژول):** ممیزی سرویس‌های گواهی اکتیو دایرکتوری حملات ESC1 تا ESC8 با متدولوژی Certipy (`adcs-esc-template-auditor`)، کشف کوتاه‌ترین مسیر نفوذ تا Domain Admin با متدولوژی BloodHound (`ad-bloodhound-path-analyzer`)، شناسایی سرورهای آسیب‌پذیر به وادارکردن احراز هویت و رله NTLM نظیر PetitPotam (`ntlm-relay-coercion-scanner`)، ممیزی رمزهای ذخیره‌شده و اسکریپت‌های لاگین در SYSVOL GPO (`gpo-security-drift-auditor`)، ممیزی Silver Ticket و الگوریتم‌های ضعیف RC4 در سرویس‌های کربروس (`kerberos-silver-ticket-auditor`) در کنار AS-REP و Kerberoasting.
4. **امنیت قراردادهای هوشمند و وب۳ (۴ ماژول):** ممیزی خطاهای Reentrancy و اورفلو در بایت‌کد سالیدیتی بر پایه Slither و Mythril (`evm-smart-contract-auditor`)، تحلیل دستکاری اوراکل‌های قیمت و وام‌های آنی DeFi (`flash-loan-arbitrage-risk-scanner`)، ممیزی امضاهای تایپ‌شده EIP-712 و حملات بازپخش در ERC-20 (`erc20-permit-signature-auditor`)، و بررسی کنترل دسترسی پروکسی‌ها و دستورات مخرب selfdestruct (`smart-contract-access-control-guard`).
5. **امنیت اپلیکیشن‌های دسکتاپ و کلاینت (۴ ماژول):** ممیزی تنظیمات ناامن Electron نظیر nodeIntegration و دورزدن contextIsolation (`electron-desktop-security-auditor`)، تحلیل خطاهای حافظه در باینری‌های WebAssembly (.wasm) کلاینت (`wasm-security-bytecode-analyzer`)، ارزیابی تزریق آرگومان در URI Schemeهای اختصاصی نظیر `slack://` (`deep-link-uri-scheme-auditor`)، و بررسی نشت توکن‌ها در LocalStorage و وب‌کریپتو (`client-side-storage-crypto-auditor`).
6. **امنیت ابری، زیرساخت، کانتینرها و مش سرویس (۳۵ ماژول):** ممیزی توابع سرورلس AWS Lambda و Cloud Functions (`aws-lambda-injection-auditor`)، اجبار رمزنگاری mTLS در سرویس‌مش‌های Istio و Linkerd (`service-mesh-mtls-auditor`)، ممیزی Prowler، کشف منابع ذخیره‌سازی چندابری AWS/Azure/GCP با cloud_enum، آگاهی موقعیتی با CloudFox، ممیزی سکیوریتی‌گروپ‌ها با CloudMapper، و حملات سطح دسترسی با Pacu.
7. **شناسایی دارایی‌ها، پروتکل‌های نسل جدید و رمزنگاری (۲۵ ماژول):** ممیزی امنیت HTTP/3 و QUIC در برابر حملات 0-RTT و Downgrade (`http3-quic-downgrade-tester`)، آمادگی رمزنگاری پساکوانتومی (PQC) و مهاجرت از کلیدهای کلاسیک بر پایه استانداردهای NIST (`pqc-post-quantum-readiness-scanner`)، پروب سریع با httprobe، استخراج SAN از گواهی‌ها با cero، و پویش معکوس با hakrevdns.
8. **تحلیل سورس کد (SAST) و زنجیره تامین نرم‌افزار (۳۰ ماژول):** ممیزی سورس جاوا با Find Security Bugs، تحلیل C# و دات‌نت با Security Code Scan، ردیابی جریان ورودی در PHP با Progpilot، گراف ویژگی‌های کد با Joern، تولید SBOM استاندارد با Syft، امتیازدهی OpenSSF Scorecard، و پایش بسته‌های مخرب با Socket.dev.

---

## 🧪 ماتریکس آزمون و اعتبارسنجی ۲۰۰/۲۰۰

تمام ۲۰۰ ماژول در ۵ گیت سخت‌گیرانه تست و تایید شده‌اند:
- **Manifest:** بررسی درستی فیلدهای پیکربندی و نگارش
- **Artifact:** محاسبه و تطابق هش امنیتی SHA-256
- **Health:** ارتباط از طریق پروتکل Stdio IPC JSON
- **Scope:** رد اهداف غیرمجاز توسط ScopeGuard
- **RunTask:** اجرای موفق اسکن در حالت شبیه‌سازی و تولید خروجی استاندارد

---

## ⚖️ لایسنس و قوانین اخلاقی

پروژه تحت **مجوز آپاچی ۲.۰ (Apache License 2.0)** منتشر شده است.

> **تذکر حقوقی و اخلاقی:** سایبر هاشیرا صرفاً برای تست‌های نفوذ مجاز، اهداف تحقیقاتی و آموزشی و با رضایت کتبی و رسمی صاحبان سیستم‌ها ساخته شده است. هرگونه اسکن یا حمله بدون مجوز طبق قوانین بین‌المللی و داخلی جرم محسوب می‌شود.
