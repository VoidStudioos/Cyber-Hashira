# سایبر هاشیرا (Cyber Hashira)

> **ورک‌استیشن جامع و ماژولار امنیت سایبری، تست نفوذ و تیم قرمز**  
> *۱۴۱ ماژول معتبر • ۳ رابط کاربری (وب پنل، ترمینال، دسکتاپ) • ویندوز و لینوکس • آماده برای داکر • کاملاً آفلاین و ایزوله*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Certification Matrix](https://img.shields.io/badge/ماژول‌های%20تایید%20شده-141%2F141%20PASS-brightgreen.svg)](tests/test_all_modules_matrix.py)
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
6. [دسته‌بندی ۱۴۱ ماژول رسمی](#-دسته‌بندی-۱۴۱-ماژول-رسمی)
7. [ماتریکس آزمون و اعتبارسنجی ۱۴۱/۱۴۱](#-ماتریکس-آزمون-و-اعتبارسنجی-۱۴۱۱۴۱)
8. [اصول امنیتی و معماری](#-اصول-امنیتی-و-معماری)
9. [لایسنس و قوانین اخلاقی](#-لایسنس-و-قوانین-اخلاقی)

---

## 🌟 معرفی کلی

**سایبر هاشیرا (Cyber Hashira)** یک پلتفرم پیشرفته و ماژولار برای تست نفوذ مجاز، ارزیابی وضعیت امنیتی، جرم‌شناسی دیجیتال، و مهندسی دفاعی است.

برخلاف ابزارهای حجیم و یکپارچه قدیمی، سایبر هاشیرا بر پایه **معماری ماژولار دقیق** طراحی شده است:

- **۳ رابط کاربری همزمان:** قابلیت اجرا به صورت **وب‌پنل مدرن**، **کنسول متنی ترمینال (TUI)**، یا **اپلیکیشن نیتیو دسکتاپ**.
- **۱۴۱ ماژول امنیتی تخصصی:** پوشش جامع شناسایی (Reconnaissance)، وب، API، باگ بانتی، ابری، کوبرنتیز، اکتیو دایرکتوری، رمزنگاری و هوش مصنوعی.
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
# مشاهده تمام ۱۴۱ ماژول:
python hashira.py list

# فیلتر بر اساس دسته‌بندی (مثلاً کلود یا وب):
python hashira.py list --category "Cloud"
python hashira.py list --category "Web"
```

### ۶. اجرای آزمون ماتریکس ۱۴۱ ماژول
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
  همراه با فایل‌های اجرایی تک‌کلیک `Launch-Web-Panel.bat` و `Launch-Terminal-TUI.bat` و اسکریپت نصب خودکار `install-windows.bat`.
- **نسخه پرتابل لینوکس:** `cyber-hashira-linux-x64-v1.0.0.tar.gz`  
  همراه با اسکریپت‌های اجرایی `launch-web.sh` و `launch-tui.sh` و فایل منوی برنامه لینوکس `cyber-hashira.desktop`.

---

## 🛡️ دسته‌بندی ۱۴۱ ماژول رسمی

۱۴۱ ماژول پروژه در حوزه‌های زیر دسته‌بندی شده‌اند:
1. **امنیت وب، API و باگ بانتی (بیش از ۵۰ ماژول):** تزریق SQL، فازینگ اسکیما، BOLA، قاچاق درخواست HTTP (Smuggling)، آلودگی پروتوتایپ، CORS، سشن‌ها، توکن‌های JWT و OAuth، تزریق تمپلیت (SSTI)، فازینگ مسیر و دارایی‌ها (`content-discovery-fuzzer` بر پایه ffuf/feroxbuster)، ممیزی تزریق فرمان (`command-injection-auditor` بر پایه commix)، واکشی کدهای منبع جاوااسکریپت (`client-js-beautifier-analyzer`)، استخراج سورس‌مپ (`sourcemap-source-extractor`)، دامپ مخازن گیت افشا شده (`exposed-git-dumper`)، فازینگ پلی‌گلات XSS (`xss-polyglot-auditor`)، بازنویسی پارامترها (`url-parameter-replacer`)، و ممیزی سیستم‌های مدیریت محتوا نظیر وردپرس، دروپال و جوملا.
2. **شناسایی دارایی‌ها و OSINT (بیش از ۲۰ ماژول):** استخراج غیرفعال ساب‌دامین (`subdomain-passive-miner` بر پایه Amass/Subfinder)، نگاشت رنج‌های ASN و BGP (`asn-ip-range-mapper`)، نظارت بر تایپواسکواتینگ و برند (`typosquatting-brand-monitor` بر پایه dnstwist)، تجمیع افشاگری‌های OSINT از شودن/سنسیس/فوفا (`osint-search-exposure`)، انگشت‌نگاری فناوری وب (`web-technology-fingerprinter` بر پایه Wappalyzer)، بایپس و شناسایی WAF/CDN (`cdn-waf-detector`)، ماینر آدرس‌های گذشته اینترنت از Wayback/AlienVault (`historical-url-miner`)، اسکرین‌شات و مصورسازی دارایی‌ها (`screenshot-asset-visualizer`)، و تولید دیکشنری کلمات کلیدی هدفمند (`wordlist-generator-cewl`).
3. **امنیت ابری، زیرساخت و کانتینرها (بیش از ۲۵ ماژول):** ارزیابی جامع استانداردهای CIS ابری بر پایه Prowler (`cloud-prowler-compliance`)، باکت‌های S3، پیکربندی IAM، ران‌تایم داکر، کنترل دسترسی کوبرنتیز (RBAC)، امنیت Podها (PSS)، و باگ‌های کلودفلر.
4. **امنیت شبکه و رمزنگاری (بیش از ۲۰ ماژول):** کشف پورت‌ها و سرویس‌ها، تست DNS Rebinding (`dns-rebinding-tester`)، بررسی گواهی‌های TLS، رکوردهای DNSSEC/CAA، کلیدهای ضعیف SSH، و امنیت وایرلس و خودرویی (CAN Bus / UDS).
5. **هویت، پسورد و سیستم‌ها (بیش از ۱۵ ماژول):** اکتیو دایرکتوری (AS-REP Roasting / Kerberoasting)، پسوردهای تکراری، LDAP StartTLS، اعتبارسنجی متادیتای SAML، و ارزیابی هدرهای امنیتی.
6. **جرم‌شناسی دیجیتال، کتابخانه‌های منسوخ و هوش تهدیدات (بیش از ۱۵ ماژول):** شناسایی کتابخانه‌های آسیب‌پذیر جاوااسکریپت (`retire-js-vulnerable-libraries`)، ارزیابی بدافزار با انتروپی شانون، بازرسی بسته‌های شبکه PCAP، مپینگ تاکتیک‌های MITRE ATT&CK، لاگ‌های SIEM، و دستیار هوش مصنوعی دفاعی دو زبانه (فارسی/انگلیسی).

---

## 🧪 ماتریکس آزمون و اعتبارسنجی ۱۴۱/۱۴۱

تمام ۱۴۱ ماژول در ۵ گیت سخت‌گیرانه تست و تایید شده‌اند:
- **Manifest:** بررسی درستی فیلدهای پیکربندی و نگارش
- **Artifact:** محاسبه و تطابق هش امنیتی SHA-256
- **Health:** ارتباط از طریق پروتکل Stdio IPC JSON
- **Scope:** رد اهداف غیرمجاز توسط ScopeGuard
- **RunTask:** اجرای موفق اسکن در حالت شبیه‌سازی و تولید خروجی استاندارد

---

## ⚖️ لایسنس و قوانین اخلاقی

پروژه تحت **مجوز آپاچی ۲.۰ (Apache License 2.0)** منتشر شده است.

> **تذکر حقوقی و اخلاقی:** سایبر هاشیرا صرفاً برای تست‌های نفوذ مجاز، اهداف تحقیقاتی و آموزشی و با رضایت کتبی و رسمی صاحبان سیستم‌ها ساخته شده است. هرگونه اسکن یا حمله بدون مجوز طبق قوانین بین‌المللی و داخلی جرم محسوب می‌شود.
