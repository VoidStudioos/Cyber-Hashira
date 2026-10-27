# سایبر هاشیرا (Cyber Hashira)

> **ورک‌استیشن جامع و ماژولار امنیت سایبری، تست نفوذ و تیم قرمز**  
> *۱۷۴ ماژول معتبر • ۳ رابط کاربری (وب پنل، ترمینال، دسکتاپ) • ویندوز و لینوکس • آماده برای داکر • کاملاً آفلاین و ایزوله*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Certification Matrix](https://img.shields.io/badge/ماژول‌های%20تایید%20شده-174%2F174%20PASS-brightgreen.svg)](tests/test_all_modules_matrix.py)
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
6. [دسته‌بندی ۱۷۴ ماژول رسمی](#-دسته‌بندی-۱۷۴-ماژول-رسمی)
7. [ماتریکس آزمون و اعتبارسنجی ۱۷۴/۱۷۴](#-ماتریکس-آزمون-و-اعتبارسنجی-۱۷۴۱۷۴)
8. [اصول امنیتی و معماری](#-اصول-امنیتی-و-معماری)
9. [لایسنس و قوانین اخلاقی](#-لایسنس-و-قوانین-اخلاقی)

---

## 🌟 معرفی کلی

**سایبر هاشیرا (Cyber Hashira)** یک پلتفرم پیشرفته و ماژولار برای تست نفوذ مجاز، ارزیابی وضعیت امنیتی، جرم‌شناسی دیجیتال، و مهندسی دفاعی است.

برخلاف ابزارهای حجیم و یکپارچه قدیمی، سایبر هاشیرا بر پایه **معماری ماژولار دقیق** طراحی شده است:

- **۳ رابط کاربری همزمان:** قابلیت اجرا به صورت **وب‌پنل مدرن**، **کنسول متنی ترمینال (TUI)**، یا **اپلیکیشن نیتیو دسکتاپ**.
- **۱۷۴ ماژول امنیتی تخصصی:** پوشش جامع شناسایی (Reconnaissance)، وب، API، باگ بانتی، ابری، کوبرنتیز، تحلیل سورس کد (SAST)، زنجیره تامین (Supply Chain)، اکتیو دایرکتوری، رمزنگاری و هوش مصنوعی.
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
# مشاهده تمام ۱۷۴ ماژول:
python hashira.py list

# فیلتر بر اساس دسته‌بندی (مثلاً کلود یا وب):
python hashira.py list --category "Cloud"
python hashira.py list --category "Web"
```

### ۶. اجرای آزمون ماتریکس ۱۷۴ ماژول
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

## 🛡️ دسته‌بندی ۱۷۴ ماژول رسمی

۱۷۴ ماژول پروژه در حوزه‌های زیر دسته‌بندی شده‌اند:
1. **امنیت وب، API و باگ بانتی (بیش از ۷۰ ماژول):** اسکن پیشرفته آپلود فایل و بایپس MIME (`file-upload-vulnerability-scanner`)، بایپس خطای 403 Forbidden با بازنویسی هدرها و مسیر (`forbidden-bypass-auditor`)، نشت اطلاعات و استک‌تریس‌های دیباگ (`debug-error-leak-detector`)، دستکاری نوع محتوا و ایجاد ابهام بین JSON/XML/YAML (`content-type-tamper-tester`)، انحراف قرارداد وب‌سرویس و OpenAPI بر پایه متدولوژی Dredd (`api-contract-drift-auditor`)، ممیزی قواعد امنیتی OpenAPI با Spectral (`openapi-spec-linter`)، انگشت‌نگاری موتورهای GraphQL نظیر Apollo/Hasura با graphw00f (`graphql-engine-fingerprinter`)، تولید پی‌لودهای استثمار SSRF با پروتکل Gopher برای ردیس و دیتابیس (`ssrf-gopher-payload-generator`)، موتور دورزدن مسیر و LFI با فیلترهای PHP بر پایه LFImap (`lfi-path-traversal-engine`)، تزریق در میدل‌ورهای جاوا/J2EE بر پایه J2EEScan (`j2ee-deserialization-auditor`)، در کنار ده‌ها ماژول SQLi، XSS پولی‌گلات، BOLA، قاچاق درخواست HTTP (Smuggling)، آلودگی پروتوتایپ، CORS و فازینگ بازگشتی مسیر با ffuf.
2. **شناسایی دارایی‌ها، DNS و OSINT (بیش از ۲۵ ماژول):** پروب سریع وضعیت پاسخگویی HTTP/HTTPS بر پایه httprobe (`live-http-service-prober`)، استخراج دامنه‌ها از افزونه SAN گواهینامه‌های TLS بر پایه cero (`tls-san-domain-extractor`)، پویش معکوس آدرس‌های IP و PTR بر پایه hakrevdns (`reverse-dns-ptr-scanner`)، استخراج غیرفعال ساب‌دامین (`subdomain-passive-miner` بر پایه Amass/Subfinder)، نگاشت رنج‌های ASN و BGP (`asn-ip-range-mapper`)، نظارت بر تایپواسکواتینگ و برند (`typosquatting-brand-monitor` بر پایه dnstwist)، تجمیع افشاگری‌های OSINT از شودن/سنسیس/فوفا (`osint-search-exposure`)، انگشت‌نگاری فناوری وب (`web-technology-fingerprinter`)، بایپس و شناسایی WAF/CDN (`cdn-waf-detector`)، و ماینر آرشیو اینترنت Wayback (`historical-url-miner`).
3. **امنیت ابری، زیرساخت و کانتینرها (بیش از ۳۵ ماژول):** ارزیابی جامع استانداردهای CIS ابری بر پایه Prowler (`cloud-prowler-compliance`)، کشف منابع ذخیره‌سازی چندابری AWS/Azure/GCP بر پایه cloud_enum (`multi-cloud-resource-enumerator`)، آگاهی موقعیتی از دسترسی‌ها و مسیرهای نفوذ ابری با CloudFox (`cloudfox-privilege-analyzer`)، ممیزی سکیوریتی‌گروپ‌ها و پورت‌های باز اینترنت بر پایه CloudMapper (`aws-security-group-analyzer`)، بردارهای افزایش سطح دسترسی در AWS بر پایه Pacu (`aws-pacu-attack-surface-auditor`)، انطباق کانتینر با استانداردهای امنیتی و ایمیج بر پایه Dockle (`container-image-compliance-dockle`)، لینتر امنیتی داکرفایل با Hadolint (`dockerfile-security-linter`)، اسکنر چندموتوره زیرساخت مبتنی بر کد با KICS و Terrascan (`kics-iac-security-scanner`)، ارزیابی نودها با بنچمارک CIS کوبرنتیز با kube-bench (`kubernetes-cis-bench-auditor`)، اعتبارسنجی مانیفست‌های کوبرنتیز و Helm با KubeLinter (`kubernetes-yaml-linter`)، و ارزیابی سیاست‌های سازمانی با موتور Rego و OPA بر پایه Conftest (`rego-policy-enforcement-checker`).
4. **تحلیل ایستای سورس کد (SAST) و مهندسی معکوس (بیش از ۱۰ ماژول):** ممیزی آسیب‌پذیری‌های امنیتی سورس کدهای جاوا و بایت‌کد بر پایه Find Security Bugs و SpotBugs (`java-source-sast-auditor`)، تحلیل کدهای C# و دات‌نت بر پایه Security Code Scan (`dotnet-security-code-analyzer`)، ردیابی جریان داده و Taint Analysis در کدهای PHP با Progpilot (`php-taint-source-analyzer`)، و گراف ویژگی‌های کد (CPG) و کوئری‌های AST با Joern (`code-property-graph-analyzer`).
5. **زنجیره تامین نرم‌افزار، SBOM و ممیزی بسته‌ها (بیش از ۱۵ ماژول):** تولید صورت مواد نرم‌افزار (SBOM) در قالب‌های CycloneDX و SPDX با Syft (`sbom-generator-syft`)، ارزیابی امنیت ریپازیتوری‌های کد بر پایه OpenSSF Scorecard (`openssf-supply-chain-scorecard`)، تحلیل رفتارهای مشکوک و اسکریپت‌های مخرب در پکیج‌های npm/PyPI بر پایه Socket.dev (`malicious-dependency-behavior-analyzer`)، ممیزی امنیتی وابستگی‌های Ruby با bundler-audit (`ruby-bundler-security-auditor`)، ممیزی پکیج‌های زبان Rust با cargo-audit (`rust-cargo-security-auditor`)، و بررسی بسته‌های PHP با Composer audit (`php-composer-security-auditor`).
6. **هویت، پسورد، جرم‌شناسی و هوش مصنوعی دفاعی (بیش از ۱۵ ماژول):** اکتیو دایرکتوری (AS-REP Roasting / Kerberoasting)، پسوردهای تکراری، LDAP StartTLS، اعتبارسنجی متادیتای SAML، ارزیابی بدافزار با انتروپی شانون، بازرسی بسته‌های شبکه PCAP، مپینگ تاکتیک‌های MITRE ATT&CK، لاگ‌های SIEM، و دستیار هوش مصنوعی دفاعی دو زبانه (فارسی/انگلیسی).

---

## 🧪 ماتریکس آزمون و اعتبارسنجی ۱۷۴/۱۷۴

تمام ۱۷۴ ماژول در ۵ گیت سخت‌گیرانه تست و تایید شده‌اند:
- **Manifest:** بررسی درستی فیلدهای پیکربندی و نگارش
- **Artifact:** محاسبه و تطابق هش امنیتی SHA-256
- **Health:** ارتباط از طریق پروتکل Stdio IPC JSON
- **Scope:** رد اهداف غیرمجاز توسط ScopeGuard
- **RunTask:** اجرای موفق اسکن در حالت شبیه‌سازی و تولید خروجی استاندارد

---

## ⚖️ لایسنس و قوانین اخلاقی

پروژه تحت **مجوز آپاچی ۲.۰ (Apache License 2.0)** منتشر شده است.

> **تذکر حقوقی و اخلاقی:** سایبر هاشیرا صرفاً برای تست‌های نفوذ مجاز، اهداف تحقیقاتی و آموزشی و با رضایت کتبی و رسمی صاحبان سیستم‌ها ساخته شده است. هرگونه اسکن یا حمله بدون مجوز طبق قوانین بین‌المللی و داخلی جرم محسوب می‌شود.
