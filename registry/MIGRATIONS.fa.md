# سایبر هاشیرا — تاریخچه مهاجرت‌های اسکیما و شناسه‌های ماژول در رجیستری

این سند تمامی فرآیندهای یکپارچه‌سازی، تغییر نام، حذف شناسه‌های موازی (Aliases) و تکامل ساختار کاتالوگ رجیستری سایبر هاشیرا (`registry/v1/modules.json`) را ثبت و مستند می‌کند.

---

## مهاجرت مورخ ۱۶ نوامبر ۲۰۲۶: استانداردسازی شناسه‌ها و یکپارچه‌سازی نام‌های دوگانه

### ۱. خلاصه مغایرت‌های نام‌گذاری دوگانه شناسایی‌شده

طی بازرسی جامع رجیستری، دو مورد مغایرت تاریخی شناسایی شد که در آن‌ها نام فیزیکی پوشه با شناسه رسمی مانیفست و ورودی کاتالوگ رجیستری تفاوت داشت:

| نام تاریخی / نام پوشه قبلی | شناسه استاندارد (Canonical ID) | دسته‌بندی | آرتیفکت بسته‌بندی‌شده | تصمیم اتخاذشده |
|---|---|---|---|---|
| `forensics` | `digital-forensics` | Digital Forensics | `digital-forensics-1.0.0.tar.gz` | **ادغام و تثبیت شد** روی `digital-forensics`. پوشه فیزیکی از `modules/forensics` به `modules/digital-forensics` تغییر نام یافت. |
| `vulnerability` | `vulnerability-assessment` | Vulnerability Assessment | `vulnerability-assessment-1.0.0.tar.gz` | **ادغام و تثبیت شد** روی `vulnerability-assessment`. پوشه فیزیکی از `modules/vulnerability` به `modules/vulnerability-assessment` تغییر نام یافت. |

---

### ۲. دلایل فنی و منطق تصمیم‌گیری

هر دو جفت ماژول دقیقاً یک پیاده‌سازی واحد و بدون تکرار را نمایندگی می‌کردند:
1. **ماژول `digital-forensics`**: پیاده‌سازی کامل محاسبات هش‌های رمزنگاری (MD5, SHA-1, SHA-256)، محاسبه آنتروپی شانون برای تریاژ باینری‌های مبهم‌سازی‌شده، استخراج رشته‌های Win32 API و ثبت زنجیره شواهد (Chain-of-Custody). شناسه مانیفست این ماژول همواره `digital-forensics` بوده است.
2. **ماژول `vulnerability-assessment`**: ارزیابی آسیب‌پذیری‌های قانون‌محور مبتنی بر الگوهای نوکلئای (Nuclei) برای نگاشت CVE، CWE و CVSS. شناسه مانیفست آن همواره `vulnerability-assessment` بوده است.

---

### ۳. سازگاری رو به عقب و سیاست ریدایرکت (Backward Compatibility)

جهت تضمین پایداری کامل اسکریپت‌های کاربران، پایپ‌لاین‌های CI/CD و اتوماسیون‌های موجود:
- **ریدایرکت خودکار شناسه‌های قدیمی:** لانچر اصلی (`hashira.py`) و وب پنل (`ui/web/app.py`) به صورت هوشمند شناسه‌های قدیمی را به شناسه استاندارد جدید نگاشت می‌کنند:
  - `"forensics"` $\rightarrow$ `"digital-forensics"`
  - `"vulnerability"` $\rightarrow$ `"vulnerability-assessment"`
- **پیام هشدار منسوخ‌شدن (Deprecation Notice):** در صورت فراخوانی نام قدیمی از خط فرمان یا IPC، هشدار زیر نمایش داده می‌شود:
  ```text
  [!] DEPRECATION WARNING: Module alias '{alias}' is deprecated and will be removed in v2.0.0.
      Redirecting seamlessly to canonical module '{canonical_id}'.
  ```
- **اسکیمای کاتالوگ رجیستری:** فیلد اختیاری `"aliases": ["..."]` به منظور رهگیری معکوس به ورودی‌های استاندارد افزوده شده است.
