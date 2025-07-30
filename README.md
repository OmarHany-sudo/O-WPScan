# O-WPScan

**O-WPScan** هي أداة احترافية مفتوحة المصدر لفحص مواقع WordPress ضد قائمة شاملة من الثغرات الأمنية. تم تطويرها باستخدام لغة Python وتوفر واجهة سطر أوامر (CLI) سهلة الاستخدام.

## الميزات

- **فحص شامل للثغرات:** تقوم الأداة بفحص موقع WordPress المستهدف ضد مجموعة واسعة من الثغرات الأمنية المصنفة حسب درجة الخطورة (عالية، متوسطة، منخفضة).
- **تقرير مفصل:** تُخرج النتائج في ملف نصي منسق `wordpress_vuln_report.txt` يحتوي على اسم الثغرة، حالة الفحص، درجة الخطورة، شرح مختصر، ونصيحة أمنية لمعالجة أو منع كل ثغرة.
- **سهولة الاستخدام:** واجهة سطر أوامر بسيطة لتشغيل الفحص.
- **قابلية التوسيع:** هيكل الكود منظم ومرن للسماح بإضافة المزيد من وحدات الفحص في المستقبل.

## الثغرات التي يتم فحصها

### 🔥 ثغرات عالية الخطورة:
- Remote Code Execution (RCE)
- SQL Injection (SQLi)
- Authentication Bypass
- Privilege Escalation
- File Upload Vulnerability
- Local File Inclusion (LFI)
- Directory Traversal
- Insecure Deserialization
- Arbitrary File Deletion
- Arbitrary File Read
- Arbitrary File Write
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Command Injection
- Unauthenticated Admin Access
- Shell Upload via Theme/Plugin Editor

### ⚠️ ثغرات متوسطة الخطورة:
- Cross-Site Scripting (XSS) — (Stored / Reflected / DOM)
- Cross-Site Request Forgery (CSRF)
- Open Redirect
- Information Disclosure
- REST API Unauthorized Access
- Insecure Direct Object Reference (IDOR)
- Clickjacking
- Open Port / Misconfigured Services
- Exposed Debug Logs
- Directory Indexing
- Version Disclosure
- Reflected File Download
- Content Spoofing
- Insecure File Permissions
- Theme/Plugin Path Disclosure

### 🧪 ثغرات ناتجة عن الإعداد الخاطئ (Misconfigurations):
- Exposed XML-RPC
- Weak wp-config.php permissions
- No HTTP Security Headers (CSP, X-Frame-Options, etc.)
- Admin Panel Exposed (/wp-admin/ without protection)
- Default Usernames (admin, editor)
- Weak Passwords (Brute-force vulnerability)
- No 2FA
- No CAPTCHA on Login
- Auto Indexing Enabled
- Backup Files Exposed (.zip, .sql, .bak)
- WP-Cron Abuse
- File Editor Enabled (via Dashboard)

### 🧩 ثغرات متعلقة بالإضافات (Plugins) والقوالب (Themes):
- Nulled Themes/Plugins (مع Backdoors)
- Insecure Update Mechanism
- Insecure AJAX Actions
- Missing Nonce Verification
- Plugin with Publicly Known Exploits
- Demo Importer Exploits
- Malicious Shortcodes
- Insecure Widget Code
- Theme/Plugin Options Injection
- No Access Control on Custom Endpoints
- Arbitrary Options Update (update_option Vulnerability)
- Arbitrary User Creation
- Theme Function Injection via functions.php

## المتطلبات

تتطلب الأداة تثبيت مكتبات Python التالية:

- `pyfiglet`
- `requests`

## التثبيت

1. استنسخ المستودع:
   ```bash
   git clone https://github.com/your-username/O-WPScan.git
   cd O-WPScan
   ```

2. قم بتثبيت المتطلبات:
   ```bash
   pip install -r requirements.txt
   ```

## الاستخدام

لتشغيل الأداة، استخدم الأمر التالي:

```bash
python3 owpscan.py
```

ستطلب منك الأداة إدخال رابط موقع WordPress المستهدف. بعد الانتهاء من الفحص، سيتم إنشاء ملف `wordpress_vuln_report.txt` في نفس المجلد يحتوي على نتائج الفحص.

## المساهمة

نرحب بالمساهمات لتحسين الأداة وإضافة المزيد من وحدات الفحص. يرجى فتح `issue` أو إرسال `pull request`.

## الترخيص

هذا المشروع مرخص بموجب ترخيص MIT. انظر ملف `LICENSE` لمزيد من التفاصيل.

## شكر وتقدير

Project by Eng.Omar Hany Shalaby


