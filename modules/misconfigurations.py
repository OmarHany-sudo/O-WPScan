import requests
import re
from urllib.parse import urljoin

def check_exposed_xmlrpc(target_url, report):
    vulnerability_name = "Exposed XML-RPC"
    severity = "متوسطة"
    description = "تعرض XML-RPC endpoint مما يسمح بهجمات brute force وDDoS."
    remediation = "تعطيل XML-RPC إذا لم يكن مستخدماً، أو تقييد الوصول إليه."
    
    detected = False
    try:
        xmlrpc_url = urljoin(target_url, "xmlrpc.php")
        response = requests.get(xmlrpc_url, timeout=5)
        if response.status_code == 200 and "XML-RPC server accepts POST requests only" in response.text:
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_weak_wp_config_permissions(target_url, report):
    vulnerability_name = "Weak wp-config.php permissions"
    severity = "عالية"
    description = "صلاحيات ضعيفة على ملف wp-config.php قد تسمح بقراءته."
    remediation = "تطبيق صلاحيات 600 أو 644 على wp-config.php، نقله خارج المجلد العام."
    
    detected = False
    try:
        config_url = urljoin(target_url, "wp-config.php")
        response = requests.get(config_url, timeout=5)
        if response.status_code == 200 and ("DB_NAME" in response.text or "DB_USER" in response.text):
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_no_http_security_headers(target_url, report):
    vulnerability_name = "No HTTP Security Headers"
    severity = "متوسطة"
    description = "عدم وجود HTTP security headers مثل CSP، X-Frame-Options، إلخ."
    remediation = "إضافة HTTP security headers: Content-Security-Policy، X-Frame-Options، X-Content-Type-Options، إلخ."
    
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security'
        ]
        missing_headers = []
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        
        if len(missing_headers) >= 3:  # If 3 or more security headers are missing
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_admin_panel_exposed(target_url, report):
    vulnerability_name = "Admin Panel Exposed"
    severity = "متوسطة"
    description = "لوحة تحكم المسؤول مكشوفة دون حماية إضافية."
    remediation = "تقييد الوصول إلى /wp-admin من عناوين IP موثوقة، استخدام .htaccess أو جدار حماية."
    
    detected = False
    try:
        admin_url = urljoin(target_url, "wp-admin/")
        response = requests.get(admin_url, timeout=5)
        if response.status_code == 200 or (response.status_code in [301, 302] and "wp-login.php" in response.headers.get('Location', '')):
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_default_usernames(target_url, report):
    vulnerability_name = "Default Usernames"
    severity = "متوسطة"
    description = "استخدام أسماء مستخدمين افتراضية مثل 'admin' أو 'administrator'."
    remediation = "تغيير أسماء المستخدمين الافتراضية، استخدام أسماء مستخدمين قوية وغير متوقعة."
    
    detected = False
    try:
        # Check if REST API reveals usernames
        api_url = urljoin(target_url, "wp-json/wp/v2/users")
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            users_data = response.json()
            for user in users_data:
                if user.get('slug') in ['admin', 'administrator', 'user', 'test']:
                    detected = True
                    break
    except (requests.exceptions.RequestException, ValueError):
        pass

    # Alternative method: check author archives
    try:
        author_url = urljoin(target_url, "?author=1")
        response = requests.get(author_url, allow_redirects=True, timeout=5)
        if "/author/admin" in response.url or "/author/administrator" in response.url:
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_weak_passwords(target_url, report):
    vulnerability_name = "Weak Passwords (Brute-force vulnerability)"
    severity = "عالية"
    description = "استخدام كلمات مرور ضعيفة قابلة للكسر بهجمات brute force."
    remediation = "استخدام كلمات مرور قوية، تطبيق سياسات كلمات المرور، استخدام إضافات لمنع brute force."
    
    # This would require actual brute force attempts which we won't do in this simulation.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_no_2fa(target_url, report):
    vulnerability_name = "No 2FA"
    severity = "متوسطة"
    description = "عدم تطبيق المصادقة الثنائية (Two-Factor Authentication)."
    remediation = "تطبيق المصادقة الثنائية لجميع المستخدمين، خاصة المسؤولين."
    
    # This is hard to detect remotely without attempting to log in.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_no_captcha_on_login(target_url, report):
    vulnerability_name = "No CAPTCHA on Login"
    severity = "متوسطة"
    description = "عدم وجود CAPTCHA على صفحة تسجيل الدخول مما يسهل هجمات brute force."
    remediation = "إضافة CAPTCHA على صفحة تسجيل الدخول، استخدام إضافات مثل reCAPTCHA."
    
    detected = False
    try:
        login_url = urljoin(target_url, "wp-login.php")
        response = requests.get(login_url, timeout=5)
        if response.status_code == 200 and "captcha" not in response.text.lower() and "recaptcha" not in response.text.lower():
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_auto_indexing_enabled(target_url, report):
    vulnerability_name = "Auto Indexing Enabled"
    severity = "متوسطة"
    description = "تمكين فهرسة المجلدات تلقائياً مما يكشف محتوياتها."
    remediation = "تعطيل directory listing في إعدادات الخادم، إضافة ملفات index.html فارغة."
    
    detected = False
    # Check common directories for auto indexing
    directories = ["wp-content/uploads/", "wp-includes/", "wp-content/plugins/"]
    for directory in directories:
        try:
            dir_url = urljoin(target_url, directory)
            response = requests.get(dir_url, timeout=5)
            if response.status_code == 200 and ("Index of" in response.text or "<title>Index of" in response.text):
                detected = True
                break
        except requests.exceptions.RequestException:
            pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_backup_files_exposed(target_url, report):
    vulnerability_name = "Backup Files Exposed"
    severity = "عالية"
    description = "تعرض ملفات النسخ الاحتياطية (.zip, .sql, .bak) للعامة."
    remediation = "حماية ملفات النسخ الاحتياطية، تخزينها خارج المجلد العام، استخدام .htaccess لمنع الوصول."
    
    detected = False
    # Check for common backup file patterns
    backup_files = [
        "backup.zip", "backup.sql", "backup.bak",
        "wordpress.zip", "wordpress.sql", "wordpress.bak",
        "wp-config.php.bak", "database.sql", "db.sql"
    ]
    for backup_file in backup_files:
        try:
            backup_url = urljoin(target_url, backup_file)
            response = requests.head(backup_url, timeout=5)  # Use HEAD to avoid downloading large files
            if response.status_code == 200:
                detected = True
                break
        except requests.exceptions.RequestException:
            pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_wp_cron_abuse(target_url, report):
    vulnerability_name = "WP-Cron Abuse"
    severity = "منخفضة"
    description = "إمكانية استغلال WP-Cron لتنفيذ هجمات DDoS أو استنزاف الموارد."
    remediation = "تعطيل WP-Cron العام واستخدام cron job حقيقي، أو تقييد الوصول إلى wp-cron.php."
    
    detected = False
    try:
        cron_url = urljoin(target_url, "wp-cron.php")
        response = requests.get(cron_url, timeout=5)
        if response.status_code == 200 and len(response.text) == 0:  # WP-Cron typically returns empty response
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": "منخفضة",
        "description": description,
        "remediation": remediation
    })

def check_file_editor_enabled(target_url, report):
    vulnerability_name = "File Editor Enabled"
    severity = "عالية"
    description = "تمكين محرر الملفات في لوحة التحكم مما يسمح بتعديل ملفات PHP."
    remediation = "تعطيل محرر الملفات بإضافة `define('DISALLOW_FILE_EDIT', true);` في wp-config.php."
    
    # This requires authenticated access to check. For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def run_misconfiguration_checks(target_url, report):
    print("\n--- بدء فحص الثغرات الناتجة عن الإعداد الخاطئ ---")
    check_exposed_xmlrpc(target_url, report)
    check_weak_wp_config_permissions(target_url, report)
    check_no_http_security_headers(target_url, report)
    check_admin_panel_exposed(target_url, report)
    check_default_usernames(target_url, report)
    check_weak_passwords(target_url, report)
    check_no_2fa(target_url, report)
    check_no_captcha_on_login(target_url, report)
    check_auto_indexing_enabled(target_url, report)
    check_backup_files_exposed(target_url, report)
    check_wp_cron_abuse(target_url, report)
    check_file_editor_enabled(target_url, report)
    print("--- انتهى فحص الثغرات الناتجة عن الإعداد الخاطئ ---")

