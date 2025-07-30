import requests
import re
from urllib.parse import urljoin

def check_xss(target_url, report):
    vulnerability_name = "Cross-Site Scripting (XSS)"
    severity = "متوسطة"
    description = "إمكانية حقن سكريبت JavaScript ضار في صفحات الموقع."
    remediation = "تطهير جميع مدخلات المستخدم، استخدام Content Security Policy (CSP)، تشفير المخرجات."
    
    # Simulate XSS check: try common XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"?s={payload}") # Example: search parameter 's'
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
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

def check_csrf(target_url, report):
    vulnerability_name = "Cross-Site Request Forgery (CSRF)"
    severity = "متوسطة"
    description = "إمكانية تنفيذ إجراءات غير مرغوب فيها نيابة عن المستخدم المصادق عليه."
    remediation = "استخدام CSRF tokens، التحقق من HTTP Referer header، استخدام SameSite cookies."
    
    # This is complex to detect without specific knowledge of forms and their protection mechanisms.
    # For simulation, we'll mark it as 'Not Detected' unless a very specific, easily detectable pattern is found.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_open_redirect(target_url, report):
    vulnerability_name = "Open Redirect"
    severity = "متوسطة"
    description = "إمكانية إعادة توجيه المستخدمين إلى مواقع ضارة."
    remediation = "التحقق من صحة عناوين URL المدخلة، استخدام قائمة بيضاء للنطاقات المسموح بها."
    
    # Simulate Open Redirect check: try common redirect parameters
    payloads = [
        "http://evil.com",
        "//evil.com",
        "https://evil.com"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"wp-login.php?redirect_to={payload}")
            response = requests.get(test_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 303, 307, 308] and payload in response.headers.get('Location', ''):
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

def check_information_disclosure(target_url, report):
    vulnerability_name = "Information Disclosure"
    severity = "متوسطة"
    description = "كشف معلومات حساسة مثل أرقام الإصدارات أو مسارات الملفات."
    remediation = "إخفاء أرقام الإصدارات، تعطيل عرض الأخطاء في بيئة الإنتاج، تأمين ملفات التكوين."
    
    detected = False
    # Check for version disclosure in HTML source
    try:
        response = requests.get(target_url, timeout=5)
        if re.search(r'wp-includes/version\.php', response.text) or re.search(r'content="WordPress \d+\.\d+', response.text):
            detected = True
    except requests.exceptions.RequestException:
        pass

    # Check for readme.html
    try:
        readme_url = urljoin(target_url, "readme.html")
        response = requests.get(readme_url, timeout=5)
        if response.status_code == 200 and "WordPress" in response.text:
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

def check_rest_api_unauthorized_access(target_url, report):
    vulnerability_name = "REST API Unauthorized Access"
    severity = "متوسطة"
    description = "الوصول غير المصرح به إلى WordPress REST API."
    remediation = "تقييد الوصول إلى REST API، استخدام المصادقة المناسبة، تعطيل endpoints غير المستخدمة."
    
    detected = False
    # Check if REST API is accessible and returns sensitive information
    try:
        api_url = urljoin(target_url, "wp-json/wp/v2/users")
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200 and "slug" in response.text:
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

def check_idor(target_url, report):
    vulnerability_name = "Insecure Direct Object Reference (IDOR)"
    severity = "متوسطة"
    description = "الوصول إلى كائنات أو بيانات غير مصرح بها عبر تغيير معرفات الكائنات."
    remediation = "تطبيق ضوابط وصول صارمة، التحقق من صلاحيات المستخدم قبل الوصول إلى الكائنات."
    
    # This is complex to detect without specific knowledge of the application's object references.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_clickjacking(target_url, report):
    vulnerability_name = "Clickjacking"
    severity = "متوسطة"
    description = "إمكانية خداع المستخدمين للنقر على عناصر مخفية أو مضللة."
    remediation = "استخدام X-Frame-Options header أو Content Security Policy (CSP) frame-ancestors directive."
    
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        x_frame_options = response.headers.get('X-Frame-Options', '').lower()
        csp = response.headers.get('Content-Security-Policy', '').lower()
        
        if not x_frame_options and 'frame-ancestors' not in csp:
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

def check_open_port_misconfigured_services(target_url, report):
    vulnerability_name = "Open Port / Misconfigured Services"
    severity = "متوسطة"
    description = "وجود منافذ مفتوحة أو خدمات مُعدة بشكل خاطئ."
    remediation = "إغلاق المنافذ غير المستخدمة، تأمين الخدمات المكشوفة، استخدام جدار حماية."
    
    # This requires port scanning which can be intrusive. For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_exposed_debug_logs(target_url, report):
    vulnerability_name = "Exposed Debug Logs"
    severity = "متوسطة"
    description = "كشف ملفات سجلات التصحيح التي قد تحتوي على معلومات حساسة."
    remediation = "تعطيل تسجيل التصحيح في بيئة الإنتاج، حماية ملفات السجلات من الوصول العام."
    
    detected = False
    # Check for common debug log files
    debug_files = ["debug.log", "error.log", "wp-content/debug.log"]
    for debug_file in debug_files:
        try:
            debug_url = urljoin(target_url, debug_file)
            response = requests.get(debug_url, timeout=5)
            if response.status_code == 200 and ("PHP" in response.text or "WordPress" in response.text):
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

def check_directory_indexing(target_url, report):
    vulnerability_name = "Directory Indexing"
    severity = "متوسطة"
    description = "إمكانية عرض محتويات المجلدات عبر المتصفح."
    remediation = "تعطيل directory listing في إعدادات الخادم، إضافة ملفات index.html فارغة في المجلدات الحساسة."
    
    detected = False
    # Check common directories for indexing
    directories = ["wp-content/", "wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/"]
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

def check_version_disclosure(target_url, report):
    vulnerability_name = "Version Disclosure"
    severity = "متوسطة"
    description = "كشف إصدار ووردبريس أو الإضافات أو القوالب."
    remediation = "إخفاء أرقام الإصدارات من HTML source، استخدام إضافات لإخفاء معلومات الإصدار."
    
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        # Check for WordPress version in meta tags or generator tags
        if re.search(r'name="generator" content="WordPress \d+\.\d+', response.text, re.IGNORECASE):
            detected = True
        # Check for version in CSS/JS file paths
        if re.search(r'wp-includes/.*\?ver=\d+\.\d+', response.text):
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

def check_reflected_file_download(target_url, report):
    vulnerability_name = "Reflected File Download"
    severity = "متوسطة"
    description = "إمكانية خداع المستخدمين لتحميل ملفات ضارة."
    remediation = "التحقق من صحة أسماء الملفات ومحتواها، استخدام Content-Disposition headers المناسبة."
    
    # This is complex to detect without specific knowledge of download endpoints.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_content_spoofing(target_url, report):
    vulnerability_name = "Content Spoofing"
    severity = "متوسطة"
    description = "إمكانية تزوير محتوى الصفحة لخداع المستخدمين."
    remediation = "تطهير مدخلات المستخدم، استخدام Content Security Policy (CSP)."
    
    # This is similar to XSS but focuses on content manipulation rather than script execution.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_insecure_file_permissions(target_url, report):
    vulnerability_name = "Insecure File Permissions"
    severity = "متوسطة"
    description = "صلاحيات ملفات غير آمنة قد تسمح بالوصول غير المصرح به."
    remediation = "تطبيق صلاحيات ملفات مناسبة (644 للملفات، 755 للمجلدات)، حماية wp-config.php."
    
    # This is hard to detect remotely without specific server access.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_theme_plugin_path_disclosure(target_url, report):
    vulnerability_name = "Theme/Plugin Path Disclosure"
    severity = "متوسطة"
    description = "كشف مسارات القوالب والإضافات مما يساعد المهاجمين في استهدافها."
    remediation = "إخفاء مسارات القوالب والإضافات، استخدام إضافات لإخفاء هذه المعلومات."
    
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        # Check for theme/plugin paths in HTML source
        if re.search(r'wp-content/themes/[^/]+', response.text) or re.search(r'wp-content/plugins/[^/]+', response.text):
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

def run_medium_severity_checks(target_url, report):
    print("\n--- بدء فحص الثغرات متوسطة الخطورة ---")
    check_xss(target_url, report)
    check_csrf(target_url, report)
    check_open_redirect(target_url, report)
    check_information_disclosure(target_url, report)
    check_rest_api_unauthorized_access(target_url, report)
    check_idor(target_url, report)
    check_clickjacking(target_url, report)
    check_open_port_misconfigured_services(target_url, report)
    check_exposed_debug_logs(target_url, report)
    check_directory_indexing(target_url, report)
    check_version_disclosure(target_url, report)
    check_reflected_file_download(target_url, report)
    check_content_spoofing(target_url, report)
    check_insecure_file_permissions(target_url, report)
    check_theme_plugin_path_disclosure(target_url, report)
    print("--- انتهى فحص الثغرات متوسطة الخطورة ---")

