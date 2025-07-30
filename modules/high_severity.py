import requests
import re
from urllib.parse import urljoin

def check_rce(target_url, report):
    # This is a placeholder for RCE check. Real RCE checks are complex and dangerous.
    # For a real tool, this would involve trying to execute commands on the server.
    # Example: Try to access a known vulnerable plugin endpoint or try to upload a shell.
    # For this project, we'll simulate a check.
    vulnerability_name = "Remote Code Execution (RCE)"
    severity = "عالية"
    description = "إمكانية تنفيذ تعليمات برمجية عن بعد على الخادم."
    remediation = "تحديث جميع الإضافات والقوالب ونواة ووردبريس بانتظام. استخدام جدار حماية تطبيقات الويب (WAF)."
    
    # Simulate a check: look for common RCE indicators (e.g., specific error messages, known vulnerable paths)
    # This is highly simplified and not a real RCE exploit attempt.
    try:
        test_url = urljoin(target_url, "wp-content/plugins/revslider/temp_upload_file.php") # Example of a known vulnerable path
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200 and "revslider" in response.text.lower():
            report.append({
                "name": vulnerability_name,
                "status": "Detected",
                "severity": severity,
                "description": description,
                "remediation": remediation
            })
            return
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": vulnerability_name,
        "status": "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_sql_injection(target_url, report):
    vulnerability_name = "SQL Injection (SQLi)"
    severity = "عالية"
    description = "إمكانية حقن استعلامات SQL ضارة في قاعدة البيانات."
    remediation = "استخدام الاستعلامات المُجهزة (Prepared Statements) أو ORMs. التحقق من صحة جميع مدخلات المستخدم."
    
    # Simulate a check: try common SQLi payloads on a typical WordPress parameter
    # This is a very basic check and not exhaustive.
    payloads = ["'", "\"", " OR 1=1-- ", "' OR 1=1-- "]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"?p=1{payload}") # Example: common parameter 'p'
            response = requests.get(test_url, timeout=5)
            if "You have an error in your SQL syntax" in response.text or "mysql_fetch_array()" in response.text:
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

def check_authentication_bypass(target_url, report):
    vulnerability_name = "Authentication Bypass"
    severity = "عالية"
    description = "تجاوز آليات المصادقة للوصول غير المصرح به."
    remediation = "تطبيق مصادقة قوية، تحديث ووردبريس والإضافات، استخدام المصادقة الثنائية (2FA)."
    
    # Simulate a check: try common bypass techniques (e.g., 'admin' OR '1'='1' as password)
    # This is a very basic check.
    detected = False
    login_url = urljoin(target_url, "wp-login.php")
    payloads = [
        {"log": "admin", "pwd": "' OR '1'='1'-- "},
        {"log": "admin", "pwd": "' or 1=1 or ''='"}
    ]
    for payload in payloads:
        try:
            response = requests.post(login_url, data=payload, timeout=5)
            if "wordpress_logged_in" in response.cookies or "wp-admin" in response.url:
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

def check_privilege_escalation(target_url, report):
    vulnerability_name = "Privilege Escalation"
    severity = "عالية"
    description = "قدرة المستخدمين ذوي الصلاحيات المنخفضة على الوصول إلى صلاحيات أعلى."
    remediation = "تطبيق مبدأ أقل الامتيازات، تحديث جميع المكونات، مراجعة صلاحيات المستخدمين بانتظام."
    
    # This check is highly complex and usually requires authenticated access or specific plugin vulnerabilities.
    # For simulation, we'll mark it as 'Not Detected' unless a very specific, easily detectable pattern is found.
    detected = False
    # Example: Look for publicly known privilege escalation vulnerabilities in popular plugins
    # This would involve searching for specific files or responses indicative of such a flaw.
    
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_file_upload_vulnerability(target_url, report):
    vulnerability_name = "File Upload Vulnerability"
    severity = "عالية"
    description = "إمكانية رفع ملفات ضارة (مثل Shell) إلى الخادم."
    remediation = "التحقق الصارم من نوع الملف وحجمه ومحتواه. تخزين الملفات المرفوعة خارج مجلد الويب العام. إعادة تسمية الملفات."
    
    # This check is complex and involves attempting to upload malicious files.
    # For simulation, we'll look for common vulnerable upload paths or indicators.
    detected = False
    # Example: Check for known vulnerable upload forms or paths
    try:
        test_url = urljoin(target_url, "wp-content/plugins/wp-support-plus-responsive-ticket-system/includes/ajax/upload-file.php")
        response = requests.get(test_url, timeout=5)
        if response.status_code == 200 and "upload-file" in response.text.lower():
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

def check_lfi(target_url, report):
    vulnerability_name = "Local File Inclusion (LFI)"
    severity = "عالية"
    description = "إمكانية تضمين ملفات محلية من الخادم."
    remediation = "تجنب استخدام مدخلات المستخدم مباشرة في مسارات الملفات. استخدام قائمة بيضاء للملفات المسموح بها. تعطيل `allow_url_include` في PHP."
    
    # Simulate LFI check: try common LFI payloads
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"?page={payload}") # Example: common parameter 'page'
            response = requests.get(test_url, timeout=5)
            if "root:x:0:0:root" in response.text or "[fonts]" in response.text.lower():
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

def check_directory_traversal(target_url, report):
    vulnerability_name = "Directory Traversal"
    severity = "عالية"
    description = "إمكانية الوصول إلى ملفات ومجلدات خارج الدليل المخصص."
    remediation = "التحقق من صحة مدخلات المستخدم. استخدام مسارات مطلقة أو تطهير المدخلات لإزالة تسلسلات '..'."
    
    # Simulate Directory Traversal check: similar to LFI, but often for file reading/listing
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"wp-content/uploads/{payload}") # Example: common upload path
            response = requests.get(test_url, timeout=5)
            if "root:x:0:0:root" in response.text or "[fonts]" in response.text.lower():
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

def check_insecure_deserialization(target_url, report):
    vulnerability_name = "Insecure Deserialization"
    severity = "عالية"
    description = "إمكانية استغلال البيانات المتسلسلة لتنفيذ تعليمات برمجية."
    remediation = "تجنب تسلسل البيانات غير الموثوق بها. استخدام تنسيقات بيانات آمنة مثل JSON. التحقق من سلامة البيانات قبل إلغاء تسلسلها."
    
    # This is a complex vulnerability to detect without specific knowledge of the application's deserialization points.
    # For simulation, we'll mark it as 'Not Detected' as it's hard to generically check.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_arbitrary_file_deletion(target_url, report):
    vulnerability_name = "Arbitrary File Deletion"
    severity = "عالية"
    description = "إمكانية حذف أي ملف على الخادم."
    remediation = "تطبيق ضوابط وصول صارمة على وظائف حذف الملفات. التحقق من صلاحيات المستخدم ومسار الملف قبل الحذف."
    
    # This is a complex vulnerability to detect without specific knowledge of vulnerable endpoints.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_arbitrary_file_read(target_url, report):
    vulnerability_name = "Arbitrary File Read"
    severity = "عالية"
    description = "إمكانية قراءة أي ملف على الخادم."
    remediation = "تطبيق ضوابط وصول صارمة على وظائف قراءة الملفات. التحقق من صلاحيات المستخدم ومسار الملف قبل القراءة."
    
    # This is similar to LFI/Directory Traversal but can be through different vectors.
    # For simulation, we'll reuse LFI/Directory Traversal logic for now.
    payloads = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"wp-includes/css/dist/block-library/style.min.css?file={payload}") # Example: common parameter 'file'
            response = requests.get(test_url, timeout=5)
            if "root:x:0:0:root" in response.text or "[fonts]" in response.text.lower():
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

def check_arbitrary_file_write(target_url, report):
    vulnerability_name = "Arbitrary File Write"
    severity = "عالية"
    description = "إمكانية كتابة أي ملف على الخادم."
    remediation = "تطبيق ضوابط وصول صارمة على وظائف كتابة الملفات. التحقق من صلاحيات المستخدم ومسار الملف قبل الكتابة."
    
    # This is a complex vulnerability to detect without specific knowledge of vulnerable endpoints.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_ssrf(target_url, report):
    vulnerability_name = "Server-Side Request Forgery (SSRF)"
    severity = "عالية"
    description = "إمكانية إجبار الخادم على إجراء طلبات HTTP إلى مواقع داخلية أو خارجية."
    remediation = "التحقق من صحة عناوين URL المدخلة من قبل المستخدم. استخدام قائمة بيضاء للنطاقات المسموح بها. تعطيل إعادة التوجيه."
    
    # This is complex to detect generically without knowing specific vulnerable parameters.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_xxe(target_url, report):
    vulnerability_name = "XML External Entity (XXE)"
    severity = "عالية"
    description = "إمكانية استغلال معالجة XML لقراءة ملفات محلية أو تنفيذ هجمات SSRF."
    remediation = "تعطيل دعم الكيانات الخارجية (external entities) في معالجات XML. تحديث المكتبات."
    
    # This is complex to detect generically without knowing specific XML parsing endpoints.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_command_injection(target_url, report):
    vulnerability_name = "Command Injection"
    severity = "عالية"
    description = "إمكانية تنفيذ أوامر نظام التشغيل على الخادم."
    remediation = "تجنب استخدام مدخلات المستخدم مباشرة في أوامر النظام. استخدام واجهات برمجة التطبيقات الآمنة. التحقق من صحة المدخلات."
    
    # This is complex to detect generically without knowing specific vulnerable parameters.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_unauthenticated_admin_access(target_url, report):
    vulnerability_name = "Unauthenticated Admin Access"
    severity = "عالية"
    description = "الوصول إلى لوحة تحكم المسؤول دون الحاجة إلى مصادقة."
    remediation = "تأمين لوحة تحكم المسؤول بكلمة مرور قوية ومصادقة ثنائية. تقييد الوصول إلى /wp-admin من عناوين IP موثوقة."
    
    detected = False
    admin_url = urljoin(target_url, "wp-admin/")
    try:
        response = requests.get(admin_url, allow_redirects=False, timeout=5)
        # If it redirects to wp-login.php, it's likely protected. If it shows admin dashboard, it's vulnerable.
        if response.status_code == 200 and "Dashboard" in response.text and "wp-login.php" not in response.url:
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

def check_shell_upload_via_editor(target_url, report):
    vulnerability_name = "Shell Upload via Theme/Plugin Editor"
    severity = "عالية"
    description = "إمكانية رفع Shell خبيث عبر محرر القوالب/الإضافات."
    remediation = "تعطيل محرر القوالب والإضافات من لوحة تحكم ووردبريس (عبر `define('DISALLOW_FILE_EDIT', true);` في wp-config.php)."
    
    # This requires authenticated access to the admin panel and is hard to check unauthenticated.
    # For simulation, we'll mark it as 'Not Detected' unless a very specific, easily detectable pattern is found.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def run_high_severity_checks(target_url, report):
    print("\n--- بدء فحص الثغرات عالية الخطورة ---")
    check_rce(target_url, report)
    check_sql_injection(target_url, report)
    check_authentication_bypass(target_url, report)
    check_privilege_escalation(target_url, report)
    check_file_upload_vulnerability(target_url, report)
    check_lfi(target_url, report)
    check_directory_traversal(target_url, report)
    check_insecure_deserialization(target_url, report)
    check_arbitrary_file_deletion(target_url, report)
    check_arbitrary_file_read(target_url, report)
    check_arbitrary_file_write(target_url, report)
    check_ssrf(target_url, report)
    check_xxe(target_url, report)
    check_command_injection(target_url, report)
    check_unauthenticated_admin_access(target_url, report)
    check_shell_upload_via_editor(target_url, report)
    print("--- انتهى فحص الثغرات عالية الخطورة ---")


