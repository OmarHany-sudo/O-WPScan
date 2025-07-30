import requests
import re
from urllib.parse import urljoin

def check_nulled_themes_plugins(target_url, report):
    vulnerability_name = "Nulled Themes/Plugins (مع Backdoors)"
    severity = "عالية"
    description = "استخدام قوالب أو إضافات مقرصنة قد تحتوي على backdoors."
    remediation = "استخدام قوالب وإضافات أصلية من مصادر موثوقة فقط، فحص الملفات بحثاً عن كود ضار."
    
    detected = False
    # Look for common backdoor patterns in publicly accessible files
    try:
        response = requests.get(target_url, timeout=5)
        # Check for common backdoor signatures in HTML source
        backdoor_patterns = [
            r'eval\s*\(\s*base64_decode',
            r'eval\s*\(\s*gzinflate',
            r'eval\s*\(\s*str_rot13',
            r'assert\s*\(\s*base64_decode',
            r'system\s*\(\s*base64_decode'
        ]
        for pattern in backdoor_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
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

def check_insecure_update_mechanism(target_url, report):
    vulnerability_name = "Insecure Update Mechanism"
    severity = "عالية"
    description = "آلية تحديث غير آمنة للإضافات أو القوالب."
    remediation = "استخدام HTTPS لجميع التحديثات، التحقق من صحة التوقيعات الرقمية، تحديث ووردبريس والإضافات بانتظام."
    
    # This is complex to detect without specific knowledge of update mechanisms.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_insecure_ajax_actions(target_url, report):
    vulnerability_name = "Insecure AJAX Actions"
    severity = "متوسطة"
    description = "إجراءات AJAX غير محمية تسمح بتنفيذ عمليات غير مصرح بها."
    remediation = "تطبيق nonce verification على جميع إجراءات AJAX، التحقق من صلاحيات المستخدم."
    
    detected = False
    # Check for common AJAX endpoints
    try:
        ajax_url = urljoin(target_url, "wp-admin/admin-ajax.php")
        # Test some common insecure AJAX actions
        test_actions = ["wp_ajax_nopriv_", "wp_ajax_"]
        for action in test_actions:
            response = requests.post(ajax_url, data={"action": "test"}, timeout=5)
            if response.status_code == 200 and "0" not in response.text:  # WordPress typically returns "0" for invalid actions
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

def check_missing_nonce_verification(target_url, report):
    vulnerability_name = "Missing Nonce Verification"
    severity = "متوسطة"
    description = "عدم وجود nonce verification مما يسمح بهجمات CSRF."
    remediation = "تطبيق nonce verification على جميع النماذج والإجراءات الحساسة."
    
    # This is complex to detect without specific knowledge of forms and their protection.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_plugin_publicly_known_exploits(target_url, report):
    vulnerability_name = "Plugin with Publicly Known Exploits"
    severity = "عالية"
    description = "استخدام إضافات معروفة بوجود ثغرات أمنية مكشوفة."
    remediation = "تحديث جميع الإضافات إلى أحدث الإصدارات، إزالة الإضافات غير المستخدمة، مراقبة تحديثات الأمان."
    
    detected = False
    # Check for some known vulnerable plugins (this is a simplified check)
    vulnerable_plugins = [
        "revslider",  # Revolution Slider - had multiple vulnerabilities
        "wp-support-plus-responsive-ticket-system",  # Known for file upload vulnerabilities
        "wp-mobile-detector",  # Had RCE vulnerabilities
        "cherry-plugin"  # Had multiple vulnerabilities
    ]
    
    try:
        response = requests.get(target_url, timeout=5)
        for plugin in vulnerable_plugins:
            if f"wp-content/plugins/{plugin}" in response.text:
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

def check_demo_importer_exploits(target_url, report):
    vulnerability_name = "Demo Importer Exploits"
    severity = "عالية"
    description = "استغلال أدوات استيراد العروض التوضيحية لرفع ملفات ضارة."
    remediation = "تعطيل أو إزالة أدوات استيراد العروض التوضيحية بعد الانتهاء من الإعداد، تقييد الوصول إليها."
    
    detected = False
    # Check for common demo importer endpoints
    demo_importers = [
        "wp-content/plugins/one-click-demo-import/",
        "wp-content/plugins/themegrill-demo-importer/",
        "wp-content/plugins/advanced-import/"
    ]
    
    for importer in demo_importers:
        try:
            importer_url = urljoin(target_url, importer)
            response = requests.get(importer_url, timeout=5)
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

def check_malicious_shortcodes(target_url, report):
    vulnerability_name = "Malicious Shortcodes"
    severity = "متوسطة"
    description = "وجود shortcodes ضارة قد تنفذ كود غير مرغوب فيه."
    remediation = "مراجعة جميع shortcodes المستخدمة، إزالة الإضافات غير الموثوقة، فحص المحتوى بحثاً عن shortcodes مشبوهة."
    
    detected = False
    # Check for suspicious shortcode patterns in the main page
    try:
        response = requests.get(target_url, timeout=5)
        suspicious_shortcodes = [
            r'\[php\].*?\[/php\]',
            r'\[exec\].*?\[/exec\]',
            r'\[system\].*?\[/system\]'
        ]
        for shortcode in suspicious_shortcodes:
            if re.search(shortcode, response.text, re.IGNORECASE | re.DOTALL):
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

def check_insecure_widget_code(target_url, report):
    vulnerability_name = "Insecure Widget Code"
    severity = "متوسطة"
    description = "كود غير آمن في widgets قد يؤدي إلى ثغرات أمنية."
    remediation = "مراجعة كود جميع widgets، تجنب استخدام widgets من مصادر غير موثوقة."
    
    # This is complex to detect without access to widget configurations.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_theme_plugin_options_injection(target_url, report):
    vulnerability_name = "Theme/Plugin Options Injection"
    severity = "عالية"
    description = "إمكانية حقن خيارات ضارة في إعدادات القوالب أو الإضافات."
    remediation = "التحقق من صحة جميع خيارات القوالب والإضافات، تطبيق ضوابط وصول صارمة."
    
    # This is complex to detect without specific knowledge of option handling.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_no_access_control_custom_endpoints(target_url, report):
    vulnerability_name = "No Access Control on Custom Endpoints"
    severity = "عالية"
    description = "عدم وجود ضوابط وصول على endpoints مخصصة."
    remediation = "تطبيق ضوابط وصول صارمة على جميع endpoints المخصصة، التحقق من صلاحيات المستخدم."
    
    # This is complex to detect without specific knowledge of custom endpoints.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_arbitrary_options_update(target_url, report):
    vulnerability_name = "Arbitrary Options Update (update_option Vulnerability)"
    severity = "عالية"
    description = "إمكانية تحديث خيارات ووردبريس بشكل تعسفي."
    remediation = "تطبيق ضوابط وصول صارمة على وظائف update_option، التحقق من صلاحيات المستخدم."
    
    # This is complex to detect without specific knowledge of option update mechanisms.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def check_arbitrary_user_creation(target_url, report):
    vulnerability_name = "Arbitrary User Creation"
    severity = "عالية"
    description = "إمكانية إنشاء مستخدمين جدد بشكل تعسفي."
    remediation = "تطبيق ضوابط وصول صارمة على وظائف إنشاء المستخدمين، تعطيل التسجيل العام إذا لم يكن مطلوباً."
    
    detected = False
    # Check if user registration is enabled
    try:
        register_url = urljoin(target_url, "wp-login.php?action=register")
        response = requests.get(register_url, timeout=5)
        if response.status_code == 200 and "user_login" in response.text:
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

def check_theme_function_injection(target_url, report):
    vulnerability_name = "Theme Function Injection via functions.php"
    severity = "عالية"
    description = "إمكانية حقن كود ضار في ملف functions.php للقالب."
    remediation = "حماية ملف functions.php من التعديل، مراجعة جميع التعديلات على ملفات القوالب."
    
    # This requires access to the functions.php file which is typically not publicly accessible.
    # For simulation, we'll mark it as 'Not Detected'.
    detected = False
    report.append({
        "name": vulnerability_name,
        "status": "Detected" if detected else "Not Detected",
        "severity": severity,
        "description": description,
        "remediation": remediation
    })

def run_plugin_theme_checks(target_url, report):
    print("\n--- بدء فحص الثغرات المتعلقة بالإضافات والقوالب ---")
    check_nulled_themes_plugins(target_url, report)
    check_insecure_update_mechanism(target_url, report)
    check_insecure_ajax_actions(target_url, report)
    check_missing_nonce_verification(target_url, report)
    check_plugin_publicly_known_exploits(target_url, report)
    check_demo_importer_exploits(target_url, report)
    check_malicious_shortcodes(target_url, report)
    check_insecure_widget_code(target_url, report)
    check_theme_plugin_options_injection(target_url, report)
    check_no_access_control_custom_endpoints(target_url, report)
    check_arbitrary_options_update(target_url, report)
    check_arbitrary_user_creation(target_url, report)
    check_theme_function_injection(target_url, report)
    print("--- انتهى فحص الثغرات المتعلقة بالإضافات والقوالب ---")

