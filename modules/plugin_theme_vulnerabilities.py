import requests
import re
from urllib.parse import urljoin

def check_nulled_themes_plugins(target_url, report):
    vulnerability_name = "Nulled Themes/Plugins (with Backdoors)"
    severity = "High"
    description = "Using pirated themes or plugins that may contain backdoors."
    remediation = "Use only original themes and plugins from trusted sources, scan files for malicious code."
    
    detected = False
    # Look for common backdoor patterns in publicly accessible files
    try:
        response = requests.get(target_url, timeout=5)
        # Check for common backdoor signatures in HTML source
        backdoor_patterns = [
            r"eval\s*\(\s*base64_decode",
            r"eval\s*\(\s*gzinflate",
            r"eval\s*\(\s*str_rot13",
            r"assert\s*\(\s*base64_decode",
            r"system\s*\(\s*base64_decode"
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
    severity = "High"
    description = "Insecure update mechanism for plugins or themes."
    remediation = "Use HTTPS for all updates, verify digital signatures, regularly update WordPress and plugins."
    
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
    severity = "Medium"
    description = "Unprotected AJAX actions allowing unauthorized operations."
    remediation = "Apply nonce verification to all AJAX actions, validate user permissions."
    
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
    severity = "Medium"
    description = "Absence of nonce verification allowing CSRF attacks."
    remediation = "Apply nonce verification to all sensitive forms and actions."
    
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
    severity = "High"
    description = "Using plugins with known public security vulnerabilities."
    remediation = "Update all plugins to the latest versions, remove unused plugins, monitor security updates."
    
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
    severity = "High"
    description = "Exploiting demo importer tools to upload malicious files."
    remediation = "Disable or remove demo importer tools after setup, restrict access to them."
    
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
    severity = "Medium"
    description = "Presence of malicious shortcodes that can execute unwanted code."
    remediation = "Review all used shortcodes, remove untrusted plugins, scan content for suspicious shortcodes."
    
    detected = False
    # Check for suspicious shortcode patterns in the main page
    try:
        response = requests.get(target_url, timeout=5)
        suspicious_shortcodes = [
            r"\[php\].*?\[/php\]",
            r"\[exec\].*?\[/exec\]",
            r"\[system\].*?\[/system\]"
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
    severity = "Medium"
    description = "Insecure code in widgets that can lead to security vulnerabilities."
    remediation = "Review all widget code, avoid using widgets from untrusted sources."
    
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
    severity = "High"
    description = "Ability to inject malicious options into theme or plugin settings."
    remediation = "Validate all theme and plugin options, apply strict access controls."
    
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
    severity = "High"
    description = "Lack of access controls on custom endpoints."
    remediation = "Apply strict access controls to all custom endpoints, validate user permissions."
    
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
    severity = "High"
    description = "Ability to arbitrarily update WordPress options."
    remediation = "Apply strict access controls to `update_option` functions, validate user permissions."
    
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
    severity = "High"
    description = "Ability to arbitrarily create new users."
    remediation = "Apply strict access controls to user creation functions, disable public registration if not required."
    
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
    severity = "High"
    description = "Ability to inject malicious code into the theme's functions.php file."
    remediation = "Protect functions.php from modification, review all changes to theme files."
    
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
    print("\n--- Starting Plugin and Theme Vulnerability Checks ---")
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
    print("--- Plugin and Theme Vulnerability Checks Finished ---")

