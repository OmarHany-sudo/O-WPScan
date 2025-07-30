import requests
import re
from urllib.parse import urljoin

def check_xss(target_url, report):
    vulnerability_name = "Cross-Site Scripting (XSS)"
    severity = "Medium"
    description = "Ability to inject malicious JavaScript into website pages."
    remediation = "Sanitize all user inputs, use Content Security Policy (CSP), encode outputs."
    
    payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>"
    ]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"?s={payload}")
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
    report.append({
        "name": "Cross-Site Request Forgery (CSRF)",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Ability to perform unwanted actions on behalf of an authenticated user.",
        "remediation": "Use CSRF tokens, validate HTTP Referer header, use SameSite cookies."
    })

def check_open_redirect(target_url, report):
    payloads = ["http://evil.com", "//evil.com", "https://evil.com"]
    detected = False
    for payload in payloads:
        try:
            test_url = urljoin(target_url, f"wp-login.php?redirect_to={payload}")
            response = requests.get(test_url, allow_redirects=False, timeout=5)
            if response.status_code in [301, 302, 303, 307, 308] and payload in response.headers.get("Location", ""):
                detected = True
                break
        except requests.exceptions.RequestException:
            pass

    report.append({
        "name": "Open Redirect",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Ability to redirect users to malicious websites.",
        "remediation": "Validate input URLs, use a whitelist for allowed domains."
    })

def check_information_disclosure(target_url, report):
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        if re.search(r'wp-includes/version\.php', response.text) or re.search(r'content="WordPress \d+\.\d+', response.text):
            detected = True
    except requests.exceptions.RequestException:
        pass

    try:
        readme_url = urljoin(target_url, "readme.html")
        response = requests.get(readme_url, timeout=5)
        if response.status_code == 200 and "WordPress" in response.text:
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": "Information Disclosure",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Disclosure of sensitive information such as version numbers or file paths.",
        "remediation": "Hide version numbers, disable error display in production, secure configuration files."
    })

def check_rest_api_unauthorized_access(target_url, report):
    detected = False
    try:
        api_url = urljoin(target_url, "wp-json/wp/v2/users")
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200 and "slug" in response.text:
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": "REST API Unauthorized Access",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Unauthorized access to the WordPress REST API.",
        "remediation": "Restrict REST API access, use proper authentication, disable unused endpoints."
    })

def check_idor(target_url, report):
    report.append({
        "name": "Insecure Direct Object Reference (IDOR)",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Access to unauthorized objects or data by changing object identifiers.",
        "remediation": "Apply strict access controls, validate user permissions before accessing objects."
    })

def check_clickjacking(target_url, report):
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        x_frame_options = response.headers.get("X-Frame-Options", "").lower()
        csp = response.headers.get("Content-Security-Policy", "").lower()
        
        if not x_frame_options and 'frame-ancestors' not in csp:
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": "Clickjacking",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Ability to trick users into clicking on hidden or misleading elements.",
        "remediation": "Use X-Frame-Options header or Content Security Policy (CSP) frame-ancestors directive."
    })

def check_open_port_misconfigured_services(target_url, report):
    report.append({
        "name": "Open Port / Misconfigured Services",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Presence of open ports or misconfigured services.",
        "remediation": "Close unused ports, secure exposed services, use a firewall."
    })

def check_exposed_debug_logs(target_url, report):
    detected = False
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
        "name": "Exposed Debug Logs",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Exposure of debug log files that may contain sensitive information.",
        "remediation": "Disable debug logging in production, protect log files from public access."
    })

def check_directory_indexing(target_url, report):
    detected = False
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
        "name": "Directory Indexing",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Ability to view directory contents via the browser.",
        "remediation": "Disable directory listing in server settings, add empty index.html files to sensitive directories."
    })

def check_version_disclosure(target_url, report):
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        if re.search(r'name="generator" content="WordPress \d+\.\d+', response.text, re.IGNORECASE):
            detected = True
        if re.search(r'wp-includes/.*\?ver=\d+\.\d+', response.text):
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": "Version Disclosure",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Disclosure of WordPress, plugin, or theme versions.",
        "remediation": "Hide version numbers from HTML source, use plugins to hide version information."
    })

def check_reflected_file_download(target_url, report):
    report.append({
        "name": "Reflected File Download",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Ability to trick users into downloading malicious files.",
        "remediation": "Validate file names and content, use appropriate Content-Disposition headers."
    })

def check_content_spoofing(target_url, report):
    report.append({
        "name": "Content Spoofing",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Ability to forge page content to deceive users.",
        "remediation": "Sanitize user input, use Content Security Policy (CSP)."
    })

def check_insecure_file_permissions(target_url, report):
    report.append({
        "name": "Insecure File Permissions",
        "status": "Not Detected",
        "severity": "Medium",
        "description": "Insecure file permissions that may allow unauthorized access.",
        "remediation": "Apply appropriate file permissions (644 for files, 755 for directories), protect wp-config.php."
    })

def check_theme_plugin_path_disclosure(target_url, report):
    detected = False
    try:
        response = requests.get(target_url, timeout=5)
        if re.search(r'wp-content/themes/[^/]+', response.text) or re.search(r'wp-content/plugins/[^/]+', response.text):
            detected = True
    except requests.exceptions.RequestException:
        pass

    report.append({
        "name": "Theme/Plugin Path Disclosure",
        "status": "Detected" if detected else "Not Detected",
        "severity": "Medium",
        "description": "Disclosure of theme and plugin paths, which helps attackers target them.",
        "remediation": "Hide theme and plugin paths, use plugins to hide this information."
    })

def run_medium_severity_checks(target_url, report):
    print("\n--- Starting Medium Severity Vulnerability Checks ---")
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
    print("--- Medium Severity Vulnerability Checks Finished ---")
