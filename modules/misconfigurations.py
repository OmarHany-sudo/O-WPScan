import requests
import re
from urllib.parse import urljoin

def check_exposed_xmlrpc(target_url, report):
    vulnerability_name = "Exposed XML-RPC"
    severity = "Medium"
    description = "Exposure of XML-RPC endpoint allowing brute force and DDoS attacks."
    remediation = "Disable XML-RPC if not used, or restrict access to it."
    
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
    severity = "High"
    description = "Weak permissions on wp-config.php file that may allow it to be read."
    remediation = "Apply 600 or 644 permissions to wp-config.php, move it outside the public folder."
    
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
    severity = "Medium"
    description = "Absence of HTTP security headers like CSP, X-Frame-Options, etc."
    remediation = "Add HTTP security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, etc."
    
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
    severity = "Medium"
    description = "Admin panel exposed without additional protection."
    remediation = "Restrict access to /wp-admin from trusted IP addresses, use .htaccess or a firewall."
    
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
    severity = "Medium"
    description = "Use of default usernames like 'admin' or 'administrator'."
    remediation = "Change default usernames, use strong and unpredictable usernames."
    
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
    severity = "High"
    description = "Use of weak passwords susceptible to brute-force attacks."
    remediation = "Use strong passwords, enforce password policies, use plugins to prevent brute force."
    
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
    severity = "Medium"
    description = "Absence of Two-Factor Authentication (2FA)."
    remediation = "Implement 2FA for all users, especially administrators."
    
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
    severity = "Medium"
    description = "Absence of CAPTCHA on the login page, facilitating brute-force attacks."
    remediation = "Add CAPTCHA to the login page, use plugins like reCAPTCHA."
    
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
    severity = "Medium"
    description = "Automatic directory indexing enabled, exposing their contents."
    remediation = "Disable directory listing in server settings, add empty index.html files."
    
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
    severity = "High"
    description = "Exposure of backup files (.zip, .sql, .bak) to the public."
    remediation = "Protect backup files, store them outside the public folder, use .htaccess to prevent access."
    
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
    severity = "Low"
    description = "Ability to exploit WP-Cron for DDoS attacks or resource exhaustion."
    remediation = "Disable public WP-Cron and use a real cron job, or restrict access to wp-cron.php."
    
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
        "severity": "Low",
        "description": description,
        "remediation": remediation
    })

def check_file_editor_enabled(target_url, report):
    vulnerability_name = "File Editor Enabled"
    severity = "High"
    description = "File editor enabled in the dashboard, allowing modification of PHP files."
    remediation = "Disable the file editor by adding `define(\'DISALLOW_FILE_EDIT\', true);` in wp-config.php."
    
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
    print("\n--- Starting Misconfiguration Checks ---")
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
    print("--- Misconfiguration Checks Finished ---")



