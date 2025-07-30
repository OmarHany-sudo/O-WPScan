# O-WPScan

**O-WPScan** is a professional open-source tool for scanning WordPress websites against a comprehensive list of security vulnerabilities. It is developed using Python and provides an easy-to-use Command Line Interface (CLI).

## Features

- **Comprehensive Vulnerability Scanning:** The tool scans the target WordPress site against a wide range of security vulnerabilities categorized by severity (High, Medium, Low).
- **Detailed Report:** Outputs results in a formatted text file (e.g., `example.com_scan_report.txt`) containing the vulnerability name, scan status, severity, a brief description, and security advice for remediation or prevention of each vulnerability.
- **Easy to Use:** Simple command-line interface for running scans.
- **Extensible:** The code structure is organized and flexible to allow for the addition of more scanning modules in the future.

## Scanned Vulnerabilities

### 🔥 High Severity Vulnerabilities:
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

### ⚠️ Medium Severity Vulnerabilities:
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

### 🧪 Misconfigurations:
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

### 🧩 Plugin and Theme Related Vulnerabilities:
- Nulled Themes/Plugins (with Backdoors)
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

## Requirements

The tool requires the following Python libraries:

- `pyfiglet`
- `requests`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/OmarHany-sudo/O-WPScan.git
   cd O-WPScan
   ```

2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the tool, use the following command:

```bash
python3 owpscan.py
```

The tool will prompt you to enter the target WordPress site URL. After the scan is complete, a report file (e.g., `example.com_scan_report.txt`) will be generated in the same directory containing the scan results.

## Contribution

Contributions are welcome to improve the tool and add more scanning modules. Please open an `issue` or submit a `pull request`.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Acknowledgements

Project by Eng.Omar Hany Shalaby


