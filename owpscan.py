import pyfiglet
import requests
import re
import os
import socket
import subprocess
from urllib.parse import urljoin, urlparse

from modules.high_severity import run_high_severity_checks
from modules.medium_severity import run_medium_severity_checks
from modules.misconfigurations import run_misconfiguration_checks
from modules.plugin_theme_vulnerabilities import run_plugin_theme_checks

def display_banner():
    ascii_banner = pyfiglet.figlet_format("O-WPScan")
    print(ascii_banner)
    print("Project by Eng.Omar Hany Shalaby\n")

def generate_report(report_data, target_url):
    parsed_url = urlparse(target_url)
    hostname = parsed_url.netloc.replace(".", "_").replace(":", "_")
    report_filename = f"{hostname}_scan_report.txt"
    report_path = os.path.join(os.getcwd(), report_filename)

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"WordPress Vulnerability Scan Report for: {target_url}\n")
        f.write("===================================================\n\n")
        for entry in report_data:
            f.write(f"Vulnerability Name: {entry['name']}\n")
            f.write(f"Scan Status: {entry['status']}\n")
            f.write(f"Severity: {entry['severity']}\n")
            f.write(f"Description: {entry['description']}\n")
            f.write(f"Remediation: {entry['remediation']}\n")
            f.write("---------------------------------------------------\n\n")
    return report_path

def main():
    display_banner()
    target_url = input("Enter the target WordPress site URL (e.g., https://example.com): ")
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    
    print(f"\nStarting vulnerability scan for: {target_url}\n")
    
    report_data = []
    
    run_high_severity_checks(target_url, report_data)
    run_medium_severity_checks(target_url, report_data)
    run_misconfiguration_checks(target_url, report_data)
    run_plugin_theme_checks(target_url, report_data)
    
    generated_report_path = generate_report(report_data, target_url)
    
    print(f"\nScan finished. The report has been saved to: {os.path.abspath(generated_report_path)}")

if __name__ == "__main__":
    main()

