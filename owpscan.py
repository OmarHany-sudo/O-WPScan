import pyfiglet
import requests
import re
import os
import socket
import subprocess
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime
import markdown
from weasyprint import HTML

from modules.high_severity import run_high_severity_checks
from modules.medium_severity import run_medium_severity_checks
from modules.misconfigurations import run_misconfiguration_checks
from modules.plugin_theme_vulnerabilities import run_plugin_theme_checks

TOOL_VERSION = "1.0.0" # Define the tool version

def display_banner():
    ascii_banner = pyfiglet.figlet_format("O-WPScan")
    print(ascii_banner)
    print("Project by Eng.Omar Hany Shalaby\n")

def display_help():
    print("Usage: python3 owpscan.py <target_url> <export_format>")
    print("       python3 owpscan.py --help")
    print("\nArguments:")
    print("  <target_url>    The URL of the WordPress site to scan (e.g., https://example.com).")
    print("  <export_format> The desired report format (e.g., txt, md, html, pdf).")
    print("\nOptions:")
    print("  --help          Show this help message and exit.")

def generate_report(report_data, target_url, export_format="txt"):
    parsed_url = urlparse(target_url)
    hostname = parsed_url.netloc.replace(".", "_").replace(":", "_")
    
    # Calculate vulnerability summary
    high_count = sum(1 for entry in report_data if entry["severity"] == "High" and entry["status"] == "Detected")
    medium_count = sum(1 for entry in report_data if entry["severity"] == "Medium" and entry["status"] == "Detected")
    low_count = sum(1 for entry in report_data if entry["severity"] == "Low" and entry["status"] == "Detected")

    scan_date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_content = []
    report_content.append(f"# WordPress Vulnerability Scan Report\n")
    report_content.append(f"===================================================\n")
    report_content.append(f"Scanned Website: {target_url}\n")
    report_content.append(f"Scan Date and Time: {scan_date_time}\n")
    report_content.append(f"Tool Version: {TOOL_VERSION}\n")
    report_content.append(f"===================================================\n\n")

    report_content.append(f"## Vulnerability Summary\n")
    report_content.append(f"-----------------------\n")
    report_content.append(f"High Severity: {high_count}\n")
    report_content.append(f"Medium Severity: {medium_count}\n")
    report_content.append(f"Low Severity: {low_count}\n")
    report_content.append(f"\n")

    for entry in report_data:
        status_symbol = '❌' if entry['status'] == 'Detected' else '✅'
        report_content.append(f"### Vulnerability Name: {entry['name']}\n")
        report_content.append(f"- Scan Status: {status_symbol} {entry['status']}\n")
        report_content.append(f"- Severity: {entry['severity']}\n")
        report_content.append(f"- Description: {entry['description']}\n")
        report_content.append(f"- Remediation: {entry['remediation']}\n")
        report_content.append(f"---------------------------------------------------\n\n")
    
    report_content.append(f"\n\n")
    report_content.append(f"--- End of Report ---\n")
    report_content.append(f"Signature: O-WPScan Tool\n")
    report_content.append(f"Developer: Eng. Omar Hany Shalaby\n")

    report_text = "".join(report_content)

    report_path = ""
    if export_format == "txt":
        report_filename = f"{hostname}_scan_report.txt"
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)
    elif export_format == "md":
        report_filename = f"{hostname}_scan_report.md"
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)
    elif export_format == "html":
        report_filename = f"{hostname}_scan_report.html"
        report_path = os.path.join(os.getcwd(), report_filename)
        html_content = markdown.markdown(report_text)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    elif export_format == "pdf":
        report_filename = f"{hostname}_scan_report.pdf"
        report_path = os.path.join(os.getcwd(), report_filename)
        html_content = markdown.markdown(report_text)
        HTML(string=html_content).write_pdf(report_path)
    else:
        print("Unsupported export format. Saving as .txt by default.")
        report_filename = f"{hostname}_scan_report.txt"
        report_path = os.path.join(os.getcwd(), report_filename)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_text)

    return report_path

def main():
    display_banner()
    if len(sys.argv) == 2 and sys.argv[1] == "--help":
        display_help()
        sys.exit(0)
    elif len(sys.argv) < 3:
        print("Error: Missing arguments.")
        display_help()
        sys.exit(1)

    target_url = sys.argv[1]
    export_format = sys.argv[2].lower()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url
    
    print(f"\nStarting vulnerability scan for: {target_url}\n")
    
    report_data = []
    
    run_high_severity_checks(target_url, report_data)
    run_medium_severity_checks(target_url, report_data)
    run_misconfiguration_checks(target_url, report_data)
    run_plugin_theme_checks(target_url, report_data)
    
    generated_report_path = generate_report(report_data, target_url, export_format)
    
    print(f"\nScan finished. The report has been saved to: {os.path.abspath(generated_report_path)}")

if __name__ == "__main__":
    main()


