import pyfiglet
import requests
import re
import os
import socket
import subprocess
from urllib.parse import urljoin

from modules.high_severity import run_high_severity_checks
from modules.medium_severity import run_medium_severity_checks
from modules.misconfigurations import run_misconfiguration_checks
from modules.plugin_theme_vulnerabilities import run_plugin_theme_checks

def display_banner():
    ascii_banner = pyfiglet.figlet_format("O-WPScan")
    print(ascii_banner)
    print("Project by Eng.Omar Hany Shalaby\n")

def generate_report(report_data):
    with open("wordpress_vuln_report.txt", "w", encoding="utf-8") as f:
        f.write("تقرير فحص ثغرات WordPress\n")
        f.write("=====================================\n\n")
        for entry in report_data:
            f.write(f"اسم الثغرة: {entry['name']}\n")
            f.write(f"حالة الفحص: {entry['status']}\n")
            f.write(f"درجة الخطورة: {entry['severity']}\n")
            f.write(f"شرح مختصر: {entry['description']}\n")
            f.write(f"نصيحة أمنية: {entry['remediation']}\n")
            f.write("-------------------------------------\n\n")

def main():
    display_banner()
    target_url = input("أدخل رابط موقع WordPress المستهدف (مثال: https://example.com): ")
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\nبدء فحص الثغرات لموقع: {target_url}\n")
    
    report_data = []
    
    run_high_severity_checks(target_url, report_data)
    run_medium_severity_checks(target_url, report_data)
    run_misconfiguration_checks(target_url, report_data)
    run_plugin_theme_checks(target_url, report_data)
    
    generate_report(report_data)
    
    print("\nانتهى الفحص. تم حفظ التقرير في wordpress_vuln_report.txt")

if __name__ == "__main__":
    main()


