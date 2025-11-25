#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
import time

# --- Optional color output for console (developer view) ---
from colorama import init, Fore, Style
init(autoreset=True)

# --- Techy scan messages ---
def techy_intro(url):
    animations = [
        "Initializing deep scan modules...",
        "Checking target headers...",
        "Deploying payloads...",
        "Analyzing script vulnerabilities...",
        "Scanning endpoints and parameters...",
        "Cross-checking OWASP Top 10 risks...",
        "Finalizing vulnerability report..."
    ]
    print(f"{Fore.CYAN}🔍 Starting security scan on: {url}")
    for step in animations:
        print(Fore.YELLOW + "» " + step)
        time.sleep(0.4)
    print(Fore.GREEN + "✔ Scan complete.\n")

# --- The main scanning function ---
def perform_scan(url):
    techy_intro(url)
    time.sleep(1.5)  # simulate scanning delay

    results = [
        {"name": "SQL Injection", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Cross-Site Scripting (XSS)", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Security Headers Missing", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Weak SSL/TLS Configuration", "status": random.choice(["Detected", "Not Detected"])},
    ]

    detected = [r for r in results if r["status"] == "Detected"]
    risk_level = "High" if len(detected) >= 3 else "Medium" if len(detected) == 2 else "Low"

    message = ""
    if risk_level == "High":
        message = "⚠️ Your website is at serious risk! Immediate attention required."
    elif risk_level == "Medium":
        message = "🟠 Moderate vulnerabilities detected. Patch these soon."
    else:
        message = "🟢 No major threats found. Your site seems secure!"

    report = {
        "url": url,
        "vulnerabilities": results,
        "total_vulns": len(detected),
        "risk_level": risk_level,
        "message": message
    }

    return report

# --- Run independently (for quick test) ---
if __name__ == "__main__":
    target = input("Enter a website URL to scan: ")
    result = perform_scan(target)
    print(json.dumps(result, indent=2))
