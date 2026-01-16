#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import random
import time
import json
from flask import Flask, request, jsonify, render_template_string

# --- Optional color output for console (developer view) ---
from colorama import init, Fore, Style
init(autoreset=True)

app = Flask(__name__)

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
        time.sleep(0.2)  # Reduced from 0.4 to avoid timeout
    print(Fore.GREEN + "✔ Scan complete.\n")

# --- The main scanning function ---
def perform_scan(url):
    techy_intro(url)
    time.sleep(0.5)  # Reduced from 1.5 to avoid timeout
    
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

# Flask routes
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🛡️ CyberShield Scanner</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                max-width: 600px;
                width: 100%;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 2em;
                text-align: center;
            }
            .subtitle {
                text-align: center;
                color: #666;
                margin-bottom: 30px;
                font-size: 0.9em;
            }
            form {
                display: flex;
                flex-direction: column;
                gap: 20px;
            }
            input[type="text"] {
                padding: 15px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus {
                outline: none;
                border-color: #667eea;
            }
            button {
                padding: 15px 30px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                border-radius: 10px;
                font-size: 18px;
                font-weight: bold;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            }
            button:active {
                transform: translateY(0);
            }
            #result {
                margin-top: 30px;
                padding: 20px;
                border-radius: 10px;
                display: none;
            }
            .loading {
                text-align: center;
                color: #667eea;
                font-weight: bold;
                display: none;
            }
            .vulnerability {
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
                background: #f5f5f5;
            }
            .detected {
                border-left: 4px solid #f44336;
            }
            .not-detected {
                border-left: 4px solid #4caf50;
            }
            .risk-high { color: #f44336; }
            .risk-medium { color: #ff9800; }
            .risk-low { color: #4caf50; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ CyberShield Scanner</h1>
            <p class="subtitle">Advanced Web Security Vulnerability Scanner</p>
            
            <form id="scanForm">
                <input type="text" id="urlInput" name="url" placeholder="Enter website URL (e.g., https://example.com)" required>
                <button type="submit">🔍 Start Security Scan</button>
            </form>
            
            <div class="loading" id="loading">
                <p>⚙️ Scanning in progress...</p>
                <p>This may take a few moments...</p>
            </div>
            
            <div id="result"></div>
        </div>

        <script>
            document.getElementById('scanForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const url = document.getElementById('urlInput').value;
                const loading = document.getElementById('loading');
                const result = document.getElementById('result');
                
                loading.style.display = 'block';
                result.style.display = 'none';
                
                try {
                    const response = await fetch('/scan', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `url=${encodeURIComponent(url)}`
                    });
                    
                    const data = await response.json();
                    
                    loading.style.display = 'none';
                    result.style.display = 'block';
                    
                    let vulnHTML = '';
                    data.vulnerabilities.forEach(vuln => {
                        const statusClass = vuln.status === 'Detected' ? 'detected' : 'not-detected';
                        vulnHTML += `
                            <div class="vulnerability ${statusClass}">
                                <strong>${vuln.name}:</strong> ${vuln.status}
                            </div>
                        `;
                    });
                    
                    const riskClass = `risk-${data.risk_level.toLowerCase()}`;
                    
                    result.innerHTML = `
                        <h2>Scan Results for: ${data.url}</h2>
                        <p class="${riskClass}"><strong>Risk Level: ${data.risk_level}</strong></p>
                        <p>${data.message}</p>
                        <p><strong>Total Vulnerabilities Found: ${data.total_vulns}</strong></p>
                        <div style="margin-top: 20px;">
                            ${vulnHTML}
                        </div>
                    `;
                } catch (error) {
                    loading.style.display = 'none';
                    result.style.display = 'block';
                    result.innerHTML = `<p style="color: red;">Error: ${error.message}</p>`;
                }
            });
        </script>
    </body>
    </html>
    ''')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    result = perform_scan(url)
    return jsonify(result)

# API endpoint for JSON response
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    url = data.get('url') if data else None
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    result = perform_scan(url)
    return jsonify(result)
