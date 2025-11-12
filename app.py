from flask import Flask, render_template, request
import random
import time

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    time.sleep(3)  # simulate scanning delay

    vulnerabilities = [
        {"name": "SQL Injection", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Cross-Site Scripting (XSS)", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Missing Security Headers", "status": random.choice(["Detected", "Not Detected"])},
        {"name": "Weak SSL/TLS Config", "status": random.choice(["Detected", "Not Detected"])},
    ]

    detected = [v for v in vulnerabilities if v["status"] == "Detected"]
    total_vulns = len(detected)
    risk_level = "High" if total_vulns >= 3 else "Medium" if total_vulns == 2 else "Low"

    if risk_level == "High":
        message = "⚠️ Critical vulnerabilities detected! Immediate action required."
    elif risk_level == "Medium":
        message = "🟠 Moderate vulnerabilities found. Please patch soon."
    else:
        message = "🟢 No major threats detected. Your site seems secure."

    return render_template('results.html', url=url,
                           vulnerabilities=vulnerabilities,
                           total_vulns=total_vulns,
                           risk_level=risk_level,
                           message=message)

if __name__ == '__main__':
    app.run(debug=True)
