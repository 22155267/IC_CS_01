#!/usr/bin/env python3
"""
Flask Web Interface for Web Application Security Scanner
Compatible with modern UI (index.html) and scanner.py
"""

from flask import Flask, render_template, request, jsonify
from scanner import SecurityScanner
import threading
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Store all scan results temporarily in memory
scan_results = {}
lock = threading.Lock()

def generate_plain_summary(vulnerabilities):
    """
    Generate a friendly, human-readable summary for the UI
    """
    if not vulnerabilities:
        return "✅ This website appears safe. No vulnerabilities detected."

    high_vulns = [v for v in vulnerabilities if v['severity'].lower() == 'high']
    medium_vulns = [v for v in vulnerabilities if v['severity'].lower() == 'medium']
    low_vulns = [v for v in vulnerabilities if v['severity'].lower() == 'low']

    summary = ""
    if high_vulns:
        summary += "🚨 Critical issues found! Avoid entering sensitive data.\n"
    elif medium_vulns:
        summary += "⚠️ Some vulnerabilities found. Exercise caution.\n"
    elif low_vulns:
        summary += "ℹ️ Minor issues detected. Site generally safe but needs review.\n"

    summary += f"Detected {len(vulnerabilities)} vulnerabilities in total.\n"
    summary += "View the full report for details and recommendations."
    return summary


@app.route('/')
def index():
    """Render homepage"""
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    """Start vulnerability scan"""
    data = request.get_json()
    target_url = data.get('url', '').strip()

    if not target_url:
        return jsonify({'error': 'Please provide a valid URL.'}), 400

    # Ensure URL starts with http or https
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    scanner = SecurityScanner(target_url)

    def run_scan():
        """Threaded scan process"""
        try:
            scanner.scan()
            vulnerabilities = scanner.vulnerabilities
            report = {
                'target': target_url,
                'scanned_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'pages_scanned': len(scanner.visited_urls),
                'vulnerabilities': vulnerabilities,
                'summary': generate_plain_summary(vulnerabilities)
            }

            # Save safely to dictionary
            with lock:
                scan_results[target_url] = report

        except Exception as e:
            with lock:
                scan_results[target_url] = {
                    'target': target_url,
                    'summary': f'❌ Scan failed due to error: {str(e)}',
                    'vulnerabilities': []
                }

    # Run scan in background
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({
        'message': '🔍 Scan started successfully!',
        'target': target_url
    })


@app.route('/results/<path:url>')
def results(url):
    """Retrieve scan results"""
    with lock:
        if url in scan_results:
            return jsonify(scan_results[url])
        elif f'http://{url}' in scan_results:
            return jsonify(scan_results[f'http://{url}'])
        elif f'https://{url}' in scan_results:
            return jsonify(scan_results[f'https://{url}'])
        else:
            return jsonify({'message': '⏳ Scan still in progress or not found.'}), 404


@app.route('/recent')
def recent_scans():
    """List all recent scans (for demo or debugging)"""
    with lock:
        if not scan_results:
            return jsonify({'message': 'No scans performed yet.'})
        return jsonify(list(scan_results.keys()))


if __name__ == '__main__':
    # Start Flask server
    app.run(debug=True, host='0.0.0.0', port=5000)
