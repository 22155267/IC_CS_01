# scanner.py
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import time
import json
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)


class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.visited_urls = set()
        self.vulnerabilities = []
        # SQL Injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'>"
        ]

    # -------------------------
    # Helper: plain-language explanations
    # -------------------------
    def _plain_explanation_for(self, vuln_type, description=None):
        t = (vuln_type or "").lower()
        if "sql" in t:
            return "An attacker might trick the site into revealing or changing private data (e.g., user accounts or stored information)."
        if "xss" in t or "cross-site" in t:
            return "Parts of the site may run malicious scripts which could steal information from your browser or act on your behalf."
        if "missing security header" in t or "header" in t:
            return "The site is not sending some browser security settings — this can make some attacks easier for attackers."
        if "csp" in t or "content-security" in t:
            return "The site has no (or only report-only) policy controlling what code runs; harmful scripts may run unchecked."
        if "hsts" in t:
            return "The site isn't forcing browsers to use a secure (HTTPS) connection; connections could be downgraded in some attacks."
        # default
        if description:
            # give a short version of the technical description
            return description if len(description) < 140 else description[:137] + "..."
        return "This indicates a potential security problem — be cautious with sensitive data on this site."

    # -------------------------
    # Console banner & prints
    # -------------------------
    def print_banner(self):
        banner = f"""
{Fore.CYAN}{'='*70}
    🔒 WEB APPLICATION SECURITY SCANNER 🔒
{'='*70}{Style.RESET_ALL}
Target: {Fore.YELLOW}{self.target_url}{Style.RESET_ALL}
Scan Started: {time.strftime('%Y-%m-%d %H:%M:%S')}
{'='*70}
"""
        print(banner)

    # -------------------------
    # Header checks
    # -------------------------
    def check_security_headers(self):
        """Check for security headers"""
        print(f"\n{Fore.CYAN}[*] Checking Security Headers...{Style.RESET_ALL}")

        try:
            response = requests.get(self.target_url, timeout=12)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Content-Type-Options': 'X-Content-Type-Options',
                'X-Frame-Options': 'X-Frame-Options',
                'X-XSS-Protection': 'X-XSS-Protection',
                'Referrer-Policy': 'Referrer-Policy'
            }

            for header, name in security_headers.items():
                if header in headers:
                    print(f"{Fore.GREEN}[✓] {name}: Found{Style.RESET_ALL}")
                    print(f"    Value: {headers[header]}")
                else:
                    # special-case CSP report-only
                    if header == 'Content-Security-Policy' and 'Content-Security-Policy-Report-Only' in headers:
                        print(f"{Fore.YELLOW}[!] CSP: Report-Only present (not enforced){Style.RESET_ALL}")
                        val = headers.get('Content-Security-Policy-Report-Only')
                        if val:
                            print(f"    Value: {val}")
                        # add vulnerability but mark as Low/Info
                        v = {
                            'type': 'CSP Report-Only',
                            'severity': 'Low',
                            'description': 'Content-Security-Policy is present only in report-only mode (not enforced).',
                        }
                        v['plain_summary'] = self._plain_explanation_for(v['type'], v['description'])
                        self.vulnerabilities.append(v)
                    else:
                        print(f"{Fore.RED}[✗] {name}: Missing (Vulnerable){Style.RESET_ALL}")
                        v = {
                            'type': 'Missing Security Header',
                            'severity': 'Medium',
                            'header': name,
                            'description': f'{name} header is missing'
                        }
                        v['plain_summary'] = self._plain_explanation_for(v['type'], v['description'])
                        self.vulnerabilities.append(v)

        except Exception as e:
            print(f"{Fore.RED}[!] Error checking headers: {e}{Style.RESET_ALL}")

    # -------------------------
    # Crawler
    # -------------------------
    def crawl_website(self, url, max_pages=20):
        """Crawl website to find all links"""
        print(f"\n{Fore.CYAN}[*] Crawling website for links...{Style.RESET_ALL}")

        if len(self.visited_urls) >= max_pages:
            return

        if url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            print(f"{Fore.YELLOW}[→] Crawling: {url}{Style.RESET_ALL}")

            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])

                # Only crawl same domain
                if urlparse(next_url).netloc == urlparse(self.target_url).netloc:
                    if next_url not in self.visited_urls and len(self.visited_urls) < max_pages:
                        self.crawl_website(next_url, max_pages)

        except Exception as e:
            print(f"{Fore.RED}[!] Error crawling {url}: {e}{Style.RESET_ALL}")

    # -------------------------
    # SQL Injection tests
    # -------------------------
    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        try:
            response = requests.get(url, timeout=7)
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                target = urljoin(url, action) if action else url

                inputs = form.find_all('input')

                for payload in self.sql_payloads:
                    data = {}
                    for input_tag in inputs:
                        input_name = input_tag.get('name')
                        input_type = input_tag.get('type', 'text')

                        if input_name:
                            if input_type in ('text', 'password'):
                                data[input_name] = payload
                            else:
                                data[input_name] = 'test'

                    try:
                        if method == 'post':
                            test_response = requests.post(target, data=data, timeout=8)
                        else:
                            test_response = requests.get(target, params=data, timeout=8)

                        # Check for SQL error messages
                        error_indicators = [
                            'sql syntax',
                            'mysql',
                            'mysqli',
                            'postgresql',
                            'oracle',
                            'sqlite',
                            'syntax error',
                            'unclosed quotation'
                        ]

                        response_text = test_response.text.lower()

                        for indicator in error_indicators:
                            if indicator in response_text:
                                print(f"{Fore.RED}[!] Potential SQL Injection found!{Style.RESET_ALL}")
                                print(f"    URL: {target}")
                                print(f"    Payload: {payload}")

                                v = {
                                    'type': 'SQL Injection',
                                    'severity': 'High',
                                    'url': target,
                                    'payload': payload,
                                    'description': 'Possible SQL Injection vulnerability detected'
                                }
                                v['plain_summary'] = self._plain_explanation_for(v['type'], v['description'])
                                self.vulnerabilities.append(v)
                                return

                    except Exception:
                        # ignore per-payload failures
                        continue

        except Exception as e:
            # fail safe
            print(f"{Fore.YELLOW}[!] SQLi test skipped for {url}: {e}{Style.RESET_ALL}")
            return

    # -------------------------
    # XSS tests
    # -------------------------
    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        try:
            response = requests.get(url, timeout=7)
            soup = BeautifulSoup(response.content, 'html.parser')

            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action')
                method = form.get('method', 'get').lower()
                target = urljoin(url, action) if action else url

                inputs = form.find_all('input')

                for payload in self.xss_payloads:
                    data = {}
                    for input_tag in inputs:
                        input_name = input_tag.get('name')
                        input_type = input_tag.get('type', 'text')

                        if input_name:
                            if input_type == 'text':
                                data[input_name] = payload
                            else:
                                data[input_name] = 'test'

                    try:
                        if method == 'post':
                            test_response = requests.post(target, data=data, timeout=8)
                        else:
                            test_response = requests.get(target, params=data, timeout=8)

                        # Check if payload is reflected
                        if payload in test_response.text:
                            print(f"{Fore.RED}[!] Potential XSS vulnerability found!{Style.RESET_ALL}")
                            print(f"    URL: {target}")
                            print(f"    Payload: {payload}")

                            v = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'High',
                                'url': target,
                                'payload': payload,
                                'description': 'Possible XSS vulnerability detected'
                            }
                            v['plain_summary'] = self._plain_explanation_for(v['type'], v['description'])
                            self.vulnerabilities.append(v)
                            return

                    except Exception:
                        continue

        except Exception as e:
            # fail safe
            print(f"{Fore.YELLOW}[!] XSS test skipped for {url}: {e}{Style.RESET_ALL}")
            return

    # -------------------------
    # Run scan
    # -------------------------
    def scan(self):
        """Run complete security scan"""
        self.print_banner()

        # Step 1: Check security headers
        self.check_security_headers()

        # Step 2: Crawl website
        self.crawl_website(self.target_url, max_pages=10)

        print(f"\n{Fore.CYAN}[*] Found {len(self.visited_urls)} pages{Style.RESET_ALL}")

        # Step 3: Test for SQL Injection
        print(f"\n{Fore.CYAN}[*] Testing for SQL Injection vulnerabilities...{Style.RESET_ALL}")
        for url in list(self.visited_urls)[:5]:  # Test first 5 pages
            self.test_sql_injection(url)

        # Step 4: Test for XSS
        print(f"\n{Fore.CYAN}[*] Testing for XSS vulnerabilities...{Style.RESET_ALL}")
        for url in list(self.visited_urls)[:5]:  # Test first 5 pages
            self.test_xss(url)

        # Generate report
        self.generate_report()

    # -------------------------
    # Report generation & helpers
    # -------------------------
    def generate_report(self):
        """Generate final vulnerability report and save as JSON"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"    📊 VULNERABILITY REPORT")
        print(f"{'='*70}{Style.RESET_ALL}\n")

        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No vulnerabilities detected!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}\n")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_color = Fore.RED if vuln.get('severity') == 'High' else Fore.YELLOW
                print(f"{severity_color}[{i}] {vuln.get('type')} - Severity: {vuln.get('severity')}{Style.RESET_ALL}")
                print(f"    Description: {vuln.get('description')}")
                if 'url' in vuln:
                    print(f"    URL: {vuln.get('url')}")
                if 'payload' in vuln:
                    print(f"    Payload: {vuln.get('payload')}")
                if 'plain_summary' in vuln:
                    print(f"    Plain: {vuln.get('plain_summary')}")
                print()

        print(f"{Fore.CYAN}{'='*70}")
        print(f"Scan completed: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}{Style.RESET_ALL}")

        # Save JSON report for front-end/demo
        try:
            report = self.get_report()
            with open('scan_report.json', 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            print(f"{Fore.CYAN}[i] Saved JSON report to scan_report.json{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not save JSON report: {e}{Style.RESET_ALL}")

    def get_report(self):
        """Return a JSON-serializable report object"""
        # create a safe copy of vulnerabilities (no non-serializable types)
        vulns = []
        for v in self.vulnerabilities:
            vulns.append({
                'type': v.get('type'),
                'severity': v.get('severity'),
                'description': v.get('description'),
                'url': v.get('url'),
                'payload': v.get('payload'),
                'plain_summary': v.get('plain_summary'),
                'header': v.get('header')
            })

        # generate a server-side plain summary
        server_summary = self._generate_server_summary(vulns)

        return {
            'target': self.target_url,
            'pages_scanned': len(self.visited_urls),
            'vulnerabilities': vulns,
            'summary': server_summary,
            'scanned_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }

    def _generate_server_summary(self, vulns):
        """Create a short server-side summary for non-technical users"""
        if not vulns:
            return "✅ This website appears safe — no major issues were detected by the scanner."
        high = [v for v in vulns if v.get('severity') == 'High']
        medium = [v for v in vulns if v.get('severity') == 'Medium' or v.get('severity') == 'Low']
        if high:
            return f"🚨 CRITICAL: {len(high)} high-severity issue(s) found. Avoid entering sensitive information on this site."
        if medium:
            return f"⚠️ Notice: {len(medium)} potential issue(s) found. Be careful with sensitive data."
        return "⚠️ Some issues were detected. Review the detailed report."

# -------------------------
# CLI runner - keep behavior for local use
# -------------------------
def main():
    print(f"{Fore.CYAN}WEB APPLICATION SECURITY SCANNER{Style.RESET_ALL}")

    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = input("\nEnter target URL (e.g., http://testphp.vulnweb.com): ").strip()

    if not target_url:
        print(f"{Fore.RED}Error: No URL provided!{Style.RESET_ALL}")
        sys.exit(1)

    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    scanner = SecurityScanner(target_url)
    scanner.scan()
    # If you want to access the report in code:
    # report = scanner.get_report()
    # print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
