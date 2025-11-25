# 🛡️ CyberShield – Web Security Scanner  
A lightweight automated vulnerability scanner built with Python.  
CyberGuard crawls a target website, collects links, and performs security checks such as:

- SQL Injection testing  
- XSS (Cross-Site Scripting) testing  
- Security headers validation  
- Weak form detection  
- Broken authentication patterns  
- Crawling all internal pages  
- Generating a JSON scan report  

CyberShield
 is designed for **educational and cybersecurity internship tasks**, based on OWASP Top 10.

---

## 🚀 Features

### 🔍 Automated Crawling  
- Finds internal links using BeautifulSoup  
- Ignores external domains  
- Builds a full map of the site  

### 🧪 Vulnerability Tests  
- SQL Injection payload checks  
- XSS JavaScript injection checks  
- Weak headers (CSP, HSTS, X-Frame-Options)  
- Insecure forms detection  

### 📝 Reporting  
- Saves scan results to `scan_report.json`  
- Shows vulnerabilities in the terminal  

### 🖥️ Tech Stack  
- **Python 3**  
- `requests`  
- `BeautifulSoup4`  
- `colorama`  

---

## 📂 Project Structure

