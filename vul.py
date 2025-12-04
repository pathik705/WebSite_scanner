from flask import Flask, render_template, request, jsonify, send_file
import requests
import json
import threading
import time
import uuid
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import socket
from concurrent.futures import ThreadPoolExecutor
import warnings
import os
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# Global storage for scan results 
scan_results = {}
scan_status = {}

class VulnerabilityScanner:
    def __init__(self, target_url, scan_id, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.scan_id = scan_id
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        
        # SQL Injection payloads
        self.sql_payloads = [
            "'", '"', "`", "''", "``",
            "' OR '1'='1", '" OR "1"="1', "1 OR 1=1", "' OR 1=1-- -",
            "admin'--", "admin'/*",
            "' UNION SELECT NULL--", '" UNION SELECT NULL--', "' UNION ALL SELECT NULL,NULL--",
            "' OR SLEEP(0)--", "' OR pg_sleep(0)--", "' OR 1=CONVERT(INT, 'abc')--",
            "1' OR '1'='1'--", "1' OR '1'='1'#",
            "AND 1=1", "AND 1=2", "' AND '1'='1", "' AND '1'='2",
            "SLEEP(5)", "pg_sleep(5)", "WAITFOR DELAY '00:00:05'",
            "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,2,3--",
            "'; --", "'; SELECT 'x'--", '\"; SELECT \'x\'--',
            "1'; DROP TABLE users--", "'; EXEC xp_cmdshell('dir')--"
        ]

        # XSS payloads
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            '\"<script>alert(1)</script>',
            "'> <img src=x onerror=alert(1)>",
            '\"<svg/onload=alert(1)>',
            "'-alert(1)-'",
            "<div onmouseover=alert(1)>hover me!</div>",
            "<input onfocus=alert(1) autofocus>",
            "<iframe srcdoc='<script>alert(1)</script>'>",
            "<a href=javascript:alert(1)>Click</a>",
            "';alert(1);//",
            '\");alert(1);//',
            "</script><script>alert(1)</script>",
            "<script>confirm(1)</script>",
            "<style>@keyframes x{}</style><div style=animation-name:x onanimationstart=alert(1)></div>",
            "<svg><script>alert(1)</script></svg>",
            "<math><mi xlink:href=\"javascript:alert(1)\">X</mi></math>",
            "jaVasCript:/*--></title></style></textarea></script><img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>test</marquee>",
            '" onmouseover=alert(1) x="',
            "';alert(String.fromCharCode(88,83,83))//",
            "<!--><script>alert(1)</script>",
        ]

    def update_status(self, message, progress=None):
        """Update scan status"""
        status = {
            'status': message,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities_found': len(self.vulnerabilities)
        }
        if progress is not None:
            status['progress'] = progress
        
        scan_status[self.scan_id] = status

    def log_vulnerability(self, vuln_type, details, severity="Medium", url="", payload="", found_on=""):
        """Log discovered vulnerability"""
        vuln = {
            'type': vuln_type,
            'details': details,
            'severity': severity,
            'url': url,
            'payload': payload,
            'found_on': found_on or 'response',
            'timestamp': datetime.now().isoformat()
        }
        self.vulnerabilities.append(vuln)
        self.update_status(f"Found {vuln_type} vulnerability")

    def get_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            return soup.find_all('form')
        except Exception:
            return []

    def get_form_details(self, form):
        """Extract form details"""
        details = {}
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = []
        
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            details["inputs"].append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })
            
        for select in form.find_all("select"):
            select_name = select.attrs.get("name")
            details["inputs"].append({
                "type": "select",
                "name": select_name,
                "value": ""
            })
            
        for textarea in form.find_all("textarea"):
            textarea_name = textarea.attrs.get("name")
            details["inputs"].append({
                "type": "textarea",
                "name": textarea_name,
                "value": ""
            })
            
        return details

    def test_sql_injection(self, url):
        """Test for SQL injection vulnerabilities"""
        self.update_status(f"Testing SQL Injection on: {url}")
        
        forms = self.get_forms(url)
        
        for form in forms:
            form_details = self.get_form_details(form)
            
            for payload in self.sql_payloads[:5]:  # Limit payloads for web interface
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["type"] == "submit":
                        data[input_tag["name"]] = input_tag["value"]
                    elif input_tag["name"]:
                        data[input_tag["name"]] = payload
                
                target_url = urljoin(url, form_details["action"])
                
                try:
                    if form_details["method"] == "post":
                        response = self.session.post(target_url, data=data, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(target_url, params=data, timeout=self.timeout, verify=False)
                    
                    sql_errors = [
                        "SQL syntax", "mysql_fetch", "ORA-", "Microsoft OLE DB",
                        "error in your SQL syntax", "PostgreSQL query failed",
                        "sqlite3.OperationalError", "Warning: mysql_",
                        "valid MySQL result", "MySqlClient.", "PostgreSQL"
                    ]
                    
                    found_on = ''

                    # If payload is reflected in response, mark as frontend (reflected)
                    if payload and payload in response.text:
                        found_on = 'frontend'

                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            # if we previously detected reflection, keep frontend otherwise server error
                            if not found_on:
                                found_on = 'server-error'

                            self.log_vulnerability(
                                "SQL Injection",
                                f"Form vulnerable to SQL injection in action: {form_details['action']}",
                                "High",
                                url,
                                payload,
                                found_on
                            )
                            break
                            
                except Exception:
                    continue
        
        # Test URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params:
                for payload in self.sql_payloads[:3]:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    try:
                        response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                        
                        sql_errors = ["SQL syntax", "mysql_fetch", "ORA-", "error in your SQL syntax"]
                        found_on = ''

                        # If payload appears in response, it's likely a reflected/frontend issue
                        if payload and payload in response.text:
                            found_on = 'frontend'

                        for error in sql_errors:
                            if error.lower() in response.text.lower():
                                if not found_on:
                                    found_on = 'server-error'
                                self.log_vulnerability(
                                    "SQL Injection",
                                    f"URL parameter '{param}' vulnerable to SQL injection",
                                    "High",
                                    url,
                                    payload,
                                    found_on
                                )
                                break
                                
                    except Exception:
                        continue

    def test_xss(self, url):
        """Test for XSS vulnerabilities"""
        self.update_status(f"Testing XSS on: {url}")
        
        forms = self.get_forms(url)
        
        for form in forms:
            form_details = self.get_form_details(form)
            
            for payload in self.xss_payloads[:5]:  # Limit payloads
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["type"] == "submit":
                        data[input_tag["name"]] = input_tag["value"]
                    elif input_tag["name"]:
                        data[input_tag["name"]] = payload
                
                target_url = urljoin(url, form_details["action"])
                
                try:
                    if form_details["method"] == "post":
                        response = self.session.post(target_url, data=data, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.get(target_url, params=data, timeout=self.timeout, verify=False)
                    
                    # If payload is directly reflected in the response, it's frontend/reflected XSS
                    if payload in response.text:
                        self.log_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            f"Form vulnerable to XSS in action: {form_details['action']}",
                            "High",
                            url,
                            payload,
                            'frontend'
                        )
                        
                except Exception:
                    continue
        
        # Test URL parameters for reflected XSS
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param in params:
                for payload in self.xss_payloads[:3]:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    
                    try:
                        response = self.session.get(url, params=test_params, timeout=self.timeout, verify=False)
                        
                        if payload in response.text:
                            self.log_vulnerability(
                                "Reflected XSS",
                                f"URL parameter '{param}' vulnerable to reflected XSS",
                                "High",
                                url,
                                payload,
                                'frontend'
                            )
                            break
                            
                    except Exception:
                        continue

    def check_security_headers(self, url):
        """Check for missing security headers"""
        self.update_status("Checking Security Headers")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content injection protection',
                'Referrer-Policy': 'Referrer information control'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header} ({description})")
            
            if missing_headers:
                self.log_vulnerability(
                    "Missing Security Headers",
                    f"Missing headers: {', '.join(missing_headers)}",
                    "Medium",
                    url,
                    "",
                    'response-headers'
                )
                
        except Exception as e:
            self.log_vulnerability(
                "Connection Error",
                f"Could not check security headers: {str(e)}",
                "Low",
                url,
                "",
                'response-headers'
            )

    def test_clickjacking(self, url):
        """Test for clickjacking vulnerability"""
        self.update_status("Testing Clickjacking Protection")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            x_frame_options = headers.get('X-Frame-Options', '').upper()
            csp = headers.get('Content-Security-Policy', '').lower()
            
            vulnerable = False
            details = ""
            
            if not x_frame_options:
                vulnerable = True
                details = "No X-Frame-Options header found - vulnerable to clickjacking"
            elif x_frame_options not in ['DENY', 'SAMEORIGIN']:
                vulnerable = True
                details = f"Weak X-Frame-Options configuration: {x_frame_options}"
            
            if not vulnerable and 'frame-ancestors' not in csp:
                vulnerable = True
                details = "No frame-ancestors directive in Content Security Policy"
            
            if vulnerable:
                self.log_vulnerability("Clickjacking", details, "Medium", url, "", 'response-headers')
                
        except Exception as e:
            pass

    def test_ddos_vulnerability(self, url):
        """Test for DDoS vulnerability indicators"""
        self.update_status("Testing DDoS Protection Mechanisms")
        
        ddos_findings = []
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        # 1. Check for rate limiting
        self.update_status("Checking rate limiting...")
        rate_limit_protected = self.check_rate_limiting(url)
        
        # 2. Test resource-intensive endpoints
        self.update_status("Testing resource-intensive endpoints...")
        resource_vulns = self.check_resource_intensive_endpoints(url)
        
        # 3. Check for slowloris vulnerability
        self.update_status("Checking slow request handling...")
        slowloris_vuln = self.check_slowloris_vulnerability(url)
        
        # 4. Check server configuration
        self.update_status("Analyzing server configuration...")
        server_config = self.check_server_configuration(url)
        
        # 5. Test connection limits
        self.update_status("Testing connection limits...")
        connection_vuln = self.check_connection_limits(url)
        
        # Compile findings
        vulnerability_details = []
        risk_score = 0
        
        if not rate_limit_protected:
            vulnerability_details.append("No rate limiting detected - server accepts unlimited requests")
            risk_score += 30
        
        if resource_vulns:
            vulnerability_details.extend(resource_vulns)
            risk_score += 25
        
        if slowloris_vuln:
            vulnerability_details.append("Server may be vulnerable to slowloris attacks")
            risk_score += 20
        
        if server_config:
            vulnerability_details.extend(server_config)
            risk_score += 15
        
        if connection_vuln:
            vulnerability_details.append("Server accepts excessive concurrent connections")
            risk_score += 10
        
        # Determine severity
        if risk_score >= 60:
            severity = "High"
            overall_status = "VULNERABLE"
        elif risk_score >= 30:
            severity = "Medium"
            overall_status = "POTENTIALLY VULNERABLE"
        else:
            severity = "Low"
            overall_status = "PROTECTED"
        
        # Log the vulnerability
        details = f"DDoS Risk Assessment: {overall_status} (Risk Score: {risk_score}/100)\n\n"
        if vulnerability_details:
            details += "Findings:\n• " + "\n• ".join(vulnerability_details)
        else:
            details += "Server appears to have adequate DDoS protection measures in place."
        
        self.log_vulnerability(
            "DDoS Vulnerability Assessment",
            details,
            severity,
            url,
            f"Risk Score: {risk_score}/100",
            "ddos-protection"
        )

    def check_rate_limiting(self, url):
        """Check if server implements rate limiting"""
        try:
            response_times = []
            status_codes = []
            
            # Send multiple rapid requests
            for i in range(10):
                start = time.time()
                try:
                    resp = self.session.get(url, timeout=self.timeout, verify=False)
                    response_times.append(time.time() - start)
                    status_codes.append(resp.status_code)
                except:
                    return True  # If requests fail, assume some protection exists
            
            # Check if we got rate limited (429 status code)
            if 429 in status_codes:
                return True
            
            # Check for consistent fast responses (no throttling)
            avg_response_time = sum(response_times) / len(response_times)
            if avg_response_time < 0.5 and all(code == 200 for code in status_codes):
                return False  # No rate limiting detected
            
            return True  # Some protection detected
            
        except Exception:
            return True  # Assume protected on error

    def check_resource_intensive_endpoints(self, url):
        """Check for resource-intensive endpoints that could be abused"""
        findings = []
        
        # Common resource-intensive paths
        test_paths = [
            '/search?q=' + 'test' * 100,
            '/api/export',
            '/download',
            '/report/generate',
        ]
        
        for path in test_paths:
            try:
                test_url = urljoin(url, path)
                start = time.time()
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                duration = time.time() - start
                
                # If endpoint responds but takes long time, it could be abused
                if resp.status_code == 200 and duration > 2:
                    findings.append(f"Slow endpoint found: {path} ({duration:.2f}s response time)")
                    
            except:
                continue
        
        return findings

    def check_slowloris_vulnerability(self, url):
        """Check basic indicators of slowloris vulnerability"""
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc.split(':')[0]
            port = 443 if parsed_url.scheme == 'https' else 80
            
            # Try to establish connection and send partial request
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send incomplete HTTP request
            sock.send(b"GET / HTTP/1.1\r\n")
            sock.send(f"Host: {host}\r\n".encode())
            
            # Wait to see if server keeps connection open
            time.sleep(3)
            
            try:
                # If we can still send data, connection is kept alive
                sock.send(b"X-Custom: test\r\n")
                sock.close()
                return True  # Potentially vulnerable
            except:
                sock.close()
                return False
                
        except Exception:
            return False

    def check_server_configuration(self, url):
        """Check server configuration for DDoS indicators"""
        findings = []
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            # Check for WAF/CDN (protection indicators)
            protection_headers = [
                'CF-RAY',  # Cloudflare
                'X-CDN',
                'X-Cache',
                'X-Akamai',
                'X-Azure-Ref',
                'X-Amz-Cf-Id',  # Amazon CloudFront
            ]
            
            has_protection = any(header in headers for header in protection_headers)
            
            if not has_protection:
                findings.append("No CDN or WAF detected in response headers")
            
            # Check server header
            server = headers.get('Server', '').lower()
            if server and 'nginx' not in server and 'cloudflare' not in server:
                findings.append(f"Server ({server}) may not have built-in DDoS protection")
            
        except Exception:
            pass
        
        return findings

    def check_connection_limits(self, url):
        """Test if server limits concurrent connections"""
        try:
            def make_request():
                try:
                    return self.session.get(url, timeout=self.timeout, verify=False)
                except:
                    return None
            
            # Try to make multiple concurrent connections
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(make_request) for _ in range(20)]
                results = [f.result() for f in futures]
            
            # Count successful connections
            successful = sum(1 for r in results if r and r.status_code == 200)
            
            # If most connections succeed, there may be no connection limiting
            if successful >= 18:
                return True
            
            return False
            
        except Exception:
            return False

    def crawl_pages(self, url, max_depth=2, visited=None):
        """Simple web crawler"""
        if visited is None:
            visited = set()
        
        if url in visited or max_depth <= 0:
            return visited
        
        visited.add(url)
        self.update_status(f"Crawling: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(url, href)
                
                if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    if full_url not in visited and len(visited) < 5:  # Limit for web interface
                        self.crawl_pages(full_url, max_depth - 1, visited)
        except:
            pass
        
        return visited

    def run_scan(self):
        """Run complete vulnerability scan"""
        try:
            start_time = time.time()
            
            # Initialize
            self.update_status("Initializing scan...", 0)
            
            # Get pages to test
            self.update_status("Discovering pages...", 10)
            pages_to_test = self.crawl_pages(self.target_url, max_depth=1)
            
            total_pages = len(pages_to_test)
            progress_per_page = 70 / total_pages if total_pages > 0 else 70
            current_progress = 20
            
            # Test each page
            for i, page in enumerate(pages_to_test):
                self.update_status(f"Testing page {i+1} of {total_pages}: {page}", current_progress)
                
                self.test_sql_injection(page)
                self.test_xss(page)
                self.check_security_headers(page)
                self.test_clickjacking(page)
                
                current_progress += progress_per_page
            
            # Test DDoS vulnerability (once for the main target)
            self.update_status("Testing DDoS Protection...", 90)
            self.test_ddos_vulnerability(self.target_url)
            
            # Complete scan
            scan_time = time.time() - start_time
            
            result = {
                'scan_id': self.scan_id,
                'target_url': self.target_url,
                'start_time': datetime.now().isoformat(),
                'scan_duration': round(scan_time, 2),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities,
                'pages_tested': list(pages_to_test),
                'summary': self.generate_summary()
            }
            
            scan_results[self.scan_id] = result
            self.update_status("Scan completed!", 100)
            
        except Exception as e:
            self.update_status(f"Scan failed: {str(e)}", 100)

    def generate_summary(self):
        """Generate vulnerability summary"""
        summary = {'High': 0, 'Medium': 0, 'Low': 0}
        vuln_types = {}
        
        for vuln in self.vulnerabilities:
            summary[vuln['severity']] += 1
            vuln_type = vuln['type']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        return {
            'severity_counts': summary,
            'vulnerability_types': vuln_types,
            'total_count': len(self.vulnerabilities)
        }

# Flask Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    try:
        parsed = urlparse(target_url)
        if not parsed.netloc:
            raise ValueError("Invalid URL")
    except:
        return jsonify({'error': 'Invalid URL format'}), 400
    
    # Generate scan ID
    scan_id = str(uuid.uuid4())
    
    # Start scan in background thread
    scanner = VulnerabilityScanner(target_url, scan_id)
    thread = threading.Thread(target=scanner.run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'Scan started'})

@app.route('/status/<scan_id>')
def get_scan_status(scan_id):
    status = scan_status.get(scan_id, {'status': 'Unknown scan ID', 'progress': 0})
    return jsonify(status)

@app.route('/results/<scan_id>')
def get_scan_results(scan_id):
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({'error': 'Scan not found or still in progress'}), 404
    
    return jsonify(result)

@app.route('/export/<scan_id>/<format>')
def export_results(scan_id, format):
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({'error': 'Scan not found'}), 404
    
    if format == 'json':
        # Export as JSON
        output = io.StringIO()
        json.dump(result, output, indent=2)
        output.seek(0)
        
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            as_attachment=True,
            download_name=f'vuln_scan_{scan_id}.json',
            mimetype='application/json'
        )
    
    elif format == 'txt':
        # Export as text report
        output = []
        output.append(f"Vulnerability Scan Report")
        output.append(f"=" * 50)
        output.append(f"Target URL: {result['target_url']}")
        output.append(f"Scan Duration: {result['scan_duration']} seconds")
        output.append(f"Total Vulnerabilities: {result['total_vulnerabilities']}")
        output.append(f"Pages Tested: {len(result['pages_tested'])}")
        output.append("")
        
        summary = result['summary']
        output.append("Severity Summary:")
        for severity, count in summary['severity_counts'].items():
            output.append(f"  {severity}: {count}")
        output.append("")
        
        if result['vulnerabilities']:
            output.append("Detailed Findings:")
            output.append("-" * 30)
            for vuln in result['vulnerabilities']:
                output.append(f"Type: {vuln['type']}")
                output.append(f"Severity: {vuln['severity']}")
                output.append(f"URL: {vuln['url']}")
                output.append(f"Details: {vuln['details']}")
                if vuln.get('payload'):
                    output.append(f"Payload: {vuln['payload']}")
                # Include found_on information in the report
                if vuln.get('found_on'):
                    output.append(f"Found on: {vuln['found_on']}")
                output.append("")
        
        content = '\n'.join(output)
        
        return send_file(
            io.BytesIO(content.encode()),
            as_attachment=True,
            download_name=f'vuln_scan_{scan_id}.txt',
            mimetype='text/plain'
        )
    
    return jsonify({'error': 'Invalid export format'}), 400

# Create templates directory and files
def create_templates():
    """Create HTML templates for the Flask app"""
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Main HTML template
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Vulnerability Scanner</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .vulnerability-card {
            border-left: 4px solid;
            transition: transform 0.2s;
        }
        .vulnerability-card:hover {
            transform: translateY(-2px);
        }
        .high-severity { border-left-color: #dc3545; }
        .medium-severity { border-left-color: #ffc107; }
        .low-severity { border-left-color: #28a745; }
        .scan-progress {
            height: 8px;
            border-radius: 4px;
        }
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
        }
        .status-scanning { background-color: #ffc107; animation: pulse 1.5s infinite; }
        .status-complete { background-color: #28a745; }
        .status-error { background-color: #dc3545; }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        .ddos-badge {
            display: inline-block;
            padding: 0.25rem 0.5rem;
            font-size: 0.75rem;
            border-radius: 0.25rem;
            font-weight: 600;
        }
        .ddos-protected {
            background-color: #d4edda;
            color: #155724;
        }
        .ddos-vulnerable {
            background-color: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="gradient-bg py-5">
        <div class="container">
            <div class="row">
                <div class="col-lg-8 mx-auto text-center">
                    <h1 class="display-4 mb-3">
                        <i class="fas fa-shield-alt"></i> Web Vulnerability Scanner
                    </h1>
                    <p class="lead mb-4">Scan websites for common security vulnerabilities including SQL Injection, XSS, DDoS Protection, and security misconfigurations.</p>
                </div>
            </div>
        </div>
    </div>

    <div class="container mt-5">
        <!-- Scan Form -->
        <div class="row mb-5">
            <div class="col-lg-8 mx-auto">
                <div class="card shadow">
                    <div class="card-body p-4">
                        <h4 class="card-title mb-4"><i class="fas fa-search"></i> Start New Scan</h4>
                        <form id="scanForm">
                            <div class="row">
                                <div class="col-md-9">
                                    <div class="form-group mb-3">
                                        <label for="targetUrl" class="form-label">Target URL</label>
                                        <input type="url" class="form-control form-control-lg" id="targetUrl" 
                                               placeholder="https://example.com" required>
                                        <div class="form-text">Enter the website URL you want to scan for vulnerabilities</div>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">&nbsp;</label>
                                    <button type="submit" class="btn btn-primary btn-lg w-100" id="scanBtn">
                                        <i class="fas fa-play"></i> Start Scan
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>

        <!-- Scan Progress -->
        <div id="scanProgress" class="row mb-5" style="display: none;">
            <div class="col-lg-8 mx-auto">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">
                            <span class="status-indicator status-scanning"></span>
                            Scan in Progress
                        </h5>
                        <div class="progress mb-3">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" 
                                 id="progressBar" style="width: 0%"></div>
                        </div>
                        <p class="mb-0" id="statusMessage">Initializing scan...</p>
                        <div class="mt-2">
                            <small class="text-muted">Vulnerabilities found: <span id="vulnCount">0</span></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Scan Results -->
        <div id="scanResults" style="display: none;">
            <div class="row mb-4">
                <div class="col-lg-8 mx-auto">
                    <div class="card shadow">
                        <div class="card-body">
                            <div class="d-flex justify-content-between align-items-center mb-3">
                                <h4 class="card-title mb-0">
                                    <span class="status-indicator status-complete"></span>
                                    Scan Results
                                </h4>
                                <div class="btn-group" role="group">
                                    <button class="btn btn-outline-primary btn-sm" onclick="exportResults('json')">
                                        <i class="fas fa-download"></i> JSON
                                    </button>
                                    <button class="btn btn-outline-primary btn-sm" onclick="exportResults('txt')">
                                        <i class="fas fa-download"></i> TXT
                                    </button>
                                </div>
                            </div>
                            
                            <div class="row text-center mb-4">
                                <div class="col-md-3">
                                    <div class="border rounded p-3">
                                        <h3 class="text-danger" id="highCount">0</h3>
                                        <small>High Risk</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="border rounded p-3">
                                        <h3 class="text-warning" id="mediumCount">0</h3>
                                        <small>Medium Risk</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="border rounded p-3">
                                        <h3 class="text-success" id="lowCount">0</h3>
                                        <small>Low Risk</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="border rounded p-3">
                                        <h3 class="text-info" id="totalCount">0</h3>
                                        <small>Total Issues</small>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6">
                                    <strong>Target URL:</strong> <span id="targetUrlResult"></span>
                                </div>
                                <div class="col-md-6">
                                    <strong>Scan Duration:</strong> <span id="scanDuration"></span> seconds
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Vulnerabilities List -->
            <div class="row">
                <div class="col-lg-8 mx-auto">
                    <div id="vulnerabilitiesList"></div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
    <script>
        let currentScanId = null;
        let progressInterval = null;

        document.getElementById('scanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const url = document.getElementById('targetUrl').value;
            startScan(url);
        });

        function startScan(url) {
            const scanBtn = document.getElementById('scanBtn');
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';

            fetch('/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url: url})
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert('Error: ' + data.error);
                    resetScanButton();
                } else {
                    currentScanId = data.scan_id;
                    showProgress();
                    startProgressPolling();
                }
            })
            .catch(error => {
                alert('Error starting scan: ' + error);
                resetScanButton();
            });
        }

        function showProgress() {
            document.getElementById('scanProgress').style.display = 'block';
            document.getElementById('scanResults').style.display = 'none';
        }

        function startProgressPolling() {
            progressInterval = setInterval(() => {
                fetch(`/status/${currentScanId}`)
                .then(response => response.json())
                .then(data => {
                    updateProgress(data);
                    
                    if (data.status === 'Scan completed!') {
                        clearInterval(progressInterval);
                        loadResults();
                    }
                });
            }, 1000);
        }

        function updateProgress(data) {
            const progressBar = document.getElementById('progressBar');
            const statusMessage = document.getElementById('statusMessage');
            const vulnCount = document.getElementById('vulnCount');
            
            if (data.progress) {
                progressBar.style.width = data.progress + '%';
            }
            statusMessage.textContent = data.status;
            vulnCount.textContent = data.vulnerabilities_found || 0;
        }

        function loadResults() {
            fetch(`/results/${currentScanId}`)
            .then(response => response.json())
            .then(data => {
                displayResults(data);
                resetScanButton();
            });
        }

        function displayResults(data) {
            document.getElementById('scanProgress').style.display = 'none';
            document.getElementById('scanResults').style.display = 'block';
            
            // Update summary counts
            const summary = data.summary.severity_counts;
            document.getElementById('highCount').textContent = summary.High || 0;
            document.getElementById('mediumCount').textContent = summary.Medium || 0;
            document.getElementById('lowCount').textContent = summary.Low || 0;
            document.getElementById('totalCount').textContent = data.total_vulnerabilities;
            
            // Update scan info
            document.getElementById('targetUrlResult').textContent = data.target_url;
            document.getElementById('scanDuration').textContent = data.scan_duration;
            
            // Display vulnerabilities
            displayVulnerabilities(data.vulnerabilities);
        }

        function displayVulnerabilities(vulnerabilities) {
            const container = document.getElementById('vulnerabilitiesList');
            container.innerHTML = '';
            
            if (vulnerabilities.length === 0) {
                container.innerHTML = `
                    <div class="card shadow">
                        <div class="card-body text-center py-5">
                            <i class="fas fa-shield-alt text-success fa-3x mb-3"></i>
                            <h4 class="text-success">No Vulnerabilities Found!</h4>
                            <p class="text-muted">The target website appears to be secure based on our tests.</p>
                        </div>
                    </div>`;
                return;
            }
            
            vulnerabilities.forEach(vuln => {
                const severityClass = vuln.severity.toLowerCase() + '-severity';
                const severityIcon = vuln.severity === 'High' ? 'fas fa-exclamation-triangle text-danger' :
                                   vuln.severity === 'Medium' ? 'fas fa-exclamation-circle text-warning' :
                                   'fas fa-info-circle text-success';
                
                const foundOnHtml = vuln.found_on ? `<p class="mb-1"><strong>Found on:</strong> <code>${vuln.found_on}</code></p>` : '';
                
                // Special handling for DDoS vulnerability
                let ddosBadge = '';
                if (vuln.type === 'DDoS Vulnerability Assessment') {
                    const isDdosProtected = vuln.severity === 'Low';
                    ddosBadge = `<span class="ddos-badge ${isDdosProtected ? 'ddos-protected' : 'ddos-vulnerable'}">
                        <i class="fas fa-${isDdosProtected ? 'shield-check' : 'shield-exclamation'}"></i>
                        ${isDdosProtected ? 'DDoS Protected' : 'DDoS Vulnerable'}
                    </span>`;
                }
                
                const card = document.createElement('div');
                card.className = 'card vulnerability-card shadow mb-3 ' + severityClass;
                card.innerHTML = `
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-start">
                            <div class="flex-grow-1">
                                <h5 class="card-title">
                                    <i class="${severityIcon}"></i>
                                    ${vuln.type}
                                    <span class="badge bg-${vuln.severity === 'High' ? 'danger' : vuln.severity === 'Medium' ? 'warning' : 'success'} ms-2">
                                        ${vuln.severity}
                                    </span>
                                    ${ddosBadge}
                                </h5>
                                <p class="card-text" style="white-space: pre-line;">${vuln.details}</p>
                                ${vuln.url ? `<p class="mb-1"><strong>URL:</strong> <code>${vuln.url}</code></p>` : ''}
                                ${vuln.payload ? `<p class="mb-1"><strong>Payload:</strong> <code>${vuln.payload}</code></p>` : ''}
                                ${foundOnHtml}
                                <small class="text-muted">Found: ${new Date(vuln.timestamp).toLocaleString()}</small>
                            </div>
                        </div>
                    </div>`;
                container.appendChild(card);
            });
        }

        function resetScanButton() {
            const scanBtn = document.getElementById('scanBtn');
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-play"></i> Start Scan';
        }

        function exportResults(format) {
            if (!currentScanId) return;
            window.open(`/export/${currentScanId}/${format}`, '_blank');
        }

        // Add some example URLs for demo
        const examples = [
            'http://testphp.vulnweb.com/',
            'https://demo.testfire.net/',
            'http://zero.webappsecurity.com/'
        ];
        
        // Add click handler for examples (optional)
        document.addEventListener('DOMContentLoaded', function() {
            const urlInput = document.getElementById('targetUrl');
            urlInput.placeholder = 'https://example.com (Try: ' + examples[0] + ')';
        });
    </script>
</body>
</html>'''
    
    with open('templates/index.html', 'w') as f:
        f.write(html_content)

if __name__ == '__main__':
   
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)