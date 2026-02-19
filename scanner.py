import requests
import re
import logging
from typing import List, Dict
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from payload_manager import PayloadManager
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class VulnerabilityScanner:
    """Advanced vulnerability scanner with payload integration"""
    
    def __init__(self, max_workers: int = 4):
        self.payload_manager = PayloadManager()
        self.max_workers = max_workers
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Epic-Pentesting-Tool/1.0'
        })
    
    def scan_url(self, url: str, depth: int = 2) -> List[Dict]:
        """Perform comprehensive vulnerability scan on target URL"""
        logger.info(f"Starting scan on {url} with depth {depth}")
        self.vulnerabilities = []
        
        try:
            # Fetch target
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'lxml')
            
            # Run all scan types
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._scan_xss, response.text, url): 'XSS',
                    executor.submit(self._scan_sql_injection, response.text, url): 'SQL Injection',
                    executor.submit(self._scan_csrf, soup, url): 'CSRF',
                    executor.submit(self._scan_headers, response.headers): 'Headers',
                    executor.submit(self._scan_command_injection, response.text, url): 'Command Injection',
                    executor.submit(self._scan_path_traversal, response.text, url): 'Path Traversal',
                    executor.submit(self._scan_xxe, response.text, url): 'XXE',
                    executor.submit(self._scan_open_redirect, soup, url): 'Open Redirect',
                }
                
                for future in as_completed(futures):
                    vuln_type = futures[future]
                    try:
                        results = future.result()
                        self.vulnerabilities.extend(results)
                        logger.info(f"Completed {vuln_type} scan")
                    except Exception as e:
                        logger.error(f"Error in {vuln_type} scan: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning URL: {e}")
        
        return self.vulnerabilities
    
    def _scan_xss(self, html: str, url: str) -> List[Dict]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        xss_patterns = [
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=\s*["\']',
            r'javascript:',
            r'eval\(',
            r'innerHTML\s*=',
        ]
        
        found = False
        for pattern in xss_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found = True
                break
        
        if found:
            payloads = self.payload_manager.fetch_payloads('xss')
            vulnerabilities.append({
                'type': 'XSS',
                'severity': 'High',
                'title': 'Cross-Site Scripting (XSS) Vulnerability',
                'description': 'The application may be vulnerable to XSS attacks',
                'url': url,
                'payloads': payloads[:10],
                'remediation': {
                    'title': 'Implement Input Validation and Output Encoding',
                    'description': 'Sanitize all user inputs and encode output',
                    'fix': 'Use DOMPurify or similar library to sanitize inputs',
                }
            })
        
        return vulnerabilities
    
    def _scan_sql_injection(self, html: str, url: str) -> List[Dict]:
        """Scan for SQL Injection vulnerabilities"""
        vulnerabilities = []
        sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bor\b.*\b1\s*=\s*1)",
            r"(\bdrop\b.*\btable\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bupdate\b.*\bset\b)",
        ]
        
        found = False
        for pattern in sql_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found = True
                break
        
        if found:
            payloads = self.payload_manager.fetch_payloads('sql_injection')
            vulnerabilities.append({
                'type': 'SQL Injection',
                'severity': 'Critical',
                'title': 'SQL Injection Vulnerability',
                'description': 'The application may be vulnerable to SQL injection',
                'url': url,
                'payloads': payloads[:10],
                'remediation': {
                    'title': 'Use Prepared Statements',
                    'description': 'Always use parameterized queries',
                    'fix': 'Replace string concatenation with prepared statements',
                }
            })
        
        return vulnerabilities
    
    def _scan_csrf(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Scan for CSRF vulnerabilities"""
        vulnerabilities = []
        forms = soup.find_all('form', method='POST')
        
        for form in forms:
            # Check if form has CSRF token
            csrf_token = form.find('input', {'name': re.compile(r'csrf|token|nonce', re.I)})
            
            if not csrf_token:
                payloads = self.payload_manager.fetch_payloads('csrf')
                vulnerabilities.append({
                    'type': 'CSRF',
                    'severity': 'Medium',
                    'title': 'CSRF Protection Missing',
                    'description': 'Form lacks CSRF token protection',
                    'url': url,
                    'payloads': payloads[:5],
                    'remediation': {
                        'title': 'Implement CSRF Tokens',
                        'description': 'Add CSRF tokens to all state-changing forms',
                        'fix': 'Generate and validate unique tokens for each form',
                    }
                })
                break
        
        return vulnerabilities
    
    def _scan_headers(self, headers: Dict) -> List[Dict]:
        """Scan for missing security headers"""
        vulnerabilities = []
        required_headers = {
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Type Sniffing Protection',
            'Strict-Transport-Security': 'HTTPS Enforcement',
            'Content-Security-Policy': 'XSS Protection',
            'X-XSS-Protection': 'XSS Filter',
        }
        
        for header, description in required_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'Insecure Headers',
                    'severity': 'Medium',
                    'title': f'Missing Security Header: {header}',
                    'description': f'{description} header not set',
                    'url': 'N/A',
                    'payloads': [],
                    'remediation': {
                        'title': f'Add {header} Header',
                        'description': f'Configure server to include {header}',
                        'fix': f'Add header: {header}: <appropriate-value>',
                    }
                })
        
        return vulnerabilities
    
    def _scan_command_injection(self, html: str, url: str) -> List[Dict]:
        """Scan for command injection vulnerabilities"""
        vulnerabilities = []
        patterns = [
            r'system\(',
            r'exec\(',
            r'shell_exec\(',
            r'passthru\(',
            r'proc_open\(',
        ]
        
        found = False
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found = True
                break
        
        if found:
            payloads = self.payload_manager.fetch_payloads('command_injection')
            vulnerabilities.append({
                'type': 'Command Injection',
                'severity': 'Critical',
                'title': 'Command Injection Vulnerability',
                'description': 'Application may execute arbitrary system commands',
                'url': url,
                'payloads': payloads[:10],
                'remediation': {
                    'title': 'Avoid System Command Execution',
                    'description': 'Use built-in functions instead of shell commands',
                    'fix': 'Replace system() calls with language-specific functions',
                }
            })
        
        return vulnerabilities
    
    def _scan_path_traversal(self, html: str, url: str) -> List[Dict]:
        """Scan for path traversal vulnerabilities"""
        vulnerabilities = []
        patterns = [
            r'file=\.\./\.\.',
            r'path=\.\./\.\.',
            r'include=\.\./\.\.',
        ]
        
        found = False
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                found = True
                break
        
        if found:
            payloads = self.payload_manager.fetch_payloads('path_traversal')
            vulnerabilities.append({
                'type': 'Path Traversal',
                'severity': 'High',
                'title': 'Path Traversal Vulnerability',
                'description': 'Application may allow access to unauthorized files',
                'url': url,
                'payloads': payloads[:10],
                'remediation': {
                    'title': 'Validate File Paths',
                    'description': 'Restrict file access to intended directories',
                    'fix': 'Use whitelist validation for file paths',
                }
            })
        
        return vulnerabilities
    
    def _scan_xxe(self, html: str, url: str) -> List[Dict]:
        """Scan for XXE vulnerabilities"""
        vulnerabilities = []
        if 'xml' in html.lower() or '<?xml' in html:
            payloads = self.payload_manager.fetch_payloads('xxe')
            vulnerabilities.append({
                'type': 'XXE',
                'severity': 'High',
                'title': 'XML External Entity (XXE) Vulnerability',
                'description': 'Application processes XML without disabling external entities',
                'url': url,
                'payloads': payloads[:10],
                'remediation': {
                    'title': 'Disable XXE Processing',
                    'description': 'Disable external entity processing in XML parsers',
                    'fix': 'Set XMLConstants.ACCESS_EXTERNAL_DTD to empty string',
                }
            })
        
        return vulnerabilities
    
    def _scan_open_redirect(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Scan for open redirect vulnerabilities"""
        vulnerabilities = []
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link.get('href', '')
            if any(param in href.lower() for param in ['redirect', 'url', 'return', 'target']):
                vulnerabilities.append({
                    'type': 'Open Redirect',
                    'severity': 'Medium',
                    'title': 'Potential Open Redirect',
                    'description': 'Link parameter may allow redirect to external sites',
                    'url': url,
                    'payloads': ['http://attacker.com', 'https://evil.com'],
                    'remediation': {
                        'title': 'Validate Redirect URLs',
                        'description': 'Whitelist allowed redirect destinations',
                        'fix': 'Validate redirect URLs against whitelist',
                    }
                })
                break
        
        return vulnerabilities
    
    def get_vulnerability_summary(self) -> Dict:
        """Get summary of found vulnerabilities"""
        summary = {
            'total': len(self.vulnerabilities),
            'critical': len([v for v in self.vulnerabilities if v['severity'] == 'Critical']),
            'high': len([v for v in self.vulnerabilities if v['severity'] == 'High']),
            'medium': len([v for v in self.vulnerabilities if v['severity'] == 'Medium']),
            'low': len([v for v in self.vulnerabilities if v['severity'] == 'Low']),
        }
        return summary
