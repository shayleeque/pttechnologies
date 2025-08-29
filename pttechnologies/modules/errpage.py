"""
ERRPAGE - Error Page Technology Detection Module

This module analyzes error pages served by web servers by deliberately triggering
various HTTP error conditions. Different web servers and technologies have distinct
error page formats that can reveal technology information.

The module tests various error conditions:
- 404 Not Found (non-existent pages)
- 403 Forbidden (restricted files like .ht, .htaccess)
- 400 Bad Request (invalid URLs with %, empty headers)
- 414 URI Too Long (extremely long URLs)
- 505 HTTP Version Not Supported (invalid HTTP versions)

Includes:
- ERRPAGE class to perform error page analysis and classification.
- run() function as an entry point to execute the test.

Usage:
    ERRPAGE(args, ptjsonlib, helpers, http_client, responses).run()
"""

import re
import socket
import ssl
from urllib.parse import urlparse, urljoin
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses

from typing import List, Dict, Any, Optional, Tuple
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test error pages for technology identification"


class ERRPAGE:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the ERRPAGE test with provided components and load error page definitions."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        
        self.errpage_definitions = self.helpers.load_definitions("errpage.json")
        self.defpage_definitions = self.helpers.load_definitions("defpage.json")
        
        self.all_patterns = []
        if self.errpage_definitions:
            self.all_patterns.extend(self.errpage_definitions.get('patterns', []))
        if self.defpage_definitions:
            self.all_patterns.extend(self.defpage_definitions.get('patterns', []))
        
        self.base_url = args.url.rstrip('/')
        self.detected_technologies = []
        self.tested_triggers = []

    def run(self) -> None:
        """
        Execute the ERRPAGE test logic.
        
        Tests various error conditions to trigger different error pages,
        then analyzes the responses for technology signatures.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        if not self.errpage_definitions:
            ptprint("No error page definitions loaded", "INFO", not self.args.json, indent=4)
            return

        error_triggers = self.errpage_definitions.get('error_triggers', [])
        
        if not error_triggers:
            ptprint("No error triggers defined", "INFO", not self.args.json, indent=4)
            return

        for trigger in error_triggers:
            self._test_error_trigger(trigger)

        self._report_findings()

    def _test_error_trigger(self, trigger: Dict[str, Any]) -> None:
        """
        Test a specific error trigger condition.
        
        Args:
            trigger: Error trigger definition from JSON
        """
        trigger_name = trigger.get('name', 'Unknown Trigger')
        method = trigger.get('method', 'GET')
        
        try:
            if method == 'RAW' or trigger.get('headers'):
                response = self._send_raw_request(trigger)
            else:
                response = self._send_standard_request(trigger)
            
            if response is None:
                return
            
            self.tested_triggers.append({
                'name': trigger_name,
                'method': method,
                'path': trigger.get('path', '/'),
                'status_code': getattr(response, 'status_code', 0),
                'expected_status': trigger.get('expected_status', [])
            })
            
            if hasattr(response, 'text') and response.text:                    
                technologies = self._analyze_error_content(response.text, trigger_name)
                
                if technologies:
                    for tech in technologies:
                        tech['trigger'] = trigger_name
                        tech['status_code'] = getattr(response, 'status_code', 0)
                        tech['url'] = getattr(response, 'url', self.base_url)
                        self.detected_technologies.append(tech)
                
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Error testing trigger {trigger_name}: {str(e)}", "INFO", not self.args.json, indent=8)
            return

    def _send_standard_request(self, trigger: Dict[str, Any]) -> Optional[object]:
        """
        Send a standard HTTP request for the given trigger.
        
        Args:
            trigger: Trigger configuration
            
        Returns:
            Response object or None
        """
        method = trigger.get('method', 'GET')
        path = trigger.get('path', '/')
        
        if '{LONG_PATH_8000}' in path:
            path = path.replace('{LONG_PATH_8000}', 'a' * 8000)
        elif '{LONG_PATH_' in path:
            match = re.search(r'\{LONG_PATH_(\d+)\}', path)
            if match:
                length = int(match.group(1))
                path = path.replace(match.group(0), 'a' * length)
        
        url = urljoin(self.base_url + '/', path.lstrip('/'))

        response = self.helpers.fetch(url)
        
        if response:
            return response
        return None
        
    def _send_raw_request(self, trigger: Dict[str, Any]) -> Optional[object]:
        """
        Send a raw HTTP request for the given trigger.
        
        Args:
            trigger: Trigger configuration
            
        Returns:
            Response-like object or None
        """
        method = trigger.get('method', 'GET')
        path = trigger.get('path', '/')
        headers = trigger.get('headers', {})
        raw_request_template = trigger.get('raw_request', '')
        
        if '{LONG_PATH_8000}' in path:
            path = path.replace('{LONG_PATH_8000}', 'a' * 8000)
        elif '{LONG_PATH_' in path:
            match = re.search(r'\{LONG_PATH_(\d+)\}', path)
            if match:
                length = int(match.group(1))
                path = path.replace(match.group(0), 'a' * length)
        
        parsed_url = urlparse(self.base_url)
        host = parsed_url.hostname or 'localhost'
        port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
        
        if raw_request_template:
            raw_request = raw_request_template.replace('{host}', host)
            raw_request = raw_request.replace('\\r\\n', '\r\n')
            raw_request = raw_request.replace('\\n', '\n')
        else:
            raw_request = f"{method} {path} HTTP/1.1\r\n"
            raw_request += f"Host: {host}\r\n"
            
            for header_name, header_value in headers.items():
                raw_request += f"{header_name}: {header_value}\r\n"
            
            raw_request += "\r\n"
        
        return self._send_custom_raw_request(raw_request, parsed_url, host, port)

    def _send_custom_raw_request(self, raw_request: str, parsed_url: object, host: str, port: int) -> Optional[object]:
        """
        Send a custom raw HTTP request.
        
        Args:
            raw_request: The raw HTTP request string
            parsed_url: Parsed URL object
            host: Target hostname
            port: Target port
            
        Returns:
            Response-like object or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.send(raw_request.encode('utf-8'))
            
            response_data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 100000:
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            response_text = response_data.decode('utf-8', errors='ignore')
            
            status_code = 0
            if response_text:
                lines = response_text.split('\n')
                if lines and 'HTTP/' in lines[0]:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except ValueError:
                            pass
            
            class RawResponse:
                def __init__(self, text, status_code, url):
                    self.text = text
                    self.status_code = status_code
                    self.url = url
            
            return RawResponse(response_text, status_code, f"{parsed_url.scheme}://{host}:{port}/")
            
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Custom raw request failed: {str(e)}", "INFO", not self.args.json, indent=8)
            return None

    def _analyze_error_content(self, content: str, trigger_name: str) -> List[Dict[str, Any]]:
        """
        Analyze error page content against known error page patterns.
        
        Args:
            content: HTML content of the error page
            trigger_name: Name of the trigger that generated this error
            
        Returns:
            List of detected technologies (deduplicated by technology name)
        """
        detected = []
        seen_technologies = set()
        
        if not self.all_patterns:
            return detected

        for pattern_def in self.all_patterns:
            if (pattern_def.get('technology', '').lower() == 'version' and 
                pattern_def.get('category', '').lower() == 'version'):
                continue
                
            match_result = self._match_pattern(content, pattern_def)
            if match_result:
                tech_key = match_result.get('technology', match_result.get('name', 'Unknown')).lower()
                
                if tech_key not in seen_technologies:
                    match_result['trigger_name'] = trigger_name
                    detected.append(match_result)
                    seen_technologies.add(tech_key)
        
        return detected

    def _match_pattern(self, content: str, pattern_def: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Match content against a specific pattern definition.
        
        Args:
            content: Page content to analyze
            pattern_def: Pattern definition from JSON
            
        Returns:
            Technology information if matched, None otherwise
        """
        pattern = pattern_def.get('pattern', '')
        if not pattern:
            return None
            
        flags = pattern_def.get('flags', 'i')
        
        re_flags = 0
        if 'i' in flags.lower():
            re_flags |= re.IGNORECASE
        if 'm' in flags.lower():
            re_flags |= re.MULTILINE
        if 's' in flags.lower():
            re_flags |= re.DOTALL
        
        try:
            match = re.search(pattern, content, re_flags)
        except re.error as e:
            if self.args.verbose:
                ptprint(f"Invalid regex pattern in definitions: {e}", "INFO", not self.args.json, indent=8)
            return None
        
        if not match:
            return None
                    
        result = {
            'name': pattern_def.get('name', 'Unknown'),
            'category': pattern_def.get('category', 'unknown'),
            'technology': pattern_def.get('technology', pattern_def.get('name', 'Unknown')),
            'version': None,
            'matched_text': match.group(0)[:100] + ('...' if len(match.group(0)) > 100 else ''),
            'pattern_used': pattern 
        }
        
        version_pattern = pattern_def.get('version_pattern')
        if version_pattern:
            try:
                version_match = re.search(version_pattern, content, re_flags)
                if version_match:
                    result['version'] = version_match.group(1) if version_match.groups() else version_match.group(0)
            except re.error:
                pass
        elif match.groups():
            result['version'] = match.group(1)

        if pattern_def.get('extract_tech') and match.groups():
            footer_text = match.group(1)
            tech_match = re.search(r'(Apache|nginx|IIS|Tomcat|Jetty|LiteSpeed|OpenResty|IBM_HTTP_Server)', footer_text, re.IGNORECASE)
            if tech_match:
                result['technology'] = tech_match.group(1)
        
        return result

    def _report_findings(self) -> None:
        """
        Report detected technologies and store them.
        """
        if not self.detected_technologies:
            ptprint("No error page technologies identified", "INFO", not self.args.json, indent=4)
            return

        unique_techs = {}
        for tech in self.detected_technologies:
            tech_key = tech.get('technology', 'Unknown').lower()
            if tech_key not in unique_techs:
                unique_techs[tech_key] = tech

        for tech in unique_techs.values():
            version_text = f" {tech['version']}" if tech.get('version') else ""
            category_text = f" ({tech['category']})" if tech.get('category') else ""
            
            ptprint(f"{tech['technology']}{version_text}{category_text}", 
                   "VULN", not self.args.json, indent=4)
            
            if self.args.verbose:
                ptprint(f"Detected via: {tech.get('trigger_name', 'unknown')} [HTTP {tech.get('status_code', '?')}]", 
                       "ADDITIONS", not self.args.json, indent=8, colortext=True)
                if tech.get('pattern_used'):
                    ptprint(f"Pattern used: {tech.get('pattern_used')}", 
                           "ADDITIONS", not self.args.json, indent=8, colortext=True)
                if tech.get('matched_text'):
                    ptprint(f"Matched text: '{tech.get('matched_text')}'", 
                           "ADDITIONS", not self.args.json, indent=8, colortext=True)

        for tech in unique_techs.values():
            self._store_technology(tech)

    def _store_technology(self, tech: Dict[str, Any]) -> None:
        """
        Store detected technology in the storage system.
        
        Args:
            tech: Detected technology information
        """
        tech_name = tech.get('technology', tech.get('name', 'Unknown'))
        version = tech.get('version')
        tech_type = tech.get('category')
        probability = tech.get('probability', 100)
        trigger_name = tech.get('trigger_name', 'unknown')
        status_code = tech.get('status_code')
        
        description = f"Error page ({trigger_name}): {tech_name}"
        if version:
            description += f" {version}"
        if status_code:
            description += f" [HTTP {status_code}]"
        
        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech_type,
            probability=probability,
            description=description
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the ERRPAGE test."""
    ERRPAGE(args, ptjsonlib, helpers, http_client, responses).run()