"""
DEFPAGE - Default Server Welcome Page Detection Module

This module analyzes default welcome pages served by web servers when accessing
IP addresses directly. Different web servers and operating systems have distinct
default pages that can reveal technology information.

The module tests both HTTP and HTTPS protocols, as servers may be configured
differently for each protocol. It uses regular expressions to identify technologies
and versions from the content of default pages.

Includes:
- DEFPAGE class to perform default page analysis and classification.
- run() function as an entry point to execute the test.

Usage:
    DEFPAGE(args, ptjsonlib, helpers, http_client, responses).run()
"""

import re
import socket
import ssl
from urllib.parse import urlparse
from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses

from typing import List, Dict, Any, Optional, Tuple
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test default server welcome pages for technology identification"


class DEFPAGE:
    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        """Initialize the DEFPAGE test with provided components and load page definitions."""
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.definitions = self.helpers.load_definitions("defpage.json")
        self.target_ip = self._extract_ip_from_url(args.url)
        self.detected_technologies = []

    def _extract_ip_from_url(self, url: str) -> Optional[str]:
        """
        Extract IP address from URL or resolve hostname to IP.
        
        Args:
            url: Target URL
            
        Returns:
            IP address string or None if unable to resolve
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass
        
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    def run(self) -> None:
        """
        Execute the DEFPAGE test logic.
        
        Tests both HTTP and HTTPS protocols on the target IP address,
        retrieves default pages, and analyzes them for technology signatures.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        #if self.args.verbose:
        #    ptprint(f"Testing default pages on IP: {self.target_ip}", "ADDITIONS", not self.args.json, indent=4, colortext=True)

        protocols = ['http', 'https']
        
        for protocol in protocols:
            self._test_protocol(protocol)

        self._report_findings()

    def _test_protocol(self, protocol: str) -> None:
        """
        Test default page for a specific protocol.
        
        Args:
            protocol: 'http' or 'https'
        """
        url = f"{protocol}://{self.target_ip}/"
        
        response = self.helpers.fetch(url)
        
        if response is None:
            return
        
        if not hasattr(response, 'text'):
            ptprint(f"Response object has no text attribute for {protocol.upper()}", "INFO", not self.args.json, indent=8)
            return
            
        content = response.text
        status_code = getattr(response, 'status_code', 0)

        if self.args.verbose:
            self._debug_output(content, protocol, response, url)
        
        technologies = self._analyze_page_content(content, protocol, response)
        
        if technologies:
            for tech in technologies:
                tech['protocol'] = protocol
                tech['url'] = url
                self.detected_technologies.append(tech)

    def _debug_output(self, content: str, protocol: str, response: object, url: str) -> None:
        """
        Debug output shown when the -vv flag is used.

        Args:
            content: HTML content of the page.
            protocol: Protocol used (e.g., HTTP, HTTPS).
            response: Response object returned by the request.
            url: Requested URL address.
        """

        title = self._extract_title(content)
        if title:
            ptprint(f"HTML Title: {title}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        else:
            ptprint("HTML Title: Not found or empty", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        if hasattr(response, 'headers') and self.args.verbose:
            server_header = response.headers.get('Server', 'Not found')
            ptprint(f"Server Header: {server_header}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        method_info = self._determine_method(response, content, url)
        ptprint(f"Method: {method_info}", "ADDITIONS", not self.args.json, indent=8, colortext=True)

    def _extract_title(self, content: str) -> Optional[str]:
        """
        Extracts the contents of the HTML <title> element.

        Args:
            content: HTML content.

        Returns:
            The title text or None if not found.
        """
        
        title_pattern = r'<title[^>]*>(.*?)</title>'
        match = re.search(title_pattern, content, re.IGNORECASE | re.DOTALL)
        
        if match:
            title = match.group(1).strip()
            title = re.sub(r'<[^>]+>', '', title)
            title = re.sub(r'\s+', ' ', title)
            return title if title else None
        
        return None

    def _determine_method(self, response: object, content: str, url: str) -> str:
        """
        Determines how the default page was delivered.

        Args:
            response: Response object.
            content: HTML content.
            url: Requested URL.

        Returns:
            Human-readable description of the delivery method.
        """
        status_code = getattr(response, 'status_code', 0)
        
        if hasattr(response, 'history') and response.history:
            return f"HTTP Redirect (final status: {status_code})"
        
        if status_code == 200:
            if self._is_index_page(content):
                return "Default index page (200) (GET method)"
            elif self._is_server_generated(content):
                return "Server-generated default page (200) (GET method)"
            else:
                return "Static default page (200) (GET method)"
        elif status_code == 403:
            return "Access forbidden - directory listing disabled (403)(GET method)"
        elif status_code == 404:
            return "Not found - custom 404 page (GET method)"
        elif status_code in [301, 302, 303, 307, 308]:
            return f"HTTP Redirect ({status_code}) (GET method)"
        else:
            return f"HTTP {status_code} response (GET method)"

    def _is_index_page(self, content: str) -> bool:
        """Checks whether the content looks like a typical index page."""
        index_indicators = [
            r'index\.html?',
            r'welcome\s+to',
            r'default\s+page',
            r'home\s+page',
            r'directory\s+listing'
        ]
        
        for pattern in index_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _is_server_generated(self, content: str) -> bool:
        """Checks whether the page appears to be server-generated."""
        server_indicators = [
            r'apache.*server',
            r'nginx.*server',
            r'iis.*server',
            r'server\s+information',
            r'web\s+server\s+is\s+running'
        ]
        
        for pattern in server_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def _analyze_page_content(self, content: str, protocol: str, response: object = None) -> List[Dict[str, Any]]:
        """
        Analyze page content and headers against known default page patterns.
        
        Args:
            content: HTML content of the page
            protocol: Protocol used ('http' or 'https')
            response: HTTP response object containing headers
            
        Returns:
            List of detected technologies (deduplicated by technology name)
        """
        detected = []
        seen_technologies = set()
        
        if not self.definitions:
            return detected

        patterns = self.definitions.get('patterns', [])
        
        headers_dict = {}
        if response and hasattr(response, 'headers'):
            headers_dict = dict(response.headers)
        
        for pattern_def in patterns:
            match_result = self._match_pattern(content, pattern_def, 'content')
            
            if not match_result and headers_dict:
                headers_text = '\n'.join([f"{k}: {v}" for k, v in headers_dict.items()])
                match_result = self._match_pattern(headers_text, pattern_def, 'headers')
            
            if match_result:
                tech_key = match_result.get('technology', match_result.get('name', 'Unknown')).lower()
                
                if tech_key not in seen_technologies:
                    detected.append(match_result)
                    seen_technologies.add(tech_key)
        
        return detected

    def _match_pattern(self, content: str, pattern_def: Dict[str, Any], source_type: str = 'content') -> Optional[Dict[str, Any]]:
        """
        Match content against a specific pattern definition.
        
        Args:
            content: Page content to analyze
            pattern_def: Pattern definition from JSON
            source_type: 'content' or 'headers'
            
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
            'source_location': source_type
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
        
        return result

    def _report_findings(self) -> None:
        """
        Report detected technologies and store them.
        """
        if not self.detected_technologies:
            ptprint("No default page technologies identified", "INFO", not self.args.json, indent=4)
            return

        by_protocol = {}
        for tech in self.detected_technologies:
            protocol = tech.get('protocol', 'unknown')
            if protocol not in by_protocol:
                by_protocol[protocol] = []
            by_protocol[protocol].append(tech)

        for protocol, techs in by_protocol.items():
            ptprint(f"{protocol.upper()} default page technologies", "INFO", not self.args.json, indent=4)
            
            for tech in techs:
                version_text = f" {tech['version']}" if tech.get('version') else ""
                category_text = f" ({tech['category']})"
                
                ptprint(f"{tech['technology']}{version_text}{category_text}", 
                       "VULN", not self.args.json, indent=8)
                
                if self.args.verbose:
                    source_location = tech.get('source_location', 'content')
                    ptprint(f"Matched: {tech.get('matched_text', 'N/A')} (from {source_location})", 
                           "ADDITIONS", not self.args.json, indent=12, colortext=True)

        unique_technologies = {}
        for tech in self.detected_technologies:
            tech_key = f"{tech.get('technology', 'Unknown').lower()}_{tech.get('protocol', 'unknown')}"
            if tech_key not in unique_technologies:
                unique_technologies[tech_key] = tech
        
        for tech in unique_technologies.values():
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
        protocol = tech.get('protocol', 'unknown')
        source_location = tech.get('source_location', 'content')
        
        description = f"Default {protocol.upper()} page: {tech_name}"
        if version:
            description += f" {version}"
        description += f" (detected from {source_location})"
        
        storage.add_to_storage(
            technology=tech_name,
            version=version,
            technology_type=tech_type,
            probability=probability,
            description=description
        )


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point to run the DEFPAGE test."""
    DEFPAGE(args, ptjsonlib, helpers, http_client, responses).run()