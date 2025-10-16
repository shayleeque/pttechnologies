"""
PLUGINS - Plugin Detection Module

This module implements detection of plugins (primarily WordPress plugins)
by analyzing HTML content from the homepage. It extracts all URLs containing
'/plugins/' pattern, identifies plugin names, and attempts to detect versions
from URLs or readme.txt files.

Classes:
    PLUGINS: Main detector class.

Functions:
    run: Entry point to execute the detection.

Usage:
    PLUGINS(args, ptjsonlib, helpers, http_client, responses).run()

"""

import re
from urllib.parse import urlparse, urljoin
from collections import defaultdict

from helpers.result_storage import storage
from helpers.stored_responses import StoredResponses
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from bs4 import BeautifulSoup

__TESTLABEL__ = "Test plugin detection"


class PLUGINS:
    """
    PLUGINS performs plugin detection and version identification.

    This class analyzes HTML content to find plugin references, extract
    plugin names, and detect versions from URLs or readme files.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses) -> None:
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client

        # Unpack stored responses
        self.response_hp = responses.resp_hp
        self.response_404 = responses.resp_404

        self.plugin_definitions = self.helpers.load_definitions("plugins.json")
        self.detected_plugins = {}

    def run(self):
        """
        Runs the plugin detection process.

        Uses a pre-fetched homepage response to find all plugin references,
        extract plugin names, and attempt version detection.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        base_url = self.args.url.rstrip("/")
        resp = self.response_hp
        html = resp.text

        # Extract all plugin references from HTML
        plugin_urls = self._extract_plugin_urls(html, base_url)
        
        if self.args.verbose:
            ptprint(f"Found {len(plugin_urls)} plugin references", "INFO", not self.args.json, indent=4, colortext=True)

        # Analyze each plugin
        for plugin_url in plugin_urls:
            self._analyze_plugin(plugin_url, base_url)

        # Report findings
        self._report()

    def _extract_plugin_urls(self, html, base_url):
        """
        Extracts all URLs containing '/plugins/' pattern from HTML content.

        Args:
            html (str): HTML content of the page.
            base_url (str): Base URL for resolving relative links.

        Returns:
            set: Set of unique plugin URLs.
        """
        plugin_urls = set()
        
        # Parse HTML to find all URLs
        soup = BeautifulSoup(html, "html.parser")
        
        # Check various HTML tags that can contain URLs
        tags_attrs = [
            ("script", "src"),
            ("link", "href"),
            ("img", "src"),
            ("a", "href"),
            ("iframe", "src")
        ]
        
        for tag, attr in tags_attrs:
            for element in soup.find_all(tag):
                url = element.get(attr)
                if url and "/plugins/" in url:
                    abs_url = urljoin(base_url, url)
                    plugin_urls.add(abs_url)
        
        # Also search in inline styles and scripts
        inline_pattern = r'["\']([^"\']*?/plugins/[^"\']*?)["\']'
        matches = re.findall(inline_pattern, html)
        for match in matches:
            abs_url = urljoin(base_url, match)
            plugin_urls.add(abs_url)
        
        return plugin_urls

    def _analyze_plugin(self, plugin_url, base_url):
        """
        Analyzes a plugin URL to extract plugin name and detect version.

        Args:
            plugin_url (str): URL containing plugin reference.
            base_url (str): Base URL of the website.
        """
        # Extract plugin name from URL
        # Pattern: /wp-content/plugins/plugin-name/...
        # or: /plugins/plugin-name/...
        plugin_match = re.search(r'/plugins/([^/]+)', plugin_url)
        
        if not plugin_match:
            return
        
        plugin_name = plugin_match.group(1)
        
        # Skip if already detected
        if plugin_name in self.detected_plugins:
            return
        
        if self.args.verbose:
            ptprint(f"Found plugin: {plugin_name}", "INFO", not self.args.json, indent=4, colortext=True)
        
        # Get plugin definition if available
        plugin_def = self._get_plugin_definition(plugin_name)
        
        # Try to detect version
        version = None
        
        # Method 1: Check if version is in the URL
        version_in_url = self._extract_version_from_url(plugin_url)
        if version_in_url:
            version = version_in_url
            if self.args.verbose:
                ptprint(f"Version found in URL: {version}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        # Method 2: Try to fetch readme.txt
        if not version:
            version_from_readme = self._get_version_from_readme(plugin_name, base_url, plugin_def)
            if version_from_readme:
                version = version_from_readme
                if self.args.verbose:
                    ptprint(f"Version found in readme.txt: {version}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
        
        # Determine display name and metadata
        display_name = plugin_name
        known_vuln = False
        priority = "medium"
        
        if plugin_def:
            display_name = plugin_def.get("display_name", plugin_name)
            known_vuln = plugin_def.get("known_vulnerabilities", False)
            priority = plugin_def.get("priority", "medium")
        
        # Store plugin information
        self.detected_plugins[plugin_name] = {
            "name": plugin_name,
            "display_name": display_name,
            "version": version,
            "url": plugin_url,
            "known_vulnerabilities": known_vuln,
            "priority": priority
        }

    def _get_plugin_definition(self, plugin_name):
        """
        Retrieves plugin definition from loaded definitions.

        Args:
            plugin_name (str): Name of the plugin.

        Returns:
            dict or None: Plugin definition if found, otherwise None.
        """
        for plugin_def in self.plugin_definitions:
            # Check if plugin name matches
            if plugin_def["name"] == plugin_name:
                return plugin_def
            
            # Check if plugin name matches any URL pattern
            url_patterns = plugin_def.get("url_patterns", [])
            if plugin_name in url_patterns:
                return plugin_def
        
        return None

    def _extract_version_from_url(self, url):
        """
        Attempts to extract version number from URL.

        Args:
            url (str): Plugin URL.

        Returns:
            str or None: Version string if found, otherwise None.
        """
        # Common version patterns in URLs:
        # - /plugin-name/1.2.3/
        # - /plugin-name.1.2.3.js
        # - /plugin-name-1.2.3/
        # - ?ver=1.2.3
        
        # Pattern for query parameter
        ver_param = re.search(r'[?&]ver=([0-9]+(?:\.[0-9]+)*)', url)
        if ver_param:
            return ver_param.group(1)
        
        # Pattern for version in path
        version_patterns = [
            r'/([0-9]+\.[0-9]+(?:\.[0-9]+)*?)/',
            r'\.([0-9]+\.[0-9]+(?:\.[0-9]+)*?)\.(?:js|css|min\.js|min\.css)',
            r'-([0-9]+\.[0-9]+(?:\.[0-9]+)*?)/',
            r'-([0-9]+\.[0-9]+(?:\.[0-9]+)*?)\.(?:js|css|min\.js|min\.css)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None

    def _get_version_from_readme(self, plugin_name, base_url, plugin_def=None):
        """
        Attempts to fetch and parse readme.txt file for version information.

        Args:
            plugin_name (str): Name of the plugin.
            base_url (str): Base URL of the website.
            plugin_def (dict): Plugin definition with custom readme paths.

        Returns:
            str or None: Version string if found, otherwise None.
        """
        # Construct common readme.txt paths
        readme_paths = []
        
        # Use custom paths from plugin definition if available
        if plugin_def and "readme_paths" in plugin_def:
            readme_paths.extend(plugin_def["readme_paths"])
        
        # Add default paths
        readme_paths.extend([
            f"/wp-content/plugins/{plugin_name}/readme.txt",
            f"/plugins/{plugin_name}/readme.txt",
            f"/wp-content/plugins/{plugin_name}/README.txt",
            f"/plugins/{plugin_name}/README.txt"
        ])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_paths = []
        for path in readme_paths:
            if path not in seen:
                seen.add(path)
                unique_paths.append(path)
        
        for path in unique_paths:
            readme_url = urljoin(base_url, path)
            
            if self.args.verbose:
                ptprint(f"Trying: {readme_url}", "INFO", not self.args.json, indent=8, colortext=True)
            
            resp = self.helpers.fetch(readme_url, allow_redirects=True)
            
            if resp and resp.status_code == 200:
                if self.args.verbose:
                    ptprint(f"Match: {readme_url}", "ADDITIONS", not self.args.json, indent=8, colortext=True)
                
                # Parse readme.txt content
                version = self._parse_readme_version(resp.text)
                if version:
                    return version
        
        return None

    def _parse_readme_version(self, readme_content):
        """
        Parses readme.txt content to extract version information.

        Args:
            readme_content (str): Content of readme.txt file.

        Returns:
            str or None: Version string if found, otherwise None.
        """
        # Common patterns in WordPress readme.txt files:
        # Stable tag: 1.2.3
        # Version: 1.2.3
        
        patterns = [
            r'Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)',
            r'version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)*)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, readme_content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _report(self):
        """
        Reports all detected plugins via ptjsonlib and prints output.
        """
        if self.detected_plugins:
            for plugin_name, plugin_info in self.detected_plugins.items():
                display_name = plugin_info.get("display_name", plugin_name)
                version = plugin_info.get("version")
                url = plugin_info.get("url")
                known_vuln = plugin_info.get("known_vulnerabilities", False)
                priority = plugin_info.get("priority", "medium")
                
                # Determine probability based on known vulnerabilities
                probability = 100 if known_vuln else 95
                
                # Store in result storage
                storage.add_to_storage(
                    technology=display_name,
                    technology_type="Plugin",
                    vulnerability="PTV-WEB-INFO-PLUGIN",
                    probability=probability,
                    version=version if version else None
                )
                
                # Print Match line if verbose
                if self.args.verbose:
                    ptprint(f"Match: {url}", "ADDITIONS", not self.args.json, indent=4, colortext=True)
                
                # Print detection
                if version:
                    ptprint(f"Identified plugin: {display_name} v{version}", "VULN", 
                           not self.args.json, indent=4, end=" ")
                else:
                    ptprint(f"Identified plugin: {display_name}", "VULN", 
                           not self.args.json, indent=4, end=" ")
                
                ptprint(f"({probability}%)", "ADDITIONS", not self.args.json, colortext=True)
        else:
            ptprint("It was not possible to identify any plugins", "INFO", 
                   not self.args.json, indent=4)


def run(args: object, ptjsonlib: object, helpers: object, http_client: object, responses: StoredResponses):
    """Entry point for running the PLUGINS detection."""
    PLUGINS(args, ptjsonlib, helpers, http_client, responses).run()