"""
PLLNG - Programming Language Detection Module

This module implements detection of web programming languages
based on file extensions found in linked resources or
by checking common filenames on the target web server.

It uses HTTP requests and HTML parsing to infer the backend
language and reports findings via ptjsonlib.

Classes:
    PLLNG: Main detector class.

Functions:
    run: Entry point to execute the detection.
"""

import json
import os
from urllib.parse import urlparse, urljoin

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.http.http_client import HttpClient
from ptlibs.ptprinthelper import ptprint

from bs4 import BeautifulSoup

__TESTLABEL__ = "Test programming language detection via file extensions"


class PLLNG:
    """
    PLLNG performs language detection or processing tasks related to language.

    This class is responsible for detecting or handling language-specific logic
    within the application. It may interact with text data, perform analysis,
    or manage language resources.

    Attributes:
        args: Input arguments or configuration.
        ptjsonlib: JSON utility library for logging results or vulnerabilities.
    """

    def __init__(self, args, ptjsonlib):
        """
        Initializes the PLLNG detector.

        Args:
            args (Namespace): Command-line arguments including URL and headers.
            ptjsonlib (object): JSON helper for reporting vulnerabilities and properties.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, "../definitions/pllng.json")
        self.extensions = self._load_extensions_from_json(json_path)

    def run(self):
        """
        Runs the programming language detection process.

        Fetches the base URL, tries to detect programming language by examining
        linked resources or by dictionary attack, then reports the result.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        resp, _ = self._fetch(base_url, allow_redirects=True)
        html = resp.text
        result = self._find_language_by_link(html, base_url)

        if not result:
            result = self._dictionary_attack(base_url)

        self._report(result)

    def _load_extensions_from_json(self, filename):
        """
        Loads programming language extensions and metadata from JSON file.

        Args:
            filename (str): Path to the JSON file with extension definitions.

        Returns:
            list: List of dictionaries containing extension info.
        """
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            ptprint(f"Error loading definitions: {e}", "ERROR", not self.args.json)
            return []

    def _fetch(self, url, allow_redirects=True):
        """
        Sends an HTTP GET request to the specified URL.

        Args:
            url (str): URL to fetch.
            allow_redirects (bool, optional): Whether to follow redirects. Defaults to True.

        Returns:
            tuple: Response object and Content-Type header string.
        """
        resp = self.http_client.send_request(
            url=url,
            method="GET",
            headers=self.args.headers,
            allow_redirects=allow_redirects,
            timeout=None
        )
        return resp, resp.headers.get("Content-Type", "")

    def _find_language_by_link(self, html, base_url):
        """
        Parses HTML to detect programming language by examining resource URLs.

        Args:
            html (str): HTML content of the base URL.
            base_url (str): Base URL for resolving relative links.

        Returns:
            dict or None: Extension metadata if detected, otherwise None.
        """
        soup = BeautifulSoup(html, "html.parser")
        netloc = urlparse(base_url).netloc

        tag_attrs = [
            ("a", "href"),
            ("link", "href"),
            ("script", "src"),
            ("img", "src"),
            ("form", "action")
        ]

        for tag, attr in tag_attrs:
            for element in soup.find_all(tag):
                url = element.get(attr)
                if not url:
                    continue
                abs_url = urljoin(base_url, url)
                parsed = urlparse(abs_url)

                if parsed.netloc == "" or parsed.netloc == netloc:
                    for ext_entry in self.extensions:
                        ext = ext_entry["extension"]
                        if abs_url.lower().endswith(f".{ext}"):
                            return ext_entry
        return None

    def _dictionary_attack(self, base_url):
        """
        Attempts to detect programming language by checking common filenames with known extensions.

        Args:
            base_url (str): Base URL to test.

        Returns:
            dict or None: Extension metadata if a matching file is found, otherwise None.
        """
        candidates = ["index", "default"]
        for name in candidates:
            for ext_entry in self.extensions:
                ext = ext_entry["extension"]
                test_url = f"{base_url}/{name}.{ext}"
                resp, _ = self._fetch(test_url, allow_redirects=True)
                if resp.status_code == 200:
                    return ext_entry
        return None

    def _report(self, result):
        """
        Reports the detected programming language via ptjsonlib and prints output.

        Args:
            result (dict or None): Detected extension metadata or None if detection failed.
        """
        if result:
            language = result["technology"]
            ext = result["extension"].capitalize()
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-LNGEX")
            self.ptjsonlib.add_properties({"webProgrammingLanguage": f"webProgrammingLanguage{ext}"})
            ptprint(f"Programming language detected: {language}", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"It was not possible to identify the programming language", "VULN", not self.args.json, indent=4)


def run(args, ptjsonlib):
    """
    Entry point for running the PLLNG detection.

    Args:
        args (Namespace): Command-line arguments.
        ptjsonlib (object): JSON helper for reporting.
    """
    PLLNG(args, ptjsonlib).run()