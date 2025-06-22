"""
Test web server identification via URL length behavior.

This module implements a test that probes how a web server responds to
HTTP requests with varying URL lengths. By analyzing the pattern of
HTTP status codes returned for different URL lengths, it attempts to
identify the underlying web server technology based on predefined
response signatures loaded from a JSON definitions file.

Includes:
- WSURLLEN class to perform the URL length behavior test.
- run() function as an entry point to execute the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient

import json
import os

__TESTLABEL__ = "Test URL length behavior to identify web server"


class WSURLLEN:
    """
    Class to test how a web server reacts to various URL lengths and
    identify the web server technology based on response patterns.
    """

    def __init__(self, args, ptjsonlib):
        """
        Initialize WSURLLEN test instance.

        Args:
            args: Parsed command-line arguments.
            ptjsonlib: JSON interface for recording results.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.lengths = [1000, 5000, 6000, 7000, 8000, 9000, 10000, 15000, 20000]
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, "../definitions/wsurllen.json")
        self.definitions = self._load_definitions(json_path)

    def run(self) -> None:
        """
        Executes the URL length test for the current context.

        This method performs the URL length analysis based on the configured inputs
        (e.g., collected requests or target domain). It processes the data, evaluates
        the results (e.g., detecting anomalies or violations), and then either prints
        the results to the console, stores them for further processing, or both.

        Intended to be the main entry point for executing the URL length test logic.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        statuses = []

        blocked_long_url = False
        for l in self.lengths:
            path = "/" + ("a" * l)
            full_url = base_url + path
            status = self._fetch_status(full_url)
            statuses.append(status if status is not None else "None")
            if status is None:
                blocked_long_url = True

        if self.args.verbose:
            ptprint("Server responses:", "INFO", not self.args.json,indent=4)
            for l, s in zip(self.lengths, statuses):
                ptprint(f"  {l} chars [{s}]", "INFO", not self.args.json,indent=4)

        if blocked_long_url:
            ptprint("Long URL are blocked", "INFO", not self.args.json,indent=4)

        server = self._identify_server(statuses)
        if server:
            ptprint(f"Identified WS: {server}", "VULN", not self.args.json, indent=4)
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-WSURL")
            self.ptjsonlib.add_properties({"webServer": f"webServer[{server}]"})
        else:
            ptprint("No matching web server identified from URL length behavior.", "INFO", not self.args.json, indent=4)

    def _fetch_status(self, url) -> None:
        """
        Send a GET request to the specified URL and return the HTTP status code.

        Args:
            url: Full URL to request.

        Returns:
            HTTP status code as string, or None if request failed.
        """
        try:
            response = self.http_client.send_request(
                url=url,
                method="GET",
                headers=self.args.headers,
                allow_redirects=False,
                timeout=10
            )
            return str(response.status_code)
        except Exception:
            return None

    def _load_definitions(self, path):
        """
        Load server signature definitions from a JSON file.

        Args:
            path: Path to the definitions JSON.

        Returns:
            List of server signature dictionaries.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            ptprint(f"Error loading definitions: {e}", "ERROR", not self.args.json)
            return []

    def _identify_server(self, observed_statuses):
        """
        Match observed response pattern against known server definitions.

        Args:
            observed_statuses: List of HTTP status codes for each tested URL length.

        Returns:
            Detected server name if match is found, otherwise None.
        """
        for entry in self.definitions:
            if entry.get("statuses") == observed_statuses:
                return entry.get("technology")
        return None


def run(args, ptjsonlib):
    """
    Entry point to run the WSURLLEN test.

    Args:
        args: Parsed CLI arguments.
        ptjsonlib: JSON interface to store results.
    """
    WSURLLEN(args, ptjsonlib).run()