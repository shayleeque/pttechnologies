"""
Test Apache Web Server detection via differential access to .ht* files.

This module provides a test that attempts to detect an Apache web server by
sending HTTP requests to `.hh` and `.ht` paths on the target URL and comparing
their responses. Apache servers typically restrict access to `.ht*` files
using `.htaccess` rules, so differing response status codes can reveal
the presence of Apache.

Contains:
- WSHT class for performing the detection test.
- run() function as an entry point for running the test.

Usage:
    run(args, ptjsonlib)
"""

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from ptlibs.http.http_client import HttpClient

__TESTLABEL__ = "Test Apache detection via .ht access rule"

class WSHT:
    """
    Detects Apache Web Server using differential behavior of .ht* file access.

    This class attempts to identify an Apache web server by probing URLs that differ
    only in the presence of `.ht` (which is typically restricted by Apache's default `.htaccess` rules).
    A discrepancy in response codes may indicate Apache or a similar server using such rules.
    """

    def __init__(self, args, ptjsonlib):
        """
        Initializes the WSHT test.

        Args:
            args: Parsed arguments or configuration object, typically containing:
                  - url (str): Base target URL
                  - headers (dict): Optional HTTP headers
                  - json (bool): Whether output should be printed in JSON format
            ptjsonlib: Object used to record vulnerabilities and properties in JSON format.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self):
        """
        Executes the Apache detection test.

        Sends two HTTP GET requests to the server:
        - One with a non-restricted `.hh` path
        - One with a potentially restricted `.ht` path

        If the status codes differ, it is likely the server uses `.htaccess`-like rules,
        commonly associated with Apache. If Apache is detected, a vulnerability and a property
        indicating the server type are added to the JSON result.
        """

        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.http_client.send_request(url=self.args.url + "/.hh", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)
        response2 = self.http_client.send_request(url=self.args.url + "/.ht", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)

        if response1.status_code != response2.status_code:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-WSHT")
            self.ptjsonlib.add_properties({"webServer": "webServerApache"})
            ptprint(f"Identified WS: Apache Server", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"It is not possible to identify the web server, but it does not seem to be Apache", "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib):
    """
    Entry point to run the WSHT (Web Server .htaccess Test).

    Args:
        args: Parsed arguments passed to the module (e.g., from CLI).
        ptjsonlib: A shared object for recording structured JSON output.
    """
    WSHT(args, ptjsonlib).run()