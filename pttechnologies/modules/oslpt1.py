"""
OSLPT1 - Operating System Detection via LPT1 Path

This module implements a simple OS detection technique based on the response
differences for requests to /LPP1 and /LPT1 paths. If the HTTP status codes
differ, it assumes the target OS is Windows, otherwise Unix/Linux.

Classes:
    OSLPT1: Main class performing the detection.

Functions:
    run: Entry point to execute the detection.
"""

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from ptlibs.http.http_client import HttpClient

__TESTLABEL__ = "Test OS detection via LPT1 path"


class OSLPT1:
    def __init__(self, args, ptjsonlib):
        """
        Initializes the OSLPT1 OS detector.

        Args:
            args (Namespace): Command-line arguments including URL and headers.
            ptjsonlib (object): JSON helper for reporting vulnerabilities and properties.
        """

        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self):
        """
        Executes the OS detection by comparing HTTP responses to /LPP1 and /LPT1.

        If the status codes differ, assumes Windows OS; otherwise Unix/Linux.
        Reports the result using ptjsonlib and prints output.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.http_client.send_request(url=self.args.url + "/LPP1", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)
        response2 = self.http_client.send_request(url=self.args.url + "/LPT1", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)

        if response1.status_code != response2.status_code:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSLNK")
            self.ptjsonlib.add_properties({"os": "osWindows"})
            ptprint(f"OS detected: Windows", "VULN", not self.args.json, indent=4)
        else:
            self.ptjsonlib.add_properties({"os": "osUnix"})
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSLNK")
            ptprint(f"OS detected: Unix / Linux", "VULN", not self.args.json, indent=4)


def run(args, ptjsonlib):
    """
    Entry point for running the OSLPT1 OS detection.

    Args:
        args (Namespace): Command-line arguments.
        ptjsonlib (object): JSON helper for reporting.
    """
    OSLPT1(args, ptjsonlib).run()

