from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from ptlibs.http.http_client import HttpClient

__TESTLABEL__ = "Test OS detection via LPT1 path"


class OSLPT1:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self):
        """Main method"""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.http_client.send_request(url=self.args.url + "/LPP1", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)
        response2 = self.http_client.send_request(url=self.args.url + "/LPT1", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)

        if response1.status_code != response2.status_code:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSLNK")
            self.ptjsonlib.add_properties({"os": "osWindows"})
            ptprint(f"OS detected: Windows", "VULN", not self.args.json, indent=0)
        else:
            self.ptjsonlib.add_properties({"os": "osUnix"})
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSLNK")
            ptprint(f"OS detected: Unix / linux", "VULN", not self.args.json, indent=4)


def run(args, ptjsonlib):
    OSLPT1(args, ptjsonlib).run()

