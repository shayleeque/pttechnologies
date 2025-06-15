from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from ptlibs.http.http_client import HttpClient

__TESTLABEL__ = "Test Apache detection via .ht access rule"


class WSHT:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self):
        """Main method"""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response1 = self.http_client.send_request(url=self.args.url + "/.hh", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)
        response2 = self.http_client.send_request(url=self.args.url + "/.ht", method="GET", headers=self.args.headers, allow_redirects=False, timeout=None)

        if response1.status_code != response2.status_code:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-WSHT")
            self.ptjsonlib.add_properties({"webServer": "webServerApache"})
            ptprint(f"It is possible to identify Apache web server by rule denies access to .ht files", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"It is not possible to identify the web server, but it does not seem to be Apache", "INFO", not self.args.json, indent=4)


def run(args, ptjsonlib):
    WSHT(args, ptjsonlib).run()