from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient

__TESTLABEL__ = "Test OS detection via Case Sensitivity"

class OSCS:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)


    def run(self):
        """Main method"""
        #ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        pass


def run(args, ptjsonlib):
    OSCS(args, ptjsonlib).run()