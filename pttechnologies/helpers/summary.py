import json
from helpers.result_storage import storage
from ptlibs.ptprinthelper import ptprint

class Summary:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib

    def run(self):
        if not storage.get_all_records():
            return