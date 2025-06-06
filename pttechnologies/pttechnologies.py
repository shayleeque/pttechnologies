#!/usr/bin/python3
"""
    Copyright (c) 2025 Penterep Security s.r.o.

    pttechnologies

    pttechnologies is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    pttechnologies is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with pttechnologies.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import importlib
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from contextlib import redirect_stdout, redirect_stderr
from threading import Lock
from io import StringIO
from urllib.parse import urlparse, urlunparse

import requests

from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print
from ptlibs.threads import ptthreads, printlock

from _version import __version__

class PtTechnologies:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.ptthreads   = ptthreads.PtThreads()
        self.args        = args
        self._lock       = Lock()

    def run(self) -> None:
        """Main method"""
        tests = self.args.tests or get_available_modules()
        print(tests)

        # Run each test (module) in a separated thread
        self.ptthreads.threads(tests, self.run_single_module, self.args.threads)

        # Output via JSON
        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)


    def run_single_module(self, module_name):
        module_path = os.path.join(os.path.dirname(__file__), "modules", f"{module_name}.py")
        try:
            module = self.import_module_from_path(module_name, module_path)
            if hasattr(module, "run") and callable(module.run):

                # Redirect output to buffer
                buffer = StringIO()
                with redirect_stdout(buffer), redirect_stderr(buffer):
                    module.run(args=self.args, ptjsonlib=self.ptjsonlib)

                # Print buffered output with lock
                with self._lock:
                    print(buffer.getvalue(), end='\n')

            else:
                ptprint(f"Module '{module_name}' does not have 'run' function", "WARNING", not self.args.json)
        except FileNotFoundError as e:
            ptprint(f"Module '{module_name}' not found", "ERROR", not self.args.json)
        except Exception as e:
            ptprint(f"Error running module '{module_name}': {e}", "ERROR", not self.args.json)


    def import_module_from_path(self, module_name, file_path):
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None:
            raise ImportError(f"Cannot find spec for {module_name} at {file_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module


def get_help():
    return [
        {"description": ["Penterep template script"]},
        {"usage": ["pttechnologies <options>"]},
        {"usage_example": [
            "pttechnologies -u https://www.example.com",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-ts", "--tests",                  "<test>",     "Specify one or more tests to perform:"],
            *get_available_modules_help(),
            ["", "", "", ""],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "<miliseconds>",    "Set timeout (default 10)"],
            ["-t",  "--threads",                "<threads>",        "Set thread count (default 10)"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-a",  "--user-agent",             "<a>",              "Set User-Agent header"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-r",  "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",  "--cache",                  "",                 "Cache HTTP communication (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]



def get_available_modules_help():
    """Build and return help rows"""
    rows = []
    available_modules = get_available_modules()
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")

    for module in available_modules:
        module_path = os.path.join(modules_folder, f"{module}.py")
        spec = importlib.util.spec_from_file_location(module, module_path)
        mod = importlib.util.module_from_spec(spec)

        try:
            spec.loader.exec_module(mod)
            label = getattr(mod, "__TESTLABEL__", f"Test for {module.upper()}")
        except Exception as e:
            label = f"Test for {module.upper()}"

        row = ["", "", f" {module.upper()}", label]
        rows.append(row)

    return sorted(rows, key=lambda x: x[2])

def get_available_modules():
    """Returns list of available modules"""
    modules_folder = os.path.join(os.path.dirname(__file__), "modules")
    available_modules = [
        f.rsplit(".py")[0].split()[0] for f in sorted(os.listdir(modules_folder))
        if (
            os.path.join(modules_folder, f) and
            not f.startswith("_") and
            f.endswith(".py")
        )
    ]
    return available_modules

def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-ts",  "--tests",         type=str, nargs="+") # TODO: If not set any test ALL
    parser.add_argument("-p",  "--proxy",          type=str)
    parser.add_argument("-T",  "--timeout",        type=int, default=10)
    parser.add_argument("-t",  "--threads",        type=int, default=10)
    parser.add_argument("-a",  "--user-agent",     type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",         type=str)
    parser.add_argument("-H",  "--headers",        type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",      action="store_true")
    parser.add_argument("-C",  "--cache",          action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)


    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()

    args.headers = ptnethelper.get_request_headers(args)
    if args.proxy:
        args.proxy = {"http": args.proxy, "https": args.proxy}

    args.url = strip_url_path(args.url)

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args

def strip_url_path(url):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, '', '', '', ''))

def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]

    requests.packages.urllib3.disable_warnings()
    args = parse_args()
    script = PtTechnologies(args)
    script.run()


if __name__ == "__main__":
    main()
