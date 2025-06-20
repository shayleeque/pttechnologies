from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint

from ptlibs.http.http_client import HttpClient

from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

import json
import os

__TESTLABEL__ = "Test programming language detection via file extensions"


class PLLNG:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, "../definitions/pllng.json")
        self.extensions = self._load_extensions_from_json(json_path)

    def run(self):
        """Main method"""
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        base_url = self.args.url.rstrip("/")
        resp, _ = self._fetch(base_url, allow_redirects=True)
        html = resp.text
        result = self._find_language_by_link(html, base_url)

        if not result:
            result = self._dictionary_attack(base_url)
        
        self._report(result)

    def _load_extensions_from_json(self, filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            ptprint(f"Error loading definitions: {e}", "ERROR", not self.args.json)
            return []
    
    def _fetch(self, url, allow_redirects=True):
        resp = self.http_client.send_request(
            url=url,
            method="GET",
            headers=self.args.headers,
            allow_redirects=allow_redirects,
            timeout=None
        )
        return resp, resp.headers.get("Content-Type", "")

    def _find_language_by_link(self, html, base_url):
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
        if result:
            language = result["technology"]
            ext = result["extension"].capitalize()
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-LNGEX")
            self.ptjsonlib.add_properties({"webProgrammingLanguage": f"webProgrammingLanguage{ext}"})
            ptprint(f"Programming language detected: {language}", "VULN", not self.args.json, indent=4)
        else:
            ptprint(f"It was not possible to identify the programming language", "VULN", not self.args.json, indent=4)


def run(args, ptjsonlib):
    PLLNG(args, ptjsonlib).run()