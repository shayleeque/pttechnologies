from ptlibs import ptjsonlib
from ptlibs.ptprinthelper import ptprint
from ptlibs.http.http_client import HttpClient

from urllib.parse import urlparse, urlunparse, urljoin
import os
import re

__TESTLABEL__ = "Test OS detection via Case Sensitivity"


class OSCS:
    def __init__(self, args, ptjsonlib):
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)

    def run(self):
        """
        Execute the OS detection test using case sensitivity of static resources.

        1) Locate a static resource (favicon or first referenced asset).
        2) Compare responses for lowercase and uppercase resource URLs.
        3) Report whether the server is case-insensitive (Windows) or case-sensitive (Unix/Linux).
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)
        resource_url = self._find_static_resource()
        if not resource_url:
            ptprint("No static source found for test", "ERROR", not self.args.json, indent=4)
            return

        lower_resp, ct_lower = self._fetch(resource_url)
        upper_url      = self._make_mixed_url(resource_url)
        upper_resp, ct_upper = self._fetch(upper_url)

        self._report(lower_resp, ct_lower, upper_resp, ct_upper)

    def _find_static_resource(self):
        """
        Locate a static resource to test:
        1) Try '/favicon.ico'.
        2) If not found, download the homepage HTML and search for the first
           reference to a static asset (.js, .css, .png, .jpg, .jpeg, .gif, .ico).

        Returns:
            str: Full URL of the located resource, or None if none found.
        """
        base = self.args.url.rstrip('/')
        parsed_base = urlparse(base)

        favicon = base + '/favicon.ico'
        resp, _ = self._fetch(favicon, allow_redirects=True)
        if resp.status_code == 200:
            return favicon
        resp_home, _ = self._fetch(base + '/', allow_redirects=True)
        html = getattr(resp_home, 'text', '') or ''
        match = re.search(
            r'(?:href|src)=["\']([^"\']+\.(?:js|css|png|jpg|jpeg|gif|ico))["\']', 
            html, re.IGNORECASE
        )
        if not match:
            return None

        candidate = match.group(1)

        full_url = urljoin(base + '/', candidate)
        parsed_cand = urlparse(full_url)
        if parsed_cand.netloc != parsed_base.netloc:
            return None

        path = parsed_cand.path if parsed_cand.path.startswith('/') else '/' + parsed_cand.path
        return parsed_base.scheme + '://' + parsed_base.netloc + path

    def _fetch(self, url, allow_redirects=True):
        """
        Send a GET request to the specified URL and return the response and its content type.

        Args:
            url (str): The URL to request.
            allow_redirects (bool): Whether to follow HTTP redirects.

        Returns:
            tuple: (response object, content type string).
        """
        resp = self.http_client.send_request(
            url=url, 
            method="GET",
            headers=self.args.headers,
            allow_redirects=allow_redirects,
            timeout=None
        )
        return resp, resp.headers.get('Content-Type', '')

    def _make_mixed_url(self, resource_url):
        """
        Generate a variant of the resource URL with the filename portion converted to uppercase,
        preserving the rest of the path, query, and fragment.

        Args:
            resource_url (str): Original resource URL.

        Returns:
            str: Modified URL with uppercase filename.
        """
        parsed = urlparse(resource_url)
        dirname, filename = os.path.split(parsed.path)
        upper = filename.upper()
        new_path = new_path = dirname + '/' + filename.upper()
        return urlunparse(parsed._replace(path=new_path))

    def _report(self, r1, ct1, r2, ct2):
        """
        Compare the lowercase and uppercase responses and report the OS type.

        If both status code and content type match, the server is case-insensitive (Windows).
        Otherwise, it is case-sensitive (Unix/Linux).

        This method also records the vulnerability code and OS property in the JSON.
        """
        self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-OSSEN")

        if r1.status_code == r2.status_code and ct1 == ct2:
            self.ptjsonlib.add_properties({"os": "osWindows"})
            ptprint("Identified OS: Windows", "VULN", not self.args.json, indent = 4)
        else:
            self.ptjsonlib.add_properties({"os": "osUnix"})
            ptprint("Identified OS: Unix / Linux", "VULN", not self.args.json, indent = 4)


def run(args, ptjsonlib):
    OSCS(args, ptjsonlib).run()