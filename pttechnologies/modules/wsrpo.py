"""
WSRPO - Web-Server Response Position-Order Detection Module

This module implements a test that identifies the web server technology
by analyzing the order of HTTP response headers in a 400 Bad Request response.

Includes:
- WSRPO class to perform the response-header order detection.
- run() function as an entry point to execute the test.

Usage:
    run(args, ptjsonlib, helpers, http_client, resp_hp, resp_404)
"""
import socket
import ssl

from http.client import HTTPConnection, HTTPResponse, HTTPSConnection
from typing import List, Tuple, Any
from urllib.parse import urlparse
from ptlibs.ptprinthelper import ptprint

__TESTLABEL__ = "Test response-header order"
WANTED = {b"server", b"date", b"content-type", b"content-length"}


class WSRPO:
    """
    Class to detect web server technology by analyzing the order
    of response headers returned in a 400 Bad Request HTTP response.

    The detection is based on predefined header order definitions loaded
    from a JSON file. It sends specially crafted HTTP requests to induce
    a 400 error and extracts the order of selected headers for matching.
    """

    def __init__(self, args: object, ptjsonlib: object, helpers: object,
                 http_client: object, resp_hp: object, resp_404: object) -> None:
        """
        Initialize the WSRPO test with necessary components.

        Args:
            args: Command-line or runtime arguments containing URL, verbosity, etc.
            ptjsonlib: JSON library instance for adding vulnerabilities/properties.
            helpers: Helper utilities (e.g., for loading definitions).
            http_client: HTTP client instance to perform requests.
            resp_hp: Placeholder for HTTP response helper (unused here).
            resp_404: Placeholder for 404 response handling (unused here).
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.helpers = helpers
        self.http_client = http_client
        self.response_hp = resp_hp
        self.response_404 = resp_404
        self.definitions = self.helpers.load_definitions("wsrpo.json")

    def run(self) -> None:
        """
        Execute the response header order detection test.

        Sends HTTP requests designed to trigger 400 Bad Request responses,
        then analyzes the order of certain HTTP headers in the response.
        If a known header order is matched, it identifies the web server.

        Prints test progress and results depending on verbosity and output mode.
        """
        ptprint(__TESTLABEL__, "TITLE", not self.args.json, colortext=True)

        response = self._get_bad_request_response(self.args.url)
        if response is None:
            ptprint("Could not induce 400 Bad Request", "INFO", not self.args.json,indent=4)
            return

        raw_headers = self._read_raw_headers(response)
        order = self._extract_order(raw_headers)
        technology = self._match_order(order)

        if getattr(self.args, "verbose", False) and raw_headers:
            self._print_verbose(raw_headers)

        if technology:
            self._report(technology)
        else:
            ptprint("Web-server could not be identified by header order", "INFO", not self.args.json,indent=4)

    def _raw_request(self, base_url: str, path: str, extra_headers: dict[str, str] | None = None) -> HTTPResponse | None:
        """
        Perform a low-level HTTP GET request to a given URL and path with optional headers.

        Args:
            base_url: The base URL including scheme and hostname.
            path: The URL path to request.
            extra_headers: Optional dictionary of additional HTTP headers to send.

        Returns:
            HTTPResponse object on success, or None on failure (e.g., timeout, SSL error).
        """
        p = urlparse(base_url)
        is_https = p.scheme == "https"
        port = p.port or (443 if is_https else 80)

        conn_cls = HTTPSConnection if is_https else HTTPConnection
        kw: dict[str, Any] = {}
        if is_https:
            kw["context"] = ssl._create_unverified_context()

        conn = conn_cls(p.hostname, port, timeout=self.args.timeout, **kw)
        try:
            conn.putrequest("GET", path)

            host_hdr = p.hostname if p.port in (None, 80, 443) else f"{p.hostname}:{p.port}"
            conn.putheader("Host", host_hdr)

            if extra_headers:
                for k, v in extra_headers.items():
                    conn.putheader(k, v)
            conn.endheaders()
            return conn.getresponse()
        except (ssl.SSLError, socket.timeout, OSError):
            return None
        finally:
            conn.close()


    def _get_bad_request_response(self, base_url: str) -> HTTPResponse | None:
        """
        Attempt to induce a 400 Bad Request response by sending malformed requests.

        Tries several methods:
        - Request path "/%"
        - Request with "Host" header set to "%"
        - Request with a header missing colon

        Args:
            base_url: The base URL to target.

        Returns:
            HTTPResponse object with status 400 if successful, else None.
        """
        base_url = base_url.rstrip("/")

        r = self._raw_request(base_url, "/%")
        if r and r.code == 400:
            return r

        r = self._raw_request(base_url, "/", extra_headers={"Host": "%"})
        if r and r.code == 400:
            return r

        r = self._raw_request(base_url, "/",
                            extra_headers={"BadHeaderWithoutColon": ""})
        if r and r.code == 400:
            return r

        return None

    @staticmethod
    def _read_raw_headers(resp: HTTPResponse) -> List[Tuple[bytes, bytes]]:
        """
        Extract raw response headers from an HTTPResponse object.

        Args:
            resp: HTTPResponse object.

        Returns:
            List of tuples (header_name_bytes, header_value_bytes).
        """
        if hasattr(resp.msg, "raw_headers"):
            return list(resp.msg.raw_headers)
        return [(k.encode(), v.encode()) for k, v in resp.msg.items()]

    @staticmethod
    def _extract_order(raw: List[Tuple[bytes, bytes]]) -> List[str]:
        """
        Extract the order of wanted headers from raw headers list.

        Args:
            raw: List of (header_name_bytes, header_value_bytes).

        Returns:
            List of header names (strings) in lowercase and in order, filtered by WANTED set.
        """
        return [n.lower().decode() for n, _ in raw if n.lower() in WANTED]

    def _match_order(self, order: List[str] | None) -> str | None:
        """
        Match observed header order against known definitions.

        Allows the 'server' header to be missing. All other headers in the definition
        must be present and in correct order.

        Args:
            order: List of observed header names (lowercase strings).

        Returns:
            Name of matched web server technology, or None if no match.
        """
        if not order:
            return None

        for d in self.definitions:
            ref = d.get("order", [])

            required_headers = [h for h in ref if h != "server"]
            optional_headers = ["server"] if "server" in ref else []

            if not all(h in order for h in required_headers):
                continue

            order_filtered = [h for h in order if h in required_headers or h in optional_headers]

            expected_sequence = [h for h in ref if h in order_filtered]

            if order_filtered == expected_sequence:
                return d.get("technology")
        return None

    def _print_verbose(self, raw: List[Tuple[bytes, bytes]]):
        """
        Print detailed raw headers for verbose output.

        Args:
            raw: List of (header_name_bytes, header_value_bytes).
        """
        ptprint("Server responses:", "INFO", True, indent=4)
        for n, v in raw:
            ptprint(f"{n.decode(errors='replace')}: "
                    f"{v.decode(errors='replace')}", "TEXT", True, indent=10)

    def _report(self, tech: str):
        """
        Report the identified web server technology and record it.

        Args:
            tech: The identified technology string.
        """
        if tech:
            self.ptjsonlib.add_vulnerability("PTV-WEB-INFO-WSRPO")
            key = f"webServer{tech}"
            self.ptjsonlib.add_properties({"webServer": key})
            ptprint(f"Identified WS: {tech}", "VULN", not self.args.json, indent=4)

def run(args, ptjsonlib, helpers, http_client, resp_hp, resp_404):
    """Entry point to run the WSRPO test."""
    WSRPO(args, ptjsonlib, helpers, http_client, resp_hp, resp_404).run()