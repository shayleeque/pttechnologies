"""
Helpers module for shared functionality used across tests.

Provides utility functions such as HTTP fetching and loading JSON definitions
from the 'definitions' directory. Acts as a central helper used by various
test modules.
"""

import json
import os
import socket
import ssl

from urllib.parse import urlparse

from ptlibs.http.http_client import HttpClient
from ptlibs.http.raw_http_client import RawHttpResponse
from ptlibs.ptprinthelper import ptprint

class Helpers:
    def __init__(self, args: object, ptjsonlib: object, http_client: object):
        """
        Helpers provides utility methods for loading definition files
        and making HTTP requests in a consistent way across modules.
        """
        self.args = args
        self.ptjsonlib = ptjsonlib
        self.http_client = http_client

    def load_definitions(self, filename: str) -> list:
        """
        Loads definitions from a JSON file in the 'definitions' directory.

        Args:
            filename (str): Name of the JSON file containing the definitions.
            caller_args (Namespace, optional): Used to suppress output formatting (e.g. --json).

        Returns:
            list | dict: Parsed JSON content as a list or dictionary, depending on file structure.
        """

        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, f"../definitions/{filename}")

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            ptprint(f"Error loading definitions: {e}", "ERROR", not self.args.json)
            return []

    def fetch(self, url, allow_redirects=False):
        """
        Sends an HTTP GET request to the specified URL.

        Args:
            url (str): URL to fetch.
            allow_redirects (bool, optional): Whether to follow redirects. Defaults to False.

        Returns:
            Response: The HTTP response object.
        """
        try:
            response = self.http_client.send_request(
                url=url,
                method="GET",
                headers=self.args.headers,
                allow_redirects=allow_redirects,
                timeout=self.args.timeout
            )
            return response

        except Exception as e:
            return None

    def _get_bad_request_response(self, base_url: str) -> RawHttpResponse | None:
        """
        Attempt to induce a 400 Bad Request response by sending raw malformed requests.

        Tries several methods:
        - Request path "/%"
        - Request with "Host" header set to "%"
        - Request with a header missing colon

        Args:
            base_url: The base URL to target.

        Returns:
            RawHttpResponse object with status 400 if successful, else None.
        """
        base_url = base_url.rstrip("/")

        r = self._raw_request(base_url, "/%")
        if r and r.status == 400:
            return r

        r = self._raw_request(base_url, "/", extra_headers={"Host": "%"})
        if r and r.status == 400:
            return r

        r = self._raw_request(base_url, "/", extra_headers={"BadHeaderWithoutColon": ""})
        if r and r.status == 400:
            return r

        return None

    def _raw_request(self, base_url: str, path: str, extra_headers: dict[str, str] | None = None, custom_request_line: str | None = None) -> RawHttpResponse | None:
        """
        Send a raw HTTP GET request to the given URL with optional extra headers.

        Merges default headers with extra_headers, extra_headers take precedence.

        Returns RawHttpResponse on success, or None on failure (e.g., timeout, SSL error).
        """
        url = base_url.rstrip("/") + path

        # Merge self.args.headers with extra_headers, extra_headers take precedence
        final_headers = dict(getattr(self.args, "headers", {}) or {})
        if extra_headers:
            final_headers.update(extra_headers)
        try:
            response = self.http_client.send_raw_request(
                url=url,
                method="GET",
                headers=final_headers,
                timeout=getattr(self.args, 'timeout', 10),
                proxies=getattr(self.args, 'proxy', None),
                custom_request_line=custom_request_line
            )
            return response
        except (socket.timeout, ssl.SSLError, OSError) as e:
            return None

    def send_raw_malformed(self, base_url: str, method="GET", protocol="HTTP", version="1.1",
                        custom_headers=None, timeout=3):
        """
        Send malformed HTTP request using raw sockets with configurable parameters.
        
        Args:
            base_url (str): Base URL to target
            method (str): HTTP method (GET, POST, FOO, etc.) - default "GET"
            protocol (str): Protocol name (HTTP, FOO, etc.) - default "HTTP" 
            version (str): Protocol version (1.1, 9.8, etc.) - default "1.1"
            custom_headers (dict): Additional headers to include
            timeout (int): Socket timeout in seconds
            
        Returns:
            Response-like object or None
            
        Examples:
            # Invalid protocol: GET / FOO/1.1
            send_raw_malformed(url, protocol="FOO")
            
            # Invalid version: GET / HTTP/9.8  
            send_raw_malformed(url, version="9.8")
            
            # Invalid method: FOO / HTTP/1.1
            send_raw_malformed(url, method="FOO")
        """
                
        try:
            parsed_url = urlparse(base_url)
            host = parsed_url.hostname or 'localhost'
            port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
            
            request_line = f"{method} / {protocol}/{version}\r\n"
            headers_text = f"Host: {host}\r\n"
            
            if custom_headers:
                for header_name, header_value in custom_headers.items():
                    headers_text += f"{header_name}: {header_value}\r\n"
            
            raw_request = request_line + headers_text + "\r\n"
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            sock.send(raw_request.encode('utf-8'))
            
            response_data = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk
                    if len(response_data) > 20000:
                        break
                except socket.timeout:
                    break
            
            sock.close()
            
            response_text = response_data.decode('utf-8', errors='ignore')
            
            status_code = 0
            if response_text:
                lines = response_text.split('\n')
                if lines and 'HTTP/' in lines[0]:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        try:
                            status_code = int(parts[1])
                        except ValueError:
                            pass
            
            class MalformedResponse:
                def __init__(self, text, status_code, url):
                    self.text = text
                    self.body = text
                    self.status_code = status_code
                    self.status = status_code
                    self.url = url
            
            return MalformedResponse(response_text, status_code, base_url)
            
        except Exception as e:
            if self.args.verbose:
                ptprint(f"Raw malformed request failed: {str(e)}", "INFO", not self.args.json, indent=8)
            return None