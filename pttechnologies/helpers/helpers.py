"""
Helpers module for shared functionality used across tests.

Provides utility functions such as HTTP fetching and loading JSON definitions
from the 'definitions' directory. Acts as a central helper used by various
test modules.
"""

import json
import os

from ptlibs.http.http_client import HttpClient
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