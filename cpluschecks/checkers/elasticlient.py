import os
import re
from checkers.base_checker import BaseChecker


class Elasticlient(BaseChecker):
    VENDOR = "seznam"
    PRODUCT = "elasticclient"
    LINK_SOURCE = "https://github.com/seznam/elasticlient.git"
    CONTAINS_PATTERNS = [
        r"Implementation of the theElasticsearch Client",
        r"Elasticsearch Client implementation",
    ]
    RX_CMAKE_PROJECT = re.compile(
        r"project\s*\(\s*elasticlient[^)]*VERSION\s+([0-9]+(?:\.[0-9]+){1,3})",
        re.IGNORECASE | re.DOTALL,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        m = self.RX_CMAKE_PROJECT.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
