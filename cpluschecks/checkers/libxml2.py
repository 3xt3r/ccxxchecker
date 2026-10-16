import os
import re
from checkers.base_checker import BaseChecker


class Libxml2(BaseChecker):
    VENDOR = "xmlsoft"
    PRODUCT = "libxml2"
    LINK_SOURCE = "https://github.com/GNOME/libxml2.git"
    CONTAINS_PATTERNS = [
        r"libxml\.h:\s*internal header only used during the compilation of libxml",
    ]
    RX_VERSION = re.compile(
        r"^\s*([0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)\s*$",
        re.MULTILINE,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "VERSION")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        m = self.RX_VERSION.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:VERSION",
                },
            )
        ]
