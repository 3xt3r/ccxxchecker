import os
import re
from checkers.base_checker import BaseChecker


class Ragel(BaseChecker):
    VENDOR = "ragel"
    PRODUCT = "ragel"
    LINK_SOURCE = "https://github.com/adrian-thurston/ragel.git"
    CONTAINS_PATTERNS = [
        r"Copyright\s+\d{4}(?:-\d{4})?\s+Adrian Thurston\s+<thurston@colm\.net>",
    ]
    RX_VERSION = re.compile(
        r"AC_INIT\s*\(\s*ragel\s*,\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*\)",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        m = self.RX_VERSION.search(text or "")
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "configure.ac")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_version(text)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:configure.ac",
                },
            )
        ]
