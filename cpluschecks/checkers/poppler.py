import os
import re
from checkers.base_checker import BaseChecker


class Poppler(BaseChecker):
    VENDOR = "poppler"
    PRODUCT = "poppler"
    LINK_SOURCE = "https://gitlab.freedesktop.org/poppler/poppler.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"\bPoppler\s+project\b",
    ]
    RX_VERSION = re.compile(
        r"^\s*Release\s+([0-9]+(?:\.[0-9]+){2})\s*:",
        re.MULTILINE,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "NEWS")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        if "poppler" not in (text or "").lower():
            return []
        m = self.RX_VERSION.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:NEWS",
                },
            )
        ]
