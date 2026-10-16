import os
import re
from checkers.base_checker import BaseChecker


class Libxcb(BaseChecker):
    VENDOR = "x"
    PRODUCT = "libxcb"
    LINK_SOURCE = "https://github.com/iplinux/libxcb"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"xcb_connection_t\s*\*\s*xcb_connect\b",
        r"XCB_CONN_CLOSED_\w+\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
    ]
    RX_VERSION = re.compile(
        r"AC_INIT\s*\(\s*\[libxcb\]\s*,\s*([0-9]+(?:\.[0-9]+){1,3})\s*\)",
        re.IGNORECASE,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "configure.ac")
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
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:configure.ac",
                },
            )
        ]
