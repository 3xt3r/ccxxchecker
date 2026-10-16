import os
import re
from checkers.base_checker import BaseChecker


class Libuv(BaseChecker):
    VENDOR = "libuv"
    PRODUCT = "libuv"
    LINK_SOURCE = "https://github.com/libuv/libuv"
    CONTAINS_PATTERNS = [
        r"Copyright Joyent, Inc\. and other Node contributors",
    ]
    RX_MAJOR = re.compile(r"#define\s+UV_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+UV_VERSION_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+UV_VERSION_PATCH\s+(\d+)")

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        if a and b and c:
            return f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        return None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "include", "uv", "version.h")
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
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:include/uv/version.h",
                },
            )
        ]
