import os
import re
from checkers.base_checker import BaseChecker


class Nghttp2(BaseChecker):
    VENDOR = "nghttp2"
    PRODUCT = "nghttp2"
    LINK_SOURCE = "https://github.com/nghttp2/nghttp2.git"
    CONTAINS_PATTERNS = [
        r"\bnghttp2\s*-\s*HTTP/2\s*C\s*Library\b",
    ]
    RX_VERSION = re.compile(
        r"project\s*\(\s*nghttp2\b[^)]*?\bVERSION\s+([\d\.]+)",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        m = self.RX_VERSION.search(text or "")
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CMakeLists.txt")
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
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
