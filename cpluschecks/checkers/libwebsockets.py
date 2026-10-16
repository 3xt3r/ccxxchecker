import os
import re
from checkers.base_checker import BaseChecker


class Libwebsockets(BaseChecker):
    VENDOR = "warmcat"
    PRODUCT = "libwebsockets"
    LINK_SOURCE = "https://github.com/warmcat/libwebsockets.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        (
            r"\blibwebsockets\s*-\s*small server side websockets and web server implementation\b",
            re.IGNORECASE,
        ),
        (
            r"Copyright\s*\(C\)\s*2010\s*-\s*20\d{2}\s*Andy\s+Green",
            re.IGNORECASE,
        ),
    ]
    RX_MAJOR = re.compile(
        r'set\s*\(\s*CPACK_PACKAGE_VERSION_MAJOR\s+"?(\d+)"?\s*\)',
        re.IGNORECASE,
    )
    RX_MINOR = re.compile(
        r'set\s*\(\s*CPACK_PACKAGE_VERSION_MINOR\s+"?(\d+)"?\s*\)',
        re.IGNORECASE,
    )
    RX_PATCH = re.compile(
        r'set\s*\(\s*CPACK_PACKAGE_VERSION_PATCH(?:_NUMBER)?\s+"?(\d+)"?\s*\)',
        re.IGNORECASE,
    )
    _PLACEHOLDER_PATCH = 99

    def _extract_version(self, content: str):
        txt = content or ""
        m = self.RX_MAJOR.search(txt)
        n = self.RX_MINOR.search(txt)
        p = self.RX_PATCH.search(txt)
        if m and n and p:
            patch = int(p.group(1))
            if patch >= self._PLACEHOLDER_PATCH:
                return None
            return f"{m.group(1)}.{n.group(1)}.{p.group(1)}"
        return None

    def check_meta(self, directory: str):
        cmake = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(cmake):
            return []
        try:
            with open(cmake, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
        except Exception:
            return []
        ver = self._extract_version(txt)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                os.path.abspath(cmake),
                extra={
                    "version_source_abs": os.path.abspath(cmake),
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
