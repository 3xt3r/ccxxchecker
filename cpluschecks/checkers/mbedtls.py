import os
import re
from checkers.base_checker import BaseChecker


class Mbedtls(BaseChecker):
    VENDOR = "mbed"
    PRODUCT = "mbedtls"
    LINK_SOURCE = "https://github.com/Mbed-TLS/mbedtls.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"#define\s+MBEDTLS_VERSION_STRING\b",
    ]
    RX_PROJECT = re.compile(
        r'project\s*\(\s*"?\s*Mbed\s+TLS\s*"?[^)]*\bVERSION\s+([0-9]+(?:\.[0-9]+){1,3})\b',
        re.IGNORECASE | re.DOTALL,
    )
    RX_SET = re.compile(
        r'\bset\s*\(\s*MBEDTLS_VERSION\s+["\']?([0-9]+(?:\.[0-9]+){1,3})["\']?\s*\)',
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        m = self.RX_PROJECT.search(text or "") or self.RX_SET.search(text or "")
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        cmake = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(cmake):
            return []
        try:
            with open(cmake, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_version(text)
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
