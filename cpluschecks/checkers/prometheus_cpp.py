import os
import re
from checkers.base_checker import BaseChecker


class PrometheusCpp(BaseChecker):
    VENDOR = "prometheus"
    PRODUCT = "prometheus-cpp"
    LINK_SOURCE = "https://github.com/jupp0r/prometheus-cpp.git"
    CONTAINS_PATTERNS = [
        r"Prometheus Client Library for Modern",
    ]
    RX_VERSION = re.compile(
        r"project\s*\(\s*prometheus-cpp\b[^)]*?\bVERSION\s+([\d\.]+)",
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
