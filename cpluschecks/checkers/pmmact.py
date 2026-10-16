import os
import re
from checkers.base_checker import BaseChecker


class Pmacct(BaseChecker):
    VENDOR = "pmacct"
    PRODUCT = "pmacct"
    LINK_SOURCE = "https://github.com/pmacct/pmacct.git"
    CONTAINS_PATTERNS = [
        r"pmacct\s+\(Promiscuous mode IP Accounting package\)",
    ]
    RX_CHANGELOG = re.compile(
        r"^\s*(\d+\.\d+\.\d+)\s+--\s+\d{2}-\d{2}-\d{4}",
        re.MULTILINE,
    )
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\s*\[?pmacct\]?\s*,\s*\[?(\d+\.\d+\.\d+)\]?",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        s = text or ""
        if "pmacct" not in s.lower():
            return None
        m = self.RX_CHANGELOG.search(s) or self.RX_AC_INIT.search(s)
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        for name in ("configure.ac", "CHANGELOG", "ChangeLog"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_version(text)
            if not ver:
                continue
            return [
                self.make_result(
                    ver,
                    full,
                    extra={
                        "version_source_abs": full,
                        "origin": f"meta:{name}",
                    },
                )
            ]
        return []
