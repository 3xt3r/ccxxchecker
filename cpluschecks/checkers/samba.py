import os
import re
from checkers.base_checker import BaseChecker


class Samba(BaseChecker):
    VENDOR = "samba"
    PRODUCT = "samba"
    LINK_SOURCE = "https://github.com/samba-team/samba.git"
    CONTAINS_PATTERNS = [
        r"Copyright\s+\(C\)\s+(?:Stefan \(metze\) Metzmacher|Andrew Tridgell|Matthias Dieter Wallnöfer)\s+\d{4}",
    ]
    RX_MAJOR = re.compile(r"SAMBA_VERSION_MAJOR\s*=\s*(\d+)")
    RX_MINOR = re.compile(r"SAMBA_VERSION_MINOR\s*=\s*(\d+)")
    RX_REL = re.compile(r"SAMBA_VERSION_RELEASE\s*=\s*(\d+)")

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.findall(s)
        b = self.RX_MINOR.findall(s)
        c = self.RX_REL.findall(s)
        return f"{a[-1]}.{b[-1]}.{c[-1]}" if a and b and c else None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "VERSION")
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
                    "origin": "meta:VERSION",
                },
            )
        ]
