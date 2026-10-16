import os
import re
from checkers.base_checker import BaseChecker


class Vmime(BaseChecker):
    VENDOR = "kisli"
    PRODUCT = "vmime"
    LINK_SOURCE = "https://github.com/kisli/vmime.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"VMime\s+library\s*\(https?://www\.vmime\.org\)",
    ]
    RX_MAJOR = re.compile(
        r"^\s*SET\s*\(\s*VMIME_VERSION_MAJOR\s+(\d+)\s*\)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_MINOR = re.compile(
        r"^\s*SET\s*\(\s*VMIME_VERSION_MINOR\s+(\d+)\s*\)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_MICRO = re.compile(
        r"^\s*SET\s*\(\s*VMIME_VERSION_MICRO\s+(\d+)\s*\)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_DEFINE = re.compile(
        r'^\s*#\s*define\s+VMIME_VERSION\s+"?(\d+(?:\.\d+){1,3})"?\s*$',
        re.MULTILINE,
    )

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_MICRO.search(s)
        if a and b and c:
            return f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        m = self.RX_DEFINE.search(s)
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
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
