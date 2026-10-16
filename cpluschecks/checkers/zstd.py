import os
import re
from checkers.base_checker import BaseChecker


class Zstd(BaseChecker):
    VENDOR = "facebook"
    PRODUCT = "zstandard"
    LINK_SOURCE = "https://github.com/facebook/zstd.git"
    CONTAINS_PATTERNS = [
        r"Zstandard\s+data\s+compression",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)lib/zstd\.h$",
        r"^zstd\.h$",
    ]
    RX_STRING = re.compile(r'#\s*define\s+ZSTD_VERSION_STRING\s+"([0-9][\d\.]*)"')
    RX_MAJOR = re.compile(r"#\s*define\s+ZSTD_VERSION_MAJOR\s+(\d+)", re.IGNORECASE)
    RX_MINOR = re.compile(r"#\s*define\s+ZSTD_VERSION_MINOR\s+(\d+)", re.IGNORECASE)
    RX_PATCH = re.compile(r"#\s*define\s+ZSTD_VERSION_RELEASE\s+(\d+)", re.IGNORECASE)
    RX_META = re.compile(
        r"\b[vV]?(\d+\.\d+\.\d+)\b\s*\(\s*[A-Za-z]{3,9}\s+\d{4}\s*\)",
        re.IGNORECASE | re.MULTILINE,
    )

    def _extract_header_version(self, text: str):
        s = text or ""
        m = self.RX_STRING.search(s)
        if m:
            return m.group(1)
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        return f"{a.group(1)}.{b.group(1)}.{c.group(1)}" if a and b and c else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_header_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CHANGELOG")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        low = (text or "").lower()
        if "zstd" not in low and "zstandard" not in low:
            return []
        m = self.RX_META.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:CHANGELOG",
                },
            )
        ]
