import os
import re
from checkers.base_checker import BaseChecker


class OneTBB(BaseChecker):
    VENDOR = "intel"
    PRODUCT = "oneTBB"
    LINK_SOURCE = "https://github.com/oneapi-src/oneTBB.git"
    STOP_AFTER_FIRST_VERSION = True
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)include/(oneapi/)?tbb/version\.h$",
        r"(^|/)include/(oneapi/)?tbb/tbb_stddef\.h$",
        r"(^|/)(oneapi/)?tbb/version\.h$",
        r"(^|/)(oneapi/)?tbb/tbb_stddef\.h$",
    ]
    RX_MAJOR = re.compile(r"#\s*define\s+TBB_VERSION_MAJOR\s+(\d+)", re.IGNORECASE)
    RX_MINOR = re.compile(r"#\s*define\s+TBB_VERSION_MINOR\s+(\d+)", re.IGNORECASE)
    RX_PATCH = re.compile(r"#\s*define\s+TBB_VERSION_PATCH\s+(\d+)", re.IGNORECASE)

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        return f"{a.group(1)}.{b.group(1)}.{c.group(1)}" if a and b and c else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_file_contains_only(self, content: str, path: str):
        return []
