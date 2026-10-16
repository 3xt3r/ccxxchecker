import os
import re
from checkers.base_checker import BaseChecker


class Libinjection(BaseChecker):
    VENDOR = "libinjection"
    PRODUCT = "libinjection"
    LINK_SOURCE = "https://github.com/libinjection/libinjection.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)libinjection\.h$",
        r"(^|/)libinjection_sqli\.c$",
        r"(^|/)libinjection_xss\.c$",
    ]
    CONTAINS_PATTERNS = [
        r"client9\.com",
        r"#define\s+LIBINJECTION_VERSION\b",
    ]
    RX_HEADER = re.compile(r'#\s*define\s+LIBINJECTION_VERSION\s+"([^"]+)"', re.I)
    RX_SQLI = re.compile(r"libinjection\s+sqli\s+([0-9a-f]{4})-([0-9a-f.-]+)", re.I)

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        m = self.RX_HEADER.search(s) or self.RX_SQLI.search(s)
        if not m:
            return []
        ver = m.group(1) if self.RX_HEADER.search(s) else f"{m.group(1)}-{m.group(2)}"
        src = os.path.abspath(path)
        return [self.make_result(ver, src, extra={"version_source_abs": src})]
