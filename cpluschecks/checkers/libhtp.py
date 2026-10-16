import os
import re
from checkers.base_checker import BaseChecker


class Libhtp(BaseChecker):
    VENDOR = "oisf"
    PRODUCT = "libhtp"
    LINK_SOURCE = "https://github.com/OISF/libhtp.git"
    CONTAINS_PATTERNS = [
        r"\*\s*@author\s+Ivan\s+Ristic\s*<ivanr@webkreator\.com>",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)VERSION$",
        r"(^|/)(CHANGELOG|ChangeLog|changes|Changes|news|News)(\.[A-Za-z0-9]+)?$",
        r"(^|/)configure\.ac$",
        r"(^|/)htp_version\.h\.in$",
    ]
    RX_VERSION = re.compile(
        r"^\s*PKG_VERSION\s*=\s*([0-9]+(?:\.[0-9]+){1,3})\s*$",
        re.MULTILINE,
    )
    RX_CHANGELOG = re.compile(
        r"^\s*([0-9]+(?:\.[0-9]+){1,3})\s*\(\s*\d{1,2}\s+[A-Za-z]+\s+\d{4}\s*\)",
        re.MULTILINE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        base = os.path.basename(path)
        if base.upper() == "VERSION":
            m = self.RX_VERSION.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        if "libhtp" in s.lower():
            m = self.RX_CHANGELOG.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        return []
