import os
import re
from checkers.base_checker import BaseChecker


class Jemalloc(BaseChecker):
    VENDOR = "jemalloc"
    PRODUCT = "jemalloc"
    LINK_SOURCE = "https://github.com/jemalloc/jemalloc.git"
    CONTAINS_PATTERNS = [
        r"jemalloc/internal",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)ChangeLog$",
    ]
    RX_VERSION = re.compile(r"jemalloc[/-]([0-9]+(?:\.[0-9]+){1,3})", re.IGNORECASE)
    RX_CHANGELOG = re.compile(r"^\*\s*([0-9]+\.[0-9]+\.[0-9]+)\s*\(", re.MULTILINE)

    def check_file_versions_only(self, content: str, path: str):
        s = content or ""
        src_abs = os.path.abspath(path)
        m = self.RX_VERSION.search(s)
        if m:
            return [
                self.make_result(
                    m.group(1), src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        if os.path.basename(path) == "ChangeLog" and "https://github.com/jemalloc" in s:
            m = self.RX_CHANGELOG.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        return []
