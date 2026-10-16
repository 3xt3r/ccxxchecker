import os
import re
from checkers.base_checker import BaseChecker


class Libjson(BaseChecker):
    VENDOR = "vincenthz"
    PRODUCT = "libjson"
    LINK_SOURCE = "https://github.com/vincenthz/libjson.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)json\.h$",
    ]
    CONTAINS_PATTERNS = [
        r"Vincent Hanquez",
        r"#define\s+JSON_MAJOR\b",
    ]
    RX_MAJOR = re.compile(r"#define\s+JSON_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+JSON_MINOR\s+(\d+)")

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        major = self.RX_MAJOR.search(content or "")
        minor = self.RX_MINOR.search(content or "")
        if not (major and minor):
            return []
        src = os.path.abspath(path)
        ver = f"{major.group(1)}.{minor.group(1)}"
        return [self.make_result(ver, src, extra={"version_source_abs": src})]
