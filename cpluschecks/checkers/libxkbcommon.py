import os
import re
from checkers.base_checker import BaseChecker


class Libxkbcommon(BaseChecker):
    VENDOR = "xkbcommon"
    PRODUCT = "libxkbcommon"
    LINK_SOURCE = "https://github.com/xkbcommon/libxkbcommon"
    CONTAINS_PATTERNS = [
        r"struct\s+xkb_context\s*;",
        r"struct\s+xkb_keymap\s*;",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)meson\.build$",
    ]
    RX_PROJECT = re.compile(r"project\s*\(\s*['\"]?xkbcommon['\"]?", re.IGNORECASE)
    RX_VERSION = re.compile(r"version\s*:\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]")

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        if not self.RX_PROJECT.search(s):
            return []
        m = self.RX_VERSION.search(s)
        if not m:
            return []
        src_abs = os.path.abspath(path)
        return [
            self.make_result(m.group(1), src_abs, extra={"version_source_abs": src_abs})
        ]
