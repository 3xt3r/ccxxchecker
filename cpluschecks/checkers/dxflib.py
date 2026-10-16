import os
import re
from checkers.base_checker import BaseChecker


class Dxflib(BaseChecker):
    VENDOR = "ribbonsoft"
    PRODUCT = "dxflib"
    LINK_SOURCE = "https://github.com/LibrePCB/dxflib"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"This file is part of the dxflib project\.",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)(src/)?dl_dxf\.h$",
    ]
    RX_VERSION = re.compile(
        r'#define\s+DL_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"',
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        m = self.RX_VERSION.search(text or "")
        return m.group(1) if m else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]
