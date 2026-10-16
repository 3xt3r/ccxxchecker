import os
import re
from checkers.base_checker import BaseChecker


class TacPlus(BaseChecker):
    VENDOR = "facebook"
    PRODUCT = "tac_plus"
    LINK_SOURCE = "https://github.com/facebook/tac_plus.git"
    STOP_AFTER_FIRST_VERSION = True
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)tac_plus\.h$",
    ]
    RX_ID = re.compile(
        r"\$Id:\s*tac_plus\.h,v\s*1\.55\s*2009/07/17\s*16:10:52\s*heas\s*Exp\s*\$",
        re.IGNORECASE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        if not self.RX_ID.search(content or ""):
            return []
        full = os.path.abspath(path)
        return [
            self.make_result(
                "F4.0.4.28",
                full,
                extra={"version_source_abs": full},
            )
        ]

    def check_file_contains_only(self, content: str, path: str):
        return []
