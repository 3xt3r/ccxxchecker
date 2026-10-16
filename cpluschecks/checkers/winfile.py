import os
import re
from checkers.base_checker import BaseChecker


class Winfile(BaseChecker):
    VENDOR = "microsoft"
    PRODUCT = "winfile"
    LINK_SOURCE = "https://github.com/microsoft/winfile.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"Long filename support for windows:\s+miscellaneous functions",
    ]
    RX_VERSION = re.compile(
        r"^##\s+Changes\s+in\s+v([0-9]+(?:\.[0-9]+){1,3})\s+compared\s+to\s+v[0-9]+(?:\.[0-9]+){1,3}\s+\(",
        re.IGNORECASE | re.MULTILINE,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CHANGES.md")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        m = self.RX_VERSION.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:CHANGES.md",
                },
            )
        ]
