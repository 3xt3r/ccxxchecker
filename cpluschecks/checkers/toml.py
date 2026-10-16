import os
import re
from checkers.base_checker import BaseChecker


class Toml(BaseChecker):
    VENDOR = "marzer"
    PRODUCT = "tomlplusplus"
    LINK_SOURCE = "https://github.com/marzer/tomlplusplus.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"This file is a part of toml\+\+",
    ]
    RX_VERSION = re.compile(
        r"project\s*\(\s*tomlplusplus\b.*?\bVERSION\s+([0-9]+(?:\.[0-9]+){2})\b",
        re.IGNORECASE | re.DOTALL,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CMakeLists.txt")
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
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
