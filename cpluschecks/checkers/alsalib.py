import os
import re
from checkers.base_checker import BaseChecker


class AlsaLib(BaseChecker):
    VENDOR = "alsa-project"
    PRODUCT = "alsa-lib"
    LINK_SOURCE = "https://github.com/alsa-project/alsa-lib.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"\*\s*\\author\s+Abramo\s+Bagnara\s+<abramo@alsa-project\.org>",
        r"\*\s*\\author\s+Jaroslav\s+Kysela\s+<perex@perex\.cz>",
        r"Advanced\s+Linux\s+Sound\s+Architecture",
        r"ALSA\s+library",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\s*\(\s*\[?alsa-lib\]?\s*,\s*\[?([0-9]+(?:\.[0-9]+){1,3})\]?",
    ]
    RX_VERSION = re.compile(VERSION_PATTERNS[0], re.IGNORECASE)

    def check_meta(self, directory: str):
        full = os.path.join(directory, "configure.ac")
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
        full = os.path.abspath(full)
        return [
            self.make_result(
                m.group(1),
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:configure.ac",
                },
            )
        ]
