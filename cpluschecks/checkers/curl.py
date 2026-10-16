import os
import re
from checkers.base_checker import BaseChecker


class Curl(BaseChecker):
    VENDOR = "haxx"
    PRODUCT = "curl"
    LINK_SOURCE = "https://github.com/curl/curl.git"
    STOP_AFTER_FIRST_VERSION = True
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)RELEASE-NOTES$",
    ]
    RX_SIG1 = re.compile(
        r"SPDX-License-Identifier:\s*curl",
        re.IGNORECASE,
    )
    RX_SIG2 = re.compile(
        r"Copyright\s*\(C\)\s*(?:\d{4}(?:-\d{4})?\s+)?Daniel\s+Stenberg,\s*<daniel@haxx\.se>",
        re.IGNORECASE,
    )
    RX_VERSION = re.compile(
        r"\bcurl\s+and\s+libcurl\s+([0-9]+(?:\.[0-9]+){1,3})\b",
        re.IGNORECASE,
    )

    def check_file_contains_only(self, content: str, path: str):
        s = content or ""
        sig1 = bool(self.RX_SIG1.search(s))
        sig2 = bool(self.RX_SIG2.search(s))
        if sig1 and sig2:
            full = os.path.abspath(path)
            return [
                self.make_result(
                    "unknown",
                    full,
                    extra={"version_source_abs": full},
                )
            ]
        return []

    def check_meta(self, directory: str):
        full = os.path.join(directory, "RELEASE-NOTES")
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
                    "origin": "meta:RELEASE-NOTES",
                },
            )
        ]
