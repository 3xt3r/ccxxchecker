import os
import re
from checkers.base_checker import BaseChecker


class Spdlog(BaseChecker):
    VENDOR = "gabime"
    PRODUCT = "spdlog"
    LINK_SOURCE = "https://github.com/gabime/spdlog.git"
    CONTAINS_PATTERNS = [
        r"//\s*Copyright\(c\)\s*2015-present,\s*Gabi Melman\s*&\s*spdlog contributors\.",
    ]
    RX_MAJOR = re.compile(r"#define\s+SPDLOG_VER_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+SPDLOG_VER_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+SPDLOG_VER_PATCH\s+(\d+)")

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        return f"{a.group(1)}.{b.group(1)}.{c.group(1)}" if a and b and c else None

    def check_meta(self, directory: str):
        for rel in (
            os.path.join("include", "spdlog", "version.h"),
            os.path.join("spdlog", "version.h"),
        ):
            full = os.path.join(directory, rel)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_version(text)
            if not ver:
                continue
            return [
                self.make_result(
                    ver,
                    full,
                    extra={
                        "version_source_abs": full,
                        "origin": f"meta:{rel.replace(os.sep, '/')}",
                    },
                )
            ]
        return []
