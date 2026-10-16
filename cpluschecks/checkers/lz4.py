import os
import re
from checkers.base_checker import BaseChecker


class Lz4(BaseChecker):
    VENDOR = "lz4_project"
    PRODUCT = "lz4"
    LINK_SOURCE = "https://github.com/lz4/lz4.git"
    CONTAINS_PATTERNS = [
        r"\bLZ4\s*-\s*Fast\s*LZ\s*compression\s*algorithm\b",
    ]
    RX_MAJOR = re.compile(r"#define\s+LZ4_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+LZ4_VERSION_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+LZ4_VERSION_RELEASE\s+(\d+)")

    def _extract_version(self, text: str):
        txt = text or ""
        m = self.RX_MAJOR.search(txt)
        n = self.RX_MINOR.search(txt)
        p = self.RX_PATCH.search(txt)
        if m and n and p:
            return f"{m.group(1)}.{n.group(1)}.{p.group(1)}"
        return None

    def check_meta(self, directory: str):
        for rel in ("lz4.h", os.path.join("lib", "lz4.h")):
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
