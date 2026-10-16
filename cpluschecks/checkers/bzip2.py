import os
import re
from checkers.base_checker import BaseChecker


class Bzip2(BaseChecker):
    VENDOR = "bzip2"
    PRODUCT = "bzip2"
    LINK_SOURCE = "https://gitlab.com/bzip2/bzip2.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)bzlib\.h$",
        r"(^|/)bzlib\.c$",
        r"(^|/)bzip2\.c$",
    ]
    VERSION_PATTERNS = [
        r'#\s*define\s+BZ_VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        r"#\s*define\s+BZ_VERSION\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        (r"bzip2\s+version\s+([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    ]
    CONTAINS_PATTERNS = [
        (r"This file is part of bzip2/libbzip2", re.IGNORECASE),
    ]
    _META_PATTERNS = (
        (
            "Makefile",
            re.compile(
                r"\bDISTNAME\s*=\s*bzip2-([0-9]+\.[0-9]+\.[0-9]+)\b", re.IGNORECASE
            ),
        ),
        (
            "meson.build",
            re.compile(
                r"project\s*\(\s*['\"][^'\"]*bzip2[^'\"]*['\"].*?version\s*:\s*['\"]([0-9]+\.[0-9]+\.[0-9]+)['\"]",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
    )

    def check_meta(self, directory: str):
        for fname, rx in self._META_PATTERNS:
            full = os.path.join(directory, fname)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue
            m = rx.search(content)
            if m:
                result = self.make_result(m.group(1), full)
                result["origin"] = "meta"
                return [result]
        return []
