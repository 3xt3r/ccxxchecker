import os
import re
from checkers.base_checker import BaseChecker


class Zlib(BaseChecker):
    VENDOR = "zlib"
    PRODUCT = "zlib"
    LINK_SOURCE = "https://github.com/madler/zlib.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"zlib\.h\s*--\s*interface of the",
        r"zlib\s+general\s+purpose\s+compression\s+library",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)zlib\.h$",
        r"^zlib\.h$",
    ]
    RX_VERSION = re.compile(r'#\s*define\s+ZLIB_VERSION\s+"([^"]+)"')
    RX_META = re.compile(
        r"^\s*Changes\s+in\s+([0-9]+(?:\.[0-9]+){1,3}(?:-[\w\-]+)?)\s*\(",
        re.IGNORECASE | re.MULTILINE,
    )

    def _norm_version(self, value: str):
        m = re.match(r"^([0-9]+(?:\.[0-9]+){1,3})", (value or "").strip())
        return m.group(1) if m else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        m = self.RX_VERSION.search(content or "")
        if not m:
            return []
        ver = self._norm_version(m.group(1))
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        for name in ("ChangeLog", "CHANGELOG", "CHANGELOG.md"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            if "zlib" not in (text or "").lower():
                continue
            m = self.RX_META.search(text)
            if not m:
                continue
            ver = self._norm_version(m.group(1))
            if not ver:
                continue
            return [
                self.make_result(
                    ver,
                    os.path.abspath(full),
                    extra={
                        "version_source_abs": os.path.abspath(full),
                        "origin": f"meta:{name}",
                    },
                )
            ]
        return []
