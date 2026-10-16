import os
import re
from checkers.base_checker import BaseChecker


class Fmt(BaseChecker):
    VENDOR = "fmt"
    PRODUCT = "fmt"
    LINK_SOURCE = "https://github.com/fmtlib/fmt.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)include/fmt/base\.h$",
        r"(^|/)fmt/base\.h$",
        r"(^|/)bundled/base\.h$",
        r"(^|/)bundled/core\.h$",
        r"(^|/)ChangeLog\.md$",
    ]
    CONTAINS_PATTERNS = [
        (r"Formatting library for C\+\+", re.IGNORECASE),
    ]
    RX_FMT_VERSION = re.compile(r"#define\s+FMT_VERSION\s+(\d+)")
    RX_CHANGELOG = re.compile(r"^#\s*([0-9]+\.[0-9]+\.[0-9]+)\s+-", re.MULTILINE)

    @staticmethod
    def _decode(n: str) -> str:
        x = int(n)
        return f"{x // 10000}.{(x // 100) % 100}.{x % 100}"

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        src_abs = os.path.abspath(path)
        base = os.path.basename(path)
        if base in ("base.h", "core.h"):
            m = self.RX_FMT_VERSION.search(content or "")
            if m:
                return [
                    self.make_result(
                        self._decode(m.group(1)),
                        src_abs,
                        extra={"version_source_abs": src_abs},
                    )
                ]
        if base == "ChangeLog.md":
            m = self.RX_CHANGELOG.search(content or "")
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        return []

    def check_meta(self, directory: str):
        for candidate in [
            os.path.join(directory, "include", "fmt", "base.h"),
            os.path.join(directory, "include", "fmt", "core.h"),
        ]:
            if not os.path.isfile(candidate):
                continue
            try:
                text = open(candidate, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            m = self.RX_FMT_VERSION.search(text)
            if m:
                return [
                    self.make_result(
                        self._decode(m.group(1)),
                        os.path.abspath(candidate),
                        extra={
                            "version_source_abs": os.path.abspath(candidate),
                            "origin": f"meta:{os.path.relpath(candidate, directory)}",
                        },
                    )
                ]
        return []
