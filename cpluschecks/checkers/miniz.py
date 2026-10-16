import os
import re
from checkers.base_checker import BaseChecker


class Miniz(BaseChecker):
    VENDOR = "richgel999"
    PRODUCT = "miniz"
    LINK_SOURCE = "https://github.com/richgel999/miniz"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"miniz\.c, v[0-9].*rich.?geldreich",
        r"\btdefl_compressor\b",
        r"\bMINIZ_LITTLE_ENDIAN\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)miniz\.(c|h)$",
    ]
    RX_CMAKE_MAJOR = re.compile(r"set\(MINIZ_API_VERSION\s+(\d+)", re.I)
    RX_CMAKE_MINOR = re.compile(r"set\(MINIZ_MINOR_VERSION\s+(\d+)", re.I)
    RX_CMAKE_PATCH = re.compile(r"set\(MINIZ_PATCH_VERSION\s+(\d+)", re.I)
    RX_HEADER_VERSION = re.compile(
        r"#define\s+MINIZ_VERSION\s+[\"']?([0-9]+\.[0-9]+\.[0-9]+)[\"']?",
        re.IGNORECASE,
    )
    RX_INLINE_VERSION = re.compile(
        r"miniz\.c,\s*v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        re.IGNORECASE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        m = self.RX_HEADER_VERSION.search(s)
        if m:
            return [
                self.make_result(
                    m.group(1), src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        m = self.RX_INLINE_VERSION.search(s)
        if m:
            return [
                self.make_result(
                    m.group(1), src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        return []

    def check_meta(self, directory: str):
        cmake = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(cmake):
            return []
        try:
            text = open(cmake, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            return []
        a = self.RX_CMAKE_MAJOR.search(text)
        b = self.RX_CMAKE_MINOR.search(text)
        c = self.RX_CMAKE_PATCH.search(text)
        if a and b and c:
            ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
            return [
                self.make_result(
                    ver,
                    os.path.abspath(cmake),
                    extra={
                        "version_source_abs": os.path.abspath(cmake),
                        "origin": "meta:CMakeLists.txt",
                    },
                )
            ]
        return []
