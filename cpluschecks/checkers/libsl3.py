import os
import re
from checkers.base_checker import BaseChecker


class Libsl3(BaseChecker):
    VENDOR = "a4z"
    PRODUCT = "libsl3"
    LINK_SOURCE = "https://github.com/a4z/libsl3"
    CONTAINS_PATTERNS = [
        r"libsl3",
        r"sl3::",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)CMakeLists\.txt$",
        r"(^|/)vcpkg\.json$",
    ]
    RX_MAJOR = re.compile(r"set\s*\(\s*sl3_MAJOR_VERSION\s+(\d+)\s*\)", re.IGNORECASE)
    RX_MINOR = re.compile(r"set\s*\(\s*sl3_MINOR_VERSION\s+(\d+)\s*\)", re.IGNORECASE)
    RX_PATCH = re.compile(r"set\s*\(\s*sl3_PATCH_VERSION\s+(\d+)\s*\)", re.IGNORECASE)
    RX_VCPKG_NAME = re.compile(r'"name"\s*:\s*"libsl3"')
    RX_VCPKG_VER = re.compile(r'"version(?:-string)?"\s*:\s*"([^"]+)"')

    def _extract_cmake_version(self, text: str):
        a = self.RX_MAJOR.search(text)
        b = self.RX_MINOR.search(text)
        c = self.RX_PATCH.search(text)
        if a and b and c:
            return f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        base = os.path.basename(path).lower()
        if base == "vcpkg.json":
            if not self.RX_VCPKG_NAME.search(s):
                return []
            m = self.RX_VCPKG_VER.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        src_abs,
                        extra={
                            "version_source_abs": src_abs,
                            "origin": "file:vcpkg.json",
                        },
                    )
                ]
        return []

    def check_meta(self, directory: str):
        full = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        if "libsl3" not in text.lower() and "sl3" not in text.lower():
            return []
        ver = self._extract_cmake_version(text)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:CMakeLists.txt",
                },
            )
        ]
