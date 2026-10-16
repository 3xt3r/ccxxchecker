import os
import re
from checkers.base_checker import BaseChecker


class Brotli(BaseChecker):
    VENDOR = "google"
    PRODUCT = "brotli"
    LINK_SOURCE = "https://github.com/google/brotli.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)c/common/version\.h$",
    ]
    CONTAINS_PATTERNS = [
        r"\bkBrotliDictionaryData\b",
        r"brotli:\s*data\s*must\s*be\s*a\s*C-contiguous\s*buffer",
    ]
    RX_MAKE = re.compile(
        r"#\s*define\s+BROTLI_VERSION\s+BROTLI_MAKE_HEX_VERSION\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
        re.I,
    )
    RX_MAJOR = re.compile(r"#\s*define\s+BROTLI_VERSION_MAJOR\s+(\d+)", re.I)
    RX_MINOR = re.compile(r"#\s*define\s+BROTLI_VERSION_MINOR\s+(\d+)", re.I)
    RX_PATCH = re.compile(r"#\s*define\s+BROTLI_VERSION_PATCH\s+(\d+)", re.I)
    RX_HEX = re.compile(r"#\s*define\s+BROTLI_VERSION\s+0x([0-9a-fA-F]+)", re.I)

    @staticmethod
    def _hex_to_semver(hex_str: str) -> str:
        x = int(hex_str, 16)
        return f"{(x >> 24) & 0xFF}.{(x >> 12) & 0xFFF}.{x & 0xFFF}"

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src = os.path.abspath(path)
        m = self.RX_MAKE.search(s)
        if m:
            return [
                self.make_result(
                    f"{m.group(1)}.{m.group(2)}.{m.group(3)}",
                    src,
                    extra={"version_source_abs": src},
                )
            ]
        maj = self.RX_MAJOR.search(s)
        minr = self.RX_MINOR.search(s)
        pat = self.RX_PATCH.search(s)
        if maj and minr and pat:
            return [
                self.make_result(
                    f"{maj.group(1)}.{minr.group(1)}.{pat.group(1)}",
                    src,
                    extra={"version_source_abs": src},
                )
            ]
        m = self.RX_HEX.search(s)
        if m:
            return [
                self.make_result(
                    self._hex_to_semver(m.group(1)),
                    src,
                    extra={"version_source_abs": src},
                )
            ]
        return []
