import os
import re
from checkers.base_checker import BaseChecker


class Hyperscan(BaseChecker):
    VENDOR = "intel"
    PRODUCT = "hyperscan"
    LINK_SOURCE = "https://github.com/intel/hyperscan.git"
    CONTAINS_PATTERNS = [
        r"\bHS_COMPILE_H_\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)src/hs_version\.h$",
        r"(^|/)CMakeLists\.txt$",
        r"(^|/)CHANGELOG\.md$",
    ]
    RX_FILE_MAJOR = re.compile(r"#\s*define\s+HS_MAJOR\s+(\d+)", re.I)
    RX_FILE_MINOR = re.compile(r"#\s*define\s+HS_MINOR\s+(\d+)", re.I)
    RX_FILE_PATCH = re.compile(r"#\s*define\s+HS_PATCH\s+(\d+)", re.I)
    RX_CMAKE_MAJOR = re.compile(r"\bset\s*\(\s*HS_MAJOR_VERSION\s+(\d+)\s*\)", re.I)
    RX_CMAKE_MINOR = re.compile(r"\bset\s*\(\s*HS_MINOR_VERSION\s+(\d+)\s*\)", re.I)
    RX_CMAKE_PATCH = re.compile(r"\bset\s*\(\s*HS_PATCH_VERSION\s+(\d+)\s*\)", re.I)
    RX_CHANGELOG = re.compile(
        r"^\s*\[([0-9]+(?:\.[0-9]+){1,3})\]\s+\d{4}-\d{2}-\d{2}", re.M
    )

    @staticmethod
    def _triplet(txt: str, rx_major, rx_minor, rx_patch):
        major = rx_major.search(txt or "")
        minor = rx_minor.search(txt or "")
        patch = rx_patch.search(txt or "")
        if major and minor and patch:
            return f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        src_abs = os.path.abspath(path)
        base = os.path.basename(path)
        if base == "hs_version.h":
            ver = self._triplet(
                content, self.RX_FILE_MAJOR, self.RX_FILE_MINOR, self.RX_FILE_PATCH
            )
            if ver:
                return [
                    self.make_result(
                        ver, src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        if base == "CMakeLists.txt":
            ver = self._triplet(
                content, self.RX_CMAKE_MAJOR, self.RX_CMAKE_MINOR, self.RX_CMAKE_PATCH
            )
            if ver:
                return [
                    self.make_result(
                        ver, src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        if base == "CHANGELOG.md" and "hyperscan" in (content or "").lower():
            m = self.RX_CHANGELOG.search(content or "")
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        return []
