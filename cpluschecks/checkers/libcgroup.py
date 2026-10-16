import os
import re
from checkers.base_checker import BaseChecker


class Libcgroup(BaseChecker):
    VENDOR = "libcgroup_project"
    PRODUCT = "libcgroup"
    LINK_SOURCE = "https://github.com/libcgroup/libcgroup.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
    ]
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\[libcgroup\],\s*\[([0-9]+\.[0-9]+\.[0-9]+)\]",
        re.IGNORECASE,
    )
    RX_MAJOR = re.compile(
        r"AC_SUBST\(\s*LIBRARY_VERSION_MAJOR\s*,\s*(\d+)", re.IGNORECASE
    )
    RX_MINOR = re.compile(
        r"AC_SUBST\(\s*LIBRARY_VERSION_MINOR\s*,\s*(\d+)", re.IGNORECASE
    )
    RX_PATCH = re.compile(
        r"AC_SUBST\(\s*LIBRARY_VERSION_RELEASE\s*,\s*(\d+)", re.IGNORECASE
    )
    _PLACEHOLDER_VERSIONS = {"0.0.0", "0.0", "0"}

    def _extract_version(self, content: str):
        s = content or ""
        m = self.RX_AC_INIT.search(s)
        if m:
            ver = m.group(1)
            if ver not in self._PLACEHOLDER_VERSIONS:
                return ver
        major = self.RX_MAJOR.search(s)
        minor = self.RX_MINOR.search(s)
        patch = self.RX_PATCH.search(s)
        if major and minor and patch:
            ver = f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
            if ver not in self._PLACEHOLDER_VERSIONS:
                return ver
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]
