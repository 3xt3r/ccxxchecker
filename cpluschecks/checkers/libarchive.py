import os
import re
from checkers.base_checker import BaseChecker


class Libarchive(BaseChecker):
    VENDOR = "libarchive"
    PRODUCT = "libarchive"
    LINK_SOURCE = "https://github.com/libarchive/libarchive.git"
    CONTAINS_PATTERNS = [
        r"Copyright\s*\(c\)\s*2016\s*Martin\s*Matuska",
        r"\barchive_entry_set_perm\b",
        r"\barchive_entry_set_rdevminor\b",
        r"\barchive_entry_copy_symlink_w\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)archive\.h$",
        r"(^|/)archive_entry\.h$",
        r"(^|/)configure\.ac$",
    ]
    RX_VERSION_STRING = re.compile(
        r'#define\s+ARCHIVE_VERSION_ONLY_STRING\s+"([0-9]+\.[0-9]+\.[0-9]+)"',
        re.IGNORECASE,
    )
    RX_CONFIGURE = re.compile(
        r"m4_define\(\[LIBARCHIVE_VERSION_S\],\s*\[([0-9]+\.[0-9]+\.[0-9]+)\]\)",
        re.IGNORECASE,
    )
    RX_VERSION_NUMBER = re.compile(
        r"#define\s+ARCHIVE_VERSION_NUMBER\s+(\d+)",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        s = text or ""
        m = self.RX_VERSION_STRING.search(s)
        if m:
            return m.group(1)
        m = self.RX_CONFIGURE.search(s)
        if m:
            return m.group(1)
        m = self.RX_VERSION_NUMBER.search(s)
        if not m:
            return None
        try:
            num = int(m.group(1))
        except Exception:
            return None
        major = num // 1000000
        minor = (num // 1000) % 1000
        patch = num % 1000
        return f"{major}.{minor}.{patch}"

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]
