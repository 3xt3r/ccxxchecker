import os
import re
from checkers.base_checker import BaseChecker


class Msgpack(BaseChecker):
    VENDOR = "msgpack"
    PRODUCT = "msgpack-c"
    LINK_SOURCE = "https://github.com/msgpack/msgpack-c.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)include/msgpack/predef/version\.h$",
        r"(^|/)include/msgpack/version\.h$",
        r"(^|/)include/msgpack\.h$",
        r"(^|/)src/msgpack\.h$",
        r"(^|/)msgpack\.h$",
    ]
    CONTAINS_PATTERNS = [
        (r"MessagePack\s+for", re.IGNORECASE),
        (r"FURUHASHI\s+Sadayuki", re.IGNORECASE),
    ]
    RX_PREDEF = re.compile(
        r"#define\s+MSGPACK_PREDEF_VERSION\s+MSGPACK_VERSION_NUMBER\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)",
        re.IGNORECASE,
    )
    RX_VERSION = re.compile(
        r'#\s*define\s+MSGPACK_VERSION\s+"([0-9.]+)"',
        re.IGNORECASE,
    )
    RX_MAJOR = re.compile(r"#\s*define\s+MSGPACK_VERSION_MAJOR\s+(\d+)", re.IGNORECASE)
    RX_MINOR = re.compile(r"#\s*define\s+MSGPACK_VERSION_MINOR\s+(\d+)", re.IGNORECASE)
    RX_REV = re.compile(r"#\s*define\s+MSGPACK_VERSION_REVISION\s+(\d+)", re.IGNORECASE)

    def _extract_version(self, text: str):
        s = text or ""
        m = self.RX_PREDEF.search(s)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        m = self.RX_VERSION.search(s)
        if m:
            return m.group(1).strip()
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_REV.search(s)
        return f"{a.group(1)}.{b.group(1)}.{c.group(1)}" if a and b and c else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_file_contains_only(self, content: str, path: str):
        return (
            super().check_file_contains_only(content, path)
            if self.match_source_filename(path)
            else []
        )
