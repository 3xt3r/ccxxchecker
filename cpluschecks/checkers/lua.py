import os
import re
from checkers.base_checker import BaseChecker


class Lua(BaseChecker):
    VENDOR = "lua"
    PRODUCT = "lua"
    LINK_SOURCE = "https://github.com/lua/lua"
    CONTAINS_PATTERNS = [
        r"#define\s+LUA_VERSION\b",
        r"#define\s+LUA_RELEASE\b",
        r"Copyright\s+\(C\).*Lua\.org",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)lua\.h$",
    ]
    RX_VERSION_NUM = re.compile(r"#\s*define\s+LUA_VERSION_NUM\s+([0-9]+)")

    def _parse_lua_version(self, num: int) -> str:
        major = num // 100
        minor = num % 100
        return f"{major}.{minor}"

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        m = self.RX_VERSION_NUM.search(content or "")
        if not m:
            return []
        try:
            ver = self._parse_lua_version(int(m.group(1)))
        except Exception:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]
