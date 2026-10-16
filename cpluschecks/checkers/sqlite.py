import os
import re
from checkers.base_checker import BaseChecker


class Sqlite(BaseChecker):
    VENDOR = "sqlite"
    PRODUCT = "sqlite"
    LINK_SOURCE = "https://github.com/sqlite/sqlite.git"
    STOP_AFTER_FIRST_VERSION = True
    RX_VERSION = re.compile(r'#\s*define\s+SQLITE_VERSION\s+"([\d\.]+)"')
    RX_VERSION_NUMBER = re.compile(r"#\s*define\s+SQLITE_VERSION_NUMBER\s+(\d+)")
    RX_CONFIGURE = re.compile(
        r"AC_INIT\(\s*\[\s*sqlite\s*\]\s*,\s*\[\s*([\d\.]+)\s*\]\s*\)",
        re.IGNORECASE,
    )
    RX_FILE = re.compile(r"^\s*(\d+\.\d+\.\d+)\s*$", re.MULTILINE)

    def _extract_version(self, text: str):
        s = text or ""
        m = self.RX_VERSION.search(s)
        if m:
            return m.group(1)
        m = self.RX_VERSION_NUMBER.search(s)
        if m:
            n = int(m.group(1))
            return f"{n // 1000000}.{(n // 1000) % 1000}.{n % 1000}"
        m = self.RX_CONFIGURE.search(s)
        if m:
            return m.group(1)
        m = self.RX_FILE.search(s)
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        for name in ("sqlite3.h", "sqlite.h", "configure.ac", "VERSION"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_version(text)
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
