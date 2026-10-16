import os
import re
from checkers.base_checker import BaseChecker


class Userver(BaseChecker):
    VENDOR = "userver"
    PRODUCT = "userver"
    LINK_SOURCE = "https://github.com/userver-framework/userver.git"
    STOP_AFTER_FIRST_VERSION = True
    MONOREPO_SINGLETON = True
    ROOT_ANCHOR_PATHS = ("userver/version.txt",)
    CONTAINS_PATTERNS = [
        r"\bUSERVER_NAMESPACE_BEGIN\b",
    ]
    RX_VERSION_TXT = re.compile(
        r"^\s*v?(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z._-]+)?)\s*$",
        re.IGNORECASE,
    )
    RX_MAJOR = re.compile(
        r"\s*set\s*\(\s*USERVER_MAJOR_VERSION\s+([0-9]+)\s*\)\s*",
        re.IGNORECASE,
    )
    RX_MINOR = re.compile(
        r"\s*set\s*\(\s*USERVER_MINOR_VERSION\s+([^\s\)]+)\s*\)\s*",
        re.IGNORECASE,
    )
    RX_DEFINE = re.compile(
        r'^\s*#\s*define\s+USERVER_VERSION\s+"?(\d+(?:\.\d+){1,3})"?\s*$',
        re.MULTILINE,
    )

    def _extract_version_txt(self, text: str):
        for line in (text or "").splitlines():
            m = self.RX_VERSION_TXT.match(line.strip())
            if m:
                return m.group(1)
        return None

    def _extract_version_cmake(self, text: str):
        s = text or ""
        major = None
        minor = None
        for line in s.splitlines():
            m = self.RX_MAJOR.match(line)
            if m:
                major = m.group(1)
                continue
            m = self.RX_MINOR.match(line)
            if m:
                minor = m.group(1)
        if major and minor:
            return f"{major}.{minor}"
        m = self.RX_DEFINE.search(s)
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        d = os.path.abspath(directory)
        for _ in range(10):
            full = os.path.join(d, "userver", "version.txt")
            if os.path.isfile(full):
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except Exception:
                    text = ""
                ver = self._extract_version_txt(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(full),
                            extra={
                                "version_source_abs": os.path.abspath(full),
                                "origin": "meta:userver/version.txt",
                            },
                        )
                    ]
            for rel in (
                os.path.join("cmake", "GetUserverVersion.cmake"),
                "GetUserverVersion.cmake",
            ):
                full = os.path.join(d, rel)
                if not os.path.isfile(full):
                    continue
                try:
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except Exception:
                    text = ""
                ver = self._extract_version_cmake(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(full),
                            extra={
                                "version_source_abs": os.path.abspath(full),
                                "origin": f"meta:{rel.replace(os.sep, '/')}",
                            },
                        )
                    ]
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
        return []
