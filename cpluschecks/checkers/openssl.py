import os
import re
from checkers.base_checker import BaseChecker


class Openssl(BaseChecker):
    VENDOR = "openssl"
    PRODUCT = "openssl"
    LINK_SOURCE = "https://github.com/openssl/openssl.git"
    TAG_TEMPLATE = "openssl-{version}"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"Copyright\s+19\d{2}(?:-\d{4})?\s+The\s+OpenSSL\s+Project\s+Authors",
    ]
    RX_MAJOR = re.compile(r"#\s*define\s+OPENSSL_VERSION_MAJOR\s+(\d+)", re.IGNORECASE)
    RX_MINOR = re.compile(r"#\s*define\s+OPENSSL_VERSION_MINOR\s+(\d+)", re.IGNORECASE)
    RX_PATCH = re.compile(r"#\s*define\s+OPENSSL_VERSION_PATCH\s+(\d+)", re.IGNORECASE)
    RX_PRE = re.compile(
        r'#\s*define\s+OPENSSL_VERSION_PRE_RELEASE\s+"([^"]*)"', re.IGNORECASE
    )
    RX_META_HEAD = re.compile(
        r"^\s*OpenSSL\s+([\w.\-]+)\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_META_CHG = re.compile(
        r"^\s*Changes\s+between\s+[\w.\-]+\s+and\s+([\w.\-]+)",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_META_RELEASES = re.compile(
        r"OpenSSL\s+Releases[\s\S]+?- \[OpenSSL\s([0-9.]+[a-z]?|0\.9\.x)\]",
        re.IGNORECASE,
    )

    def _extract_header_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        if not (a and b and c):
            return None
        ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        pre = self.RX_PRE.search(s)
        return ver + pre.group(1) if pre and pre.group(1) else ver

    def _extract_meta_version(self, text: str):
        s = text or ""
        if "openssl" not in s.lower():
            return None
        m = self.RX_META_RELEASES.search(s)
        if m:
            return m.group(1).strip()
        m = self.RX_META_HEAD.search(s) or self.RX_META_CHG.search(s)
        return m.group(1).strip() if m else None

    def check_meta(self, directory: str):
        for hpath in (
            os.path.join(directory, "include", "openssl", "opensslv.h"),
            os.path.join(directory, "include", "openssl", "openssl.h"),
        ):
            if not os.path.isfile(hpath):
                continue
            try:
                text = open(hpath, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            ver = self._extract_header_version(text)
            if ver:
                return [
                    self.make_result(
                        ver,
                        os.path.abspath(hpath),
                        extra={
                            "version_source_abs": os.path.abspath(hpath),
                            "origin": "meta:include/openssl/opensslv.h",
                        },
                    )
                ]
        for name in ("CHANGES", "CHANGES.md", "NEWS", "NEWS.md"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_meta_version(text)
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

    def check_file_versions_only(self, content: str, path: str):
        ver = self._extract_header_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]
