import os
import re
from checkers.base_checker import BaseChecker


class Cityhash(BaseChecker):
    VENDOR = "google"
    PRODUCT = "cityhash"
    LINK_SOURCE = "https://github.com/google/cityhash.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)NEWS$",
    ]
    CONTAINS_PATTERNS = [
        r"CityHash,\s*by\s*Geoff\s+Pike",
    ]
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\s*\[\s*CityHash\s*\]\s*,\s*\[\s*([^\]]+?)\s*\]",
        re.IGNORECASE,
    )
    RX_NEWS = re.compile(
        r"^CityHash\s+v([0-9]+(?:\.[0-9]+){1,3})\b",
        re.IGNORECASE | re.MULTILINE,
    )
    RX_PLAIN_VERSION = re.compile(r"^[vV]?\d+(?:\.\d+){1,4}(?:[-+][0-9A-Za-z._-]+)?$")
    RX_MAJOR = re.compile(
        r"m4_define\(\s*\[\s*cityhash_major\s*\]\s*,\s*\[\s*(\d+)\s*\]\s*\)",
        re.IGNORECASE,
    )
    RX_MINOR = re.compile(
        r"m4_define\(\s*\[\s*cityhash_minor\s*\]\s*,\s*\[\s*(\d+)\s*\]\s*\)",
        re.IGNORECASE,
    )
    RX_PATCH = re.compile(
        r"m4_define\(\s*\[\s*cityhash_patchlevel\s*\]\s*,\s*\[\s*(\d+)\s*\]\s*\)",
        re.IGNORECASE,
    )

    def _extract_configure_version(self, text: str):
        s = text or ""
        m = self.RX_AC_INIT.search(s)
        if m:
            ver = m.group(1).strip()
            if self.RX_PLAIN_VERSION.fullmatch(ver):
                return ver.lstrip("vV")
        mj = self.RX_MAJOR.search(s)
        mn = self.RX_MINOR.search(s)
        mp = self.RX_PATCH.search(s)
        if mj and mn and mp:
            return f"{mj.group(1)}.{mn.group(1)}.{mp.group(1)}"
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        base = os.path.basename(path)
        if base == "NEWS":
            m = self.RX_NEWS.search(s)
            if m:
                src_abs = os.path.abspath(path)
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
            return []
        ver = self._extract_configure_version(s)
        if not ver:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]

    def check_meta(self, directory: str):
        for name in ("configure.ac", "configure.in"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_configure_version(text)
            if ver:
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
        news = os.path.join(directory, "NEWS")
        if os.path.isfile(news):
            try:
                with open(news, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                return []
            m = self.RX_NEWS.search(text)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        os.path.abspath(news),
                        extra={
                            "version_source_abs": os.path.abspath(news),
                            "origin": "meta:NEWS",
                        },
                    )
                ]
        return []
