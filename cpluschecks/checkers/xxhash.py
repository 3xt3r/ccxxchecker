import os
import re
from checkers.base_checker import BaseChecker


class XXhash(BaseChecker):
    VENDOR = "xxhash"
    PRODUCT = "xxhash"
    LINK_SOURCE = "https://github.com/Cyan4973/xxHash.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"xxHash\s*-\s*Extremely\s+Fast\s+Hash\s+algorithm",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)xxhash\.h$",
    ]
    RX_VERSION_NUMBER = re.compile(r"#define\s+XXH_VERSION_NUMBER\s+(\d+)")
    RX_MAJOR = re.compile(r"#define\s+XXH_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+XXH_VERSION_MINOR\s+(\d+)")
    RX_RELEASE = re.compile(r"#define\s+XXH_VERSION_RELEASE\s+(\d+)")
    RX_GUARD = re.compile(
        r'^\s*PROJECT_NAME\s*=\s*"?\s*xxHash\s*"?\s*$', re.IGNORECASE | re.MULTILINE
    )
    RX_DOXY_VER = re.compile(
        r'^\s*PROJECT_NUMBER\s*=\s*"?\s*([0-9]+(?:\.[0-9]+){1,3})\s*"?\s*$',
        re.MULTILINE,
    )

    def _parse_version(self, content: str):
        s = content or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_RELEASE.search(s)
        if a and b and c:
            return f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._parse_version(content)
        if not ver:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]

    def check_meta(self, directory: str):
        for candidate in [
            os.path.join(directory, "xxhash.h"),
            os.path.join(directory, "xxHash.h"),
        ]:
            if os.path.isfile(candidate):
                try:
                    text = open(
                        candidate, "r", encoding="utf-8", errors="ignore"
                    ).read()
                except Exception:
                    continue
                ver = self._parse_version(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(candidate),
                            extra={
                                "version_source_abs": os.path.abspath(candidate),
                                "origin": "meta:xxhash.h",
                            },
                        )
                    ]
        try:
            files = os.listdir(directory)
        except Exception:
            return []
        for name in files:
            if not name.lower().startswith("doxyfile"):
                continue
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                text = open(full, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                continue
            if not self.RX_GUARD.search(text):
                continue
            m = self.RX_DOXY_VER.search(text)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        os.path.abspath(full),
                        extra={
                            "version_source_abs": os.path.abspath(full),
                            "origin": "meta:Doxyfile",
                        },
                    )
                ]
        return []
