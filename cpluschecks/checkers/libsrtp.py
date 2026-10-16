import os
import re
from checkers.base_checker import BaseChecker


class Libsrtp(BaseChecker):
    VENDOR = "cisco"
    PRODUCT = "libsrtp"
    LINK_SOURCE = "https://github.com/cisco/libsrtp.git"
    CONTAINS_PATTERNS = [
        (r"\bThis is the secure real-time transport protocol\b", re.IGNORECASE),
        (r"\bsecure real-time transport protocol\b", re.IGNORECASE),
    ]
    VERSION_GUARD_PATTERNS = [
        r"\blibsrtp\b",
        r"\bsrtp\b",
    ]
    VERSION_PATTERNS = [
        (
            r"AC_INIT\s*\(\s*\[libsrtp[^\]]*]\s*,\s*\[([\d\.]+(?:-[A-Za-z0-9._]+)?)\]",
            1,
            re.IGNORECASE,
        ),
        (
            r"project\s*\(\s*'libsrtp[^']*'\s*,\s*'c'\s*,\s*version\s*:\s*'([\d\.]+(?:-[A-Za-z0-9._]+)?)'",
            1,
            re.IGNORECASE,
        ),
        (
            r"project\s*\(\s*libsrtp[^\s,)]*\s+VERSION\s+([\d\.]+(?:-[A-Za-z0-9._]+)?)",
            1,
            re.IGNORECASE,
        ),
        (
            r"^\s*([\d]+\.[\d]+(?:\.[\d]+)?(?:-[A-Za-z0-9._]+)?)\s*$",
            1,
            re.MULTILINE,
        ),
    ]

    def _looks_like_libsrtp_root(self, directory: str) -> bool:
        markers = [
            os.path.join(directory, "crypto"),
            os.path.join(directory, "include", "srtp.h"),
            os.path.join(directory, "srtp"),
            os.path.join(directory, "configure.ac"),
            os.path.join(directory, "meson.build"),
            os.path.join(directory, "CMakeLists.txt"),
        ]
        score = sum(1 for p in markers if os.path.exists(p))
        return score >= 2

    def check_meta(self, directory: str):
        if not self._looks_like_libsrtp_root(directory):
            return []
        candidates = [
            "configure.ac",
            "meson.build",
            "CMakeLists.txt",
            "VERSION",
        ]
        results = []
        for fname in candidates:
            full = os.path.join(directory, fname)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue
            hits = self.check_file_versions_only(content, full)
            for r in hits:
                r["version_source_abs"] = os.path.abspath(full)
                r["origin"] = f"meta:{fname}"
                results.append(r)
            if results:
                return results
        return []
