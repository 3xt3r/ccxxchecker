import os
import re
from checkers.base_checker import BaseChecker


class Nginx(BaseChecker):
    VENDOR = "nginx"
    PRODUCT = "nginx"
    LINK_SOURCE = "https://github.com/nginx/nginx.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"Copyright\s+\(C\)\s+nginx,\s*Inc\.",
    ]
    VERSION_PATTERNS = [
        r'#\s*define\s+NGINX_VERSION\s+"([^"]+)"',
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)src/core/nginx\.h$",
        r"(^|/)nginx\.h$",
    ]
    RX_GUARD = re.compile(
        r'<change_log\s+[^>]*title\s*=\s*"nginx"',
        re.IGNORECASE,
    )
    RX_META = re.compile(
        r'<changes\s+[^>]*\bver\s*=\s*"([^"]+)"',
        re.IGNORECASE,
    )

    def check_meta(self, directory: str):
        full = os.path.join(directory, "changes.xml")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        if not self.RX_GUARD.search(text):
            return []
        m = self.RX_META.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1).strip(),
                os.path.abspath(full),
                extra={
                    "version_source_abs": os.path.abspath(full),
                    "origin": "meta:changes.xml",
                },
            )
        ]
