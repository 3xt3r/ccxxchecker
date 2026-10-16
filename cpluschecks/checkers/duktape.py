import os
import re
from checkers.base_checker import BaseChecker


class Duktape(BaseChecker):
    VENDOR = "duktape_project"
    PRODUCT = "duktape"
    LINK_SOURCE = "https://github.com/svaarala/duktape.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"#define\s+DUK__ARRAY_MID_JOIN_LIMIT",
        r"duk_bi_array_prototype_to_string",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)duktape\.h$",
    ]
    RX_VERSION = re.compile(
        r"#define\s+DUK_VERSION\s+(\d+)L",
        re.IGNORECASE,
    )

    def _parse_version(self, text: str):
        m = self.RX_VERSION.search(text or "")
        if not m:
            return None
        try:
            num = int(m.group(1))
            major = num // 10000
            minor = (num % 10000) // 100
            patch = num % 100
            if minor >= 99 or patch >= 99:
                return None
            return f"{major}.{minor}.{patch}"
        except Exception:
            return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._parse_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        for candidate in [
            os.path.join(directory, "duktape.h"),
            os.path.join(directory, "src", "duktape.h"),
            os.path.join(directory, "src-input", "duktape.h.in"),
        ]:
            if os.path.isfile(candidate):
                try:
                    with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
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
                                "origin": "meta:duktape.h",
                            },
                        )
                    ]
        return []
