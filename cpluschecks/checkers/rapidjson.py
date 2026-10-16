import os
import re
from checkers.base_checker import BaseChecker


class Rapidjson(BaseChecker):
    VENDOR = "tencent"
    PRODUCT = "rapidjson"
    LINK_SOURCE = "https://github.com/Tencent/rapidjson.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r'#\s*include\s*[<"][^">]*rapidjson/[^">]+[">]|\bRAPIDJSON(?:\b|_)'
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)rapidjson/rapidjson\.h$",
        r"(^|/)rapidjson\.h$",
        r"^rapidjson\.h$",
    ]
    RX_MAJOR = re.compile(
        r"^\s*#\s*define\s+RAPIDJSON_MAJOR_VERSION\s+(\d+)\b",
        re.MULTILINE | re.IGNORECASE,
    )
    RX_MINOR = re.compile(
        r"^\s*#\s*define\s+RAPIDJSON_MINOR_VERSION\s+(\d+)\b",
        re.MULTILINE | re.IGNORECASE,
    )
    RX_PATCH = re.compile(
        r"^\s*#\s*define\s+RAPIDJSON_PATCH_VERSION\s+(\d+)\b",
        re.MULTILINE | re.IGNORECASE,
    )
    RX_META = re.compile(
        r"^\s*(?:##\s*)?\[?v?(\d+\.\d+\.\d+)\]?(?:\s*[-–]\s*\d{4}-\d{2}-\d{2}|\s*\([A-Za-z]{3,9}\s+\d{4}\))?",
        re.IGNORECASE | re.MULTILINE,
    )

    def _extract_header_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        return f"{a.group(1)}.{b.group(1)}.{c.group(1)}" if a and b and c else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_header_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        for name in ("CHANGELOG.md", "Changelog.md", "changelog.md"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            if "rapidjson" not in (text or "").lower():
                continue
            m = self.RX_META.search(text)
            if not m:
                continue
            return [
                self.make_result(
                    m.group(1),
                    os.path.abspath(full),
                    extra={
                        "version_source_abs": os.path.abspath(full),
                        "origin": f"meta:{name}",
                    },
                )
            ]
        return []
