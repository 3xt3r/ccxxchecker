import os
import re
from checkers.base_checker import BaseChecker


class NlohmannJson(BaseChecker):
    VENDOR = "json-for-modern-cpp_project"
    PRODUCT = "json-for-modern-cpp"
    LINK_SOURCE = "https://github.com/nlohmann/json.git"
    CONTAINS_PATTERNS = [
        r"\bJSON for Modern C\+\+\b",
    ]
    RX_VERSION = re.compile(
        r"project\s*\(\s*['\"]nlohmann_json['\"].*?version\s*:\s*['\"](\d+\.\d+\.\d+)['\"]",
        re.IGNORECASE | re.DOTALL,
    )

    def _extract_version(self, text: str):
        m = self.RX_VERSION.search(text or "")
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "meson.build")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_version(text)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:meson.build",
                },
            )
        ]
