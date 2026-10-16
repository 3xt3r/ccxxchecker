import os
import re
from checkers.base_checker import BaseChecker


class Re2(BaseChecker):
    VENDOR = "google"
    PRODUCT = "re2"
    LINK_SOURCE = "https://github.com/google/re2.git"
    CONTAINS_PATTERNS = [
        r"Copyright\s+\d{4}\s+The\s+RE2\s+Authors",
    ]
    RX_MODULE_BLOCK = re.compile(
        r"\bmodule\s*\((?P<body>.*?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    RX_MODULE_NAME = re.compile(
        r'\bname\s*=\s*["\']re2["\']',
        re.IGNORECASE,
    )
    RX_MODULE_VERSION = re.compile(
        r'\bversion\s*=\s*"([0-9]{4}-[0-9]{2}-[0-9]{2})"',
        re.IGNORECASE,
    )

    def _extract_root_module_version(self, text: str):
        s = text or ""
        for m in self.RX_MODULE_BLOCK.finditer(s):
            body = m.group("body")
            if not self.RX_MODULE_NAME.search(body):
                continue
            vm = self.RX_MODULE_VERSION.search(body)
            if vm:
                return vm.group(1)
        return None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "MODULE.bazel")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_root_module_version(text)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:MODULE.bazel",
                },
            )
        ]
