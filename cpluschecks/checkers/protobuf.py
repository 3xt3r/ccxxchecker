import os
import re
from checkers.base_checker import BaseChecker


class Protobuf(BaseChecker):
    VENDOR = "google"
    PRODUCT = "protobuf"
    LINK_SOURCE = "https://github.com/protocolbuffers/protobuf.git"
    CONTAINS_PATTERNS = [
        r"Protocol Buffers - Google's data interchange format",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)protobuf\.h$",
        r"(^|/)google/protobuf/port_def\.inc$",
    ]
    RX_MODULE_BLOCK = re.compile(
        r"\bmodule\s*\((?P<body>.*?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    RX_MODULE_NAME = re.compile(
        r'\bname\s*=\s*["\']protobuf["\']',
        re.IGNORECASE,
    )
    RX_MODULE_VERSION = re.compile(
        r'\bversion\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    RX_HEADER_VERSION = re.compile(
        r"#define\s+GOOGLE_PROTOBUF_VERSION\s+(\d+)",
    )

    def _parse_header_version(self, num: int) -> str:
        major = num // 1_000_000
        minor = (num % 1_000_000) // 1_000
        patch = num % 1_000
        return f"{major}.{minor}.{patch}"

    def _extract_module_version(self, text: str):
        for m in self.RX_MODULE_BLOCK.finditer(text or ""):
            body = m.group("body")
            if not self.RX_MODULE_NAME.search(body):
                continue
            vm = self.RX_MODULE_VERSION.search(body)
            if vm:
                return vm.group(1).strip()
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        m = self.RX_HEADER_VERSION.search(s)
        if not m:
            return []
        try:
            ver = self._parse_header_version(int(m.group(1)))
        except Exception:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]

    def check_meta(self, directory: str):
        full = os.path.join(directory, "MODULE.bazel")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_module_version(text)
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
