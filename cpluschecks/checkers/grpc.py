import os
import re
from checkers.base_checker import BaseChecker


class Grpc(BaseChecker):
    VENDOR = "grpc"
    PRODUCT = "grpc"
    LINK_SOURCE = "https://github.com/grpc/grpc.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)MODULE\.bazel$",
    ]
    CONTAINS_PATTERNS = [
        r"The\s+gRPC\s+Authors",
    ]
    RX_MODULE_BLOCK = re.compile(
        r"\bmodule\s*\((?P<body>.*?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    RX_MODULE_NAME = re.compile(
        r'\bname\s*=\s*"grpc"',
        re.IGNORECASE,
    )
    RX_MODULE_VERSION = re.compile(
        r'\bversion\s*=\s*"([0-9]+(?:\.[0-9]+){1,3}(?:[-\w.]+)?)"',
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

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        version = self._extract_root_module_version(content or "")
        if not version:
            return []
        src_abs = os.path.abspath(path)
        return [
            self.make_result(version, src_abs, extra={"version_source_abs": src_abs})
        ]
