import os
import re
from checkers.base_checker import BaseChecker


class Ndpi(BaseChecker):
    VENDOR = "ntop"
    PRODUCT = "ndpi"
    LINK_SOURCE = "https://github.com/ntop/nDPI.git"
    CONTAINS_PATTERNS = [
        r"Copyright.*ntop.*nDPI",
        r"ndpi_workflow_node_t",
        r"ndpi_build_default_ports_range",
    ]
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\[libndpi\],\[(\d+\.\d+\.\d+)\]\)",
        re.IGNORECASE,
    )
    RX_NDPI = re.compile(
        r"\bnDPI\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        s = text or ""
        m = self.RX_AC_INIT.search(s) or self.RX_NDPI.search(s)
        return m.group(1) if m else None

    def check_meta(self, directory: str):
        for name in ("configure.ac", "CMakeLists.txt"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_version(text)
            if not ver:
                continue
            return [
                self.make_result(
                    ver,
                    full,
                    extra={
                        "version_source_abs": full,
                        "origin": f"meta:{name}",
                    },
                )
            ]
        return []

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        m = self.RX_AC_INIT.search(s) or self.RX_NDPI.search(s)
        if m:
            return [
                self.make_result(
                    m.group(1), src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        return []
