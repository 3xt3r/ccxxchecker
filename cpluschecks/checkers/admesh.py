import os
import re
from checkers.base_checker import BaseChecker


class Admesh(BaseChecker):
    VENDOR = "admesh_project"
    PRODUCT = "admesh"
    LINK_SOURCE = "https://github.com/admesh/admesh.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"ADMesh\s*--\s*process triangulated solid meshes",
        r"Questions,\s*comments,\s*suggestions.*github\.com/admesh/admesh/issues",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)README\.md$",
    ]
    RX_MAJOR = re.compile(
        r"m4_define\s*\(\s*\[admesh_version_major\]\s*,\s*\[(\d+)\]\s*\)",
        re.IGNORECASE,
    )
    RX_MINOR = re.compile(
        r"m4_define\s*\(\s*\[admesh_version_minor\]\s*,\s*\[(\d+)\]\s*\)",
        re.IGNORECASE,
    )
    RX_MICRO = re.compile(
        r"m4_define\s*\(\s*\[admesh_version_micro\]\s*,\s*\[(\d+)\]\s*\)",
        re.IGNORECASE,
    )
    RX_SUFFIX = re.compile(
        r"m4_define\s*\(\s*\[admesh_version_suffix\]\s*,\s*\[([^\]]*)\]\s*\)",
        re.IGNORECASE,
    )
    RX_README = re.compile(
        r"Grab the ([0-9]+\.[0-9]+(?:\.[0-9]+)?) tarball",
        re.IGNORECASE,
    )

    def _extract_configure_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_MICRO.search(s)
        if not (a and b and c):
            return None
        ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        suf = self.RX_SUFFIX.search(s)
        if suf and suf.group(1).strip():
            ver += suf.group(1).strip()
        return ver

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        m = self.RX_README.search(content or "")
        if not m:
            return []
        src_abs = os.path.abspath(path)
        return [
            self.make_result(m.group(1), src_abs, extra={"version_source_abs": src_abs})
        ]

    def check_meta(self, directory: str):
        for name in ("configure.ac", "configure.in"):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            ver = self._extract_configure_version(text)
            if ver:
                return [
                    self.make_result(
                        ver,
                        os.path.abspath(full),
                        extra={
                            "version_source_abs": os.path.abspath(full),
                            "origin": f"meta:{name}",
                        },
                    )
                ]
        readme = os.path.join(directory, "README.md")
        if os.path.isfile(readme):
            try:
                with open(readme, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                return []
            m = self.RX_README.search(text)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        os.path.abspath(readme),
                        extra={
                            "version_source_abs": os.path.abspath(readme),
                            "origin": "meta:README.md",
                        },
                    )
                ]
        return []
