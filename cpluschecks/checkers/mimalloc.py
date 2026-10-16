import os
import re
from checkers.base_checker import BaseChecker


class Mimalloc(BaseChecker):
    VENDOR = "microsoft"
    PRODUCT = "mimalloc"
    LINK_SOURCE = "https://github.com/microsoft/mimalloc"
    CONTAINS_PATTERNS = [
        r"Compact general purpose allocator with excellent performance",
        r"mi_heap_t\s*\*\s*mi_heap_new",
        r"Copyright.*Microsoft.*mimalloc",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)CMakeLists\.txt$",
        r"(^|/)contrib/vcpkg/vcpkg\.json$",
    ]
    RX_VCPKG_NAME = re.compile(r'"name"\s*:\s*"mimalloc"')
    RX_VCPKG_VERSION = re.compile(r'"version(?:-string)?"\s*:\s*"([^"]+)"')
    RX_CMAKE_PROJECT = re.compile(
        r"project\s*\(\s*(?:lib)?mimalloc[^)]*VERSION\s+([0-9]+(?:\.[0-9]+){1,3})",
        re.IGNORECASE,
    )
    RX_MI_VERSION = re.compile(r"#define\s+MI_MALLOC_VERSION\s+(\d+)")

    def _parse_mi_version(self, num_str: str):
        try:
            n = int(num_str)
            major = n // 100
            minor = n % 100
            return f"{major}.{minor}.0"
        except Exception:
            return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        if "vcpkg.json" in path:
            if not self.RX_VCPKG_NAME.search(s):
                return []
            m = self.RX_VCPKG_VERSION.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        if "CMakeLists.txt" in path:
            m = self.RX_CMAKE_PROJECT.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
            m = self.RX_MI_VERSION.search(s)
            if m:
                ver = self._parse_mi_version(m.group(1))
                if ver:
                    return [
                        self.make_result(
                            ver, src_abs, extra={"version_source_abs": src_abs}
                        )
                    ]
        return []

    def check_meta(self, directory: str):
        vcpkg_path = os.path.join(directory, "contrib", "vcpkg", "vcpkg.json")
        if os.path.isfile(vcpkg_path):
            try:
                with open(vcpkg_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if self.RX_VCPKG_NAME.search(content):
                    m = self.RX_VCPKG_VERSION.search(content)
                    if m:
                        return [
                            self.make_result(
                                m.group(1),
                                os.path.abspath(vcpkg_path),
                                extra={
                                    "version_source_abs": os.path.abspath(vcpkg_path),
                                    "origin": "meta:contrib/vcpkg/vcpkg.json",
                                },
                            )
                        ]
            except Exception:
                pass
        cmake = os.path.join(directory, "CMakeLists.txt")
        if os.path.isfile(cmake):
            try:
                with open(cmake, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                m = self.RX_CMAKE_PROJECT.search(content)
                if m:
                    return [
                        self.make_result(
                            m.group(1),
                            os.path.abspath(cmake),
                            extra={
                                "version_source_abs": os.path.abspath(cmake),
                                "origin": "meta:CMakeLists.txt",
                            },
                        )
                    ]
                m = self.RX_MI_VERSION.search(content)
                if m:
                    ver = self._parse_mi_version(m.group(1))
                    if ver:
                        return [
                            self.make_result(
                                ver,
                                os.path.abspath(cmake),
                                extra={
                                    "version_source_abs": os.path.abspath(cmake),
                                    "origin": "meta:CMakeLists.txt",
                                },
                            )
                        ]
            except Exception:
                pass
        return []
