import os
import re
from checkers.base_checker import BaseChecker


class Flatbuffers(BaseChecker):
    VENDOR = "google"
    PRODUCT = "flatbuffers"
    LINK_SOURCE = "https://github.com/google/flatbuffers.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"namespace\s+flatbuffers\s*\{",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)MODULE\.bazel$",
        r"(^|/)goldens/cpp/basic_generated\.h$",
        r"(^|/)flatbuffers/base\.h$",
    ]
    RX_MODULE_BLOCK = re.compile(
        r"\bmodule\s*\((?P<body>.*?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    RX_MODULE_NAME = re.compile(r'\bname\s*=\s*"flatbuffers"', re.IGNORECASE)
    RX_MODULE_VERSION = re.compile(
        r'\bversion\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', re.IGNORECASE
    )
    RX_MAJOR = re.compile(r"FLATBUFFERS_VERSION_MAJOR\s*==\s*(\d+)")
    RX_MINOR = re.compile(r"FLATBUFFERS_VERSION_MINOR\s*==\s*(\d+)")
    RX_PATCH = re.compile(r"FLATBUFFERS_VERSION_REVISION\s*==\s*(\d+)")
    RX_BASE_MAJOR = re.compile(r"#define\s+FLATBUFFERS_VERSION_MAJOR\s+(\d+)")
    RX_BASE_MINOR = re.compile(r"#define\s+FLATBUFFERS_VERSION_MINOR\s+(\d+)")
    RX_BASE_PATCH = re.compile(r"#define\s+FLATBUFFERS_VERSION_REVISION\s+(\d+)")
    RX_CMAKE_MAJOR = re.compile(r"set\s*\(\s*VERSION_MAJOR\s+(\d+)\s*\)", re.IGNORECASE)
    RX_CMAKE_MINOR = re.compile(r"set\s*\(\s*VERSION_MINOR\s+(\d+)\s*\)", re.IGNORECASE)
    RX_CMAKE_PATCH = re.compile(r"set\s*\(\s*VERSION_PATCH\s+(\d+)\s*\)", re.IGNORECASE)

    def _extract_module_version(self, text: str):
        for m in self.RX_MODULE_BLOCK.finditer(text or ""):
            body = m.group("body")
            if not self.RX_MODULE_NAME.search(body):
                continue
            vm = self.RX_MODULE_VERSION.search(body)
            if vm:
                return vm.group(1)
        return None

    def _extract_cmake_version(self, text: str):
        s = text or ""
        a = self.RX_CMAKE_MAJOR.search(s)
        b = self.RX_CMAKE_MINOR.search(s)
        c = self.RX_CMAKE_PATCH.search(s)
        if a and b and c:
            return f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        text = content or ""
        full = os.path.abspath(path)
        norm = path.replace("\\", "/")
        if norm.endswith("MODULE.bazel"):
            ver = self._extract_module_version(text)
            if ver:
                return [self.make_result(ver, full, extra={"version_source_abs": full})]
            return []
        if norm.endswith("flatbuffers/base.h"):
            a = self.RX_BASE_MAJOR.search(text)
            b = self.RX_BASE_MINOR.search(text)
            c = self.RX_BASE_PATCH.search(text)
            if a and b and c:
                ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
                return [self.make_result(ver, full, extra={"version_source_abs": full})]
            return []
        m1 = self.RX_MAJOR.search(text)
        m2 = self.RX_MINOR.search(text)
        m3 = self.RX_PATCH.search(text)
        if m1 and m2 and m3:
            ver = f"{m1.group(1)}.{m2.group(1)}.{m3.group(1)}"
            return [self.make_result(ver, full, extra={"version_source_abs": full})]
        return []

    def check_meta(self, directory: str):
        bazel = os.path.join(directory, "MODULE.bazel")
        if os.path.isfile(bazel):
            try:
                text = open(bazel, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
            else:
                ver = self._extract_module_version(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(bazel),
                            extra={
                                "version_source_abs": os.path.abspath(bazel),
                                "origin": "meta:MODULE.bazel",
                            },
                        )
                    ]
        cmake = os.path.join(directory, "CMake", "Version.cmake")
        if os.path.isfile(cmake):
            try:
                text = open(cmake, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
            else:
                ver = self._extract_cmake_version(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(cmake),
                            extra={
                                "version_source_abs": os.path.abspath(cmake),
                                "origin": "meta:CMake/Version.cmake",
                            },
                        )
                    ]
        return []
