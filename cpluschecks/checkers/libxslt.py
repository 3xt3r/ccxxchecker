from checkers.base_checker import BaseChecker
import os


class Libxslt(BaseChecker):
    VENDOR = "xmlsoft"
    PRODUCT = "libxslt"
    LINK_SOURCE = "https://github.com/GNOME/libxslt"
    CONTAINS_PATTERNS = [
        r"libxslt",
        r"XSLT",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)CMakeLists\.txt$",
    ]
    VERSION_PATTERNS = [
        r"m4_define\(\[(MAJOR|MINOR|MICRO)_VERSION\],\s*\[([0-9]+)\]\)",
        r"LIBXSLT_(MAJOR|MINOR|MICRO)_VERSION=([0-9]+)",
    ]

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        major = None
        minor = None
        micro = None
        import re

        m4_pattern = r"m4_define\(\[(MAJOR|MINOR|MICRO)_VERSION\],\s*\[([0-9]+)\]\)"
        for match in re.finditer(m4_pattern, s):
            version_type = match.group(1)
            version_value = match.group(2)
            if version_type == "MAJOR":
                major = version_value
            elif version_type == "MINOR":
                minor = version_value
            elif version_type == "MICRO":
                micro = version_value
        libxslt_pattern = r"LIBXSLT_(MAJOR|MINOR|MICRO)_VERSION=([0-9]+)"
        for match in re.finditer(libxslt_pattern, s):
            version_type = match.group(1)
            version_value = match.group(2)
            if version_type == "MAJOR":
                major = version_value
            elif version_type == "MINOR":
                minor = version_value
            elif version_type == "MICRO":
                micro = version_value
        if major and minor and micro:
            version = f"{major}.{minor}.{micro}"
            return [
                self.make_result(
                    version, src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        cmake_pattern = r"set\(LIBXSLT_(MAJOR|MINOR|MICRO)_VERSION\s+([0-9]+)\)"
        cmake_major = None
        cmake_minor = None
        cmake_micro = None
        for match in re.finditer(cmake_pattern, s):
            version_type = match.group(1)
            version_value = match.group(2)
            if version_type == "MAJOR":
                cmake_major = version_value
            elif version_type == "MINOR":
                cmake_minor = version_value
            elif version_type == "MICRO":
                cmake_micro = version_value
        if cmake_major and cmake_minor and cmake_micro:
            version = f"{cmake_major}.{cmake_minor}.{cmake_micro}"
            return [
                self.make_result(
                    version, src_abs, extra={"version_source_abs": src_abs}
                )
            ]
        return []
