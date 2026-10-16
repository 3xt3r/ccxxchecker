from checkers.base_checker import BaseChecker
import os, re


class Libogg(BaseChecker):
    VENDOR = "xiph"
    PRODUCT = "libogg"
    LINK_SOURCE = "https://github.com/eidy/libogg"
    CONTAINS_PATTERNS = [
        r"Ogg bitstream format",
        r"Xiph\.Org Foundation",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)CMakeLists\.txt$",
    ]
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\s*\[libogg\]\s*,\s*\[([0-9]+(?:\.[0-9]+){1,3})\]",
        re.IGNORECASE,
    )
    RX_CMAKE_PROJECT = re.compile(
        r"project\s*\(\s*(?:lib)?ogg[^)]*VERSION\s+([0-9]+(?:\.[0-9]+){1,3})",
        re.IGNORECASE,
    )
    RX_CMAKE_VERSION = re.compile(
        r"set\s*\(\s*PROJECT_VERSION\s+([0-9]+(?:\.[0-9]+){1,3})\s*\)",
        re.IGNORECASE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        src_abs = os.path.abspath(path)
        base = os.path.basename(path).lower()
        s = content or ""
        if base == "configure.ac":
            m = self.RX_AC_INIT.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
        elif base == "cmakelists.txt":
            m = self.RX_CMAKE_PROJECT.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
            if "libogg" in s.lower():
                m = self.RX_CMAKE_VERSION.search(s)
                if m:
                    return [
                        self.make_result(
                            m.group(1), src_abs, extra={"version_source_abs": src_abs}
                        )
                    ]
        return []
