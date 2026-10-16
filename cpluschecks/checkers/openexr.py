import os
import re
from checkers.base_checker import BaseChecker


class Openexr(BaseChecker):
    VENDOR = "openexr"
    PRODUCT = "openexr"
    LINK_SOURCE = "https://github.com/AcademySoftwareFoundation/openexr"
    CONTAINS_PATTERNS = [
        r"#define\s+OPENEXR_VERSION_MAJOR\b",
        r"OPENEXR_IMF_INTERNAL_NAMESPACE\b",
        r"Imf::InputFile\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)openexr_version\.h$",
        r"(^|/)OpenEXRConfig\.h$",
    ]
    RX_MAJOR = re.compile(r"#define\s+OPENEXR_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+OPENEXR_VERSION_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+OPENEXR_VERSION_PATCH\s+(\d+)")
    RX_CMAKE_PROJECT = re.compile(
        r"project\s*\(\s*OpenEXR[^)]*VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        re.IGNORECASE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        c = self.RX_PATCH.search(s)
        if a and b and c:
            ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
            src_abs = os.path.abspath(path)
            return [
                self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})
            ]
        return []

    def check_meta(self, directory: str):
        version_h = os.path.join(
            directory, "src", "lib", "OpenEXRCore", "openexr_version.h"
        )
        if os.path.isfile(version_h):
            try:
                text = open(version_h, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
            else:
                a = self.RX_MAJOR.search(text)
                b = self.RX_MINOR.search(text)
                c = self.RX_PATCH.search(text)
                if a and b and c:
                    ver = f"{a.group(1)}.{b.group(1)}.{c.group(1)}"
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(version_h),
                            extra={
                                "version_source_abs": os.path.abspath(version_h),
                                "origin": "meta:src/lib/OpenEXRCore/openexr_version.h",
                            },
                        )
                    ]
        cmake = os.path.join(directory, "CMakeLists.txt")
        if os.path.isfile(cmake):
            try:
                text = open(cmake, "r", encoding="utf-8", errors="ignore").read()
            except Exception:
                pass
            else:
                m = self.RX_CMAKE_PROJECT.search(text)
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
        return []
