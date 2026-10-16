import os
import re
from checkers.base_checker import BaseChecker


class Libredwg(BaseChecker):
    VENDOR = "gnu"
    PRODUCT = "libredwg"
    LINK_SOURCE = "https://github.com/LibreDWG/libredwg"
    CONTAINS_PATTERNS = [
        r"LibreDWG",
        r"free implementation of the DWG file format",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)CMakeLists\.txt$",
        r"(^|/)include/dwg\.h$",
    ]
    RX_MAJOR = re.compile(r"#define\s+LIBREDWG_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+LIBREDWG_VERSION_MINOR\s+(\d+)")
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\s*\[libredwg\]\s*,\s*\[([^\]]+)\]",
        re.IGNORECASE,
    )

    def _extract_version(self, text: str):
        s = text or ""
        a = self.RX_MAJOR.search(s)
        b = self.RX_MINOR.search(s)
        if a and b:
            return f"{a.group(1)}.{b.group(1)}"
        return None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "include", "dwg.h")
        if os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                pass
            else:
                ver = self._extract_version(text)
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(full),
                            extra={
                                "version_source_abs": os.path.abspath(full),
                                "origin": "meta:include/dwg.h",
                            },
                        )
                    ]
        full = os.path.join(directory, "configure.ac")
        if os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                pass
            else:
                m = self.RX_AC_INIT.search(text)
                if m:
                    return [
                        self.make_result(
                            m.group(1).strip(),
                            os.path.abspath(full),
                            extra={
                                "version_source_abs": os.path.abspath(full),
                                "origin": "meta:configure.ac",
                            },
                        )
                    ]
        full = os.path.join(directory, "CMakeLists.txt")
        if os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                pass
            else:
                if "libredwg" in text.lower():
                    m = re.search(
                        r'set\(.*?PACKAGE_VERSION\s+"([^"]+)"', text, re.IGNORECASE
                    )
                    if m:
                        return [
                            self.make_result(
                                m.group(1),
                                os.path.abspath(full),
                                extra={
                                    "version_source_abs": os.path.abspath(full),
                                    "origin": "meta:CMakeLists.txt",
                                },
                            )
                        ]
        return []
