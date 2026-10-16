import os
import re
from checkers.base_checker import BaseChecker


class Libvorbis(BaseChecker):
    VENDOR = "xiph"
    PRODUCT = "libvorbis"
    LINK_SOURCE = "https://github.com/xiph/vorbis"
    CONTAINS_PATTERNS = [
        r"#include\s+[\"<]vorbis/codec\.h[>\"]",
        r"vorbis_info_init\b",
        r"OGG_VORBIS_API\b",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)CMakeLists\.txt$",
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\(\s*\[libvorbis\]\s*,\s*\[([0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9._]+)?)\]",
    ]

    def check_meta(self, directory: str):
        configure_ac_path = os.path.join(directory, "configure.ac")
        if not os.path.isfile(configure_ac_path):
            return []
        try:
            with open(configure_ac_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []
        m = re.search(
            r"AC_INIT\(\s*\[libvorbis\]\s*,\s*\[([0-9]+(?:\.[0-9]+){1,3}(?:-[A-Za-z0-9._]+)?)\]",
            content,
        )
        if not m:
            return []
        path_abs = os.path.abspath(configure_ac_path)
        return [
            self.make_result(
                m.group(1),
                path_abs,
                extra={
                    "version_source_abs": path_abs,
                    "origin": "meta:configure.ac",
                },
            )
        ]
