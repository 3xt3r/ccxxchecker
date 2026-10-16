import os
import re
from checkers.base_checker import BaseChecker


class FFmpeg(BaseChecker):
    VENDOR = "ffmpeg"
    PRODUCT = "ffmpeg"
    LINK_SOURCE = "https://github.com/FFmpeg/FFmpeg.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)RELEASE$",
        r"(^|/)doc/Doxyfile$",
    ]
    CONTAINS_PATTERNS = [
        (r"\bThis file is part of FFmpeg\b", re.IGNORECASE),
    ]
    RX_RELEASE = re.compile(r"^(\d+\.\d+(?:\.\d+)?(?:\.git)?)$", re.MULTILINE)
    RX_DOXYFILE = re.compile(
        r"^PROJECT_NUMBER\s*=\s*(\d+\.\d+(?:\.\d+)?(?:\.git)?)$", re.MULTILINE
    )

    def check_meta(self, directory: str):
        release_file = os.path.join(directory, "RELEASE")
        if os.path.isfile(release_file):
            try:
                with open(release_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                content = ""
            m = self.RX_RELEASE.search(content)
            if m:
                src_abs = os.path.abspath(release_file)
                return [
                    self.make_result(
                        m.group(1),
                        src_abs,
                        extra={"version_source_abs": src_abs, "origin": "meta"},
                    )
                ]
        doxyfile = os.path.join(directory, "doc", "Doxyfile")
        if os.path.isfile(doxyfile):
            try:
                with open(doxyfile, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                content = ""
            m = self.RX_DOXYFILE.search(content)
            if m:
                src_abs = os.path.abspath(doxyfile)
                return [
                    self.make_result(
                        m.group(1),
                        src_abs,
                        extra={"version_source_abs": src_abs, "origin": "meta"},
                    )
                ]
        return []
