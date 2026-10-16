import os
import re
from checkers.base_checker import BaseChecker


class Suricata(BaseChecker):
    VENDOR = "oisf"
    PRODUCT = "suricata"
    LINK_SOURCE = "https://github.com/OISF/suricata.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r'\bPROG_NAME\s+"Suricata"',
        r'This is %s version %s\\n", PROG_NAME, GetProgramVersion\(',
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)src/suricata\.c$",
        r"(^|/)src/suricata\.h$",
        r"^suricata\.c$",
        r"^suricata\.h$",
        r"(^|/)src/suricata-version\.h\.in$",
        r"(^|/)src/suricata-version\.h$",
    ]
    RX_PROG = re.compile(
        r'#\s*define\s+PROG_VER\s+"([^"]+)"',
        re.IGNORECASE,
    )
    RX_CONFIG = re.compile(
        r'#\s*define\s+PACKAGE_NAME\s+"suricata".*?'
        r'#\s*define\s+PACKAGE_VERSION\s+"([^"]+)"',
        re.IGNORECASE | re.DOTALL,
    )
    RX_AC = re.compile(
        r"AC_INIT\(\s*\[suricata\]\s*,\s*\[([0-9]+(?:\.[0-9]+){1,3}(?:-[^\]]+)?)\]",
        re.IGNORECASE,
    )
    RX_VERSION_H = re.compile(
        r'#\s*define\s+(?:SURICATA_VERSION|PACKAGE_VERSION)\s+"([^"]+)"',
        re.IGNORECASE,
    )

    def _extract_source_version(self, text: str):
        s = text or ""
        m = (
            self.RX_PROG.search(s)
            or self.RX_CONFIG.search(s)
            or self.RX_VERSION_H.search(s)
        )
        return m.group(1) if m else None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_source_version(content)
        if not ver:
            return []
        full = os.path.abspath(path)
        return [self.make_result(ver, full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        full = os.path.join(directory, "configure.ac")
        if os.path.isfile(full):
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                text = None
            if text:
                m = self.RX_AC.search(text)
                if m:
                    return [
                        self.make_result(
                            m.group(1),
                            os.path.abspath(full),
                            extra={
                                "version_source_abs": os.path.abspath(full),
                                "origin": "meta:configure.ac",
                            },
                        )
                    ]
        for rel in (
            os.path.join("src", "suricata-version.h.in"),
            os.path.join("src", "suricata-version.h"),
        ):
            full = os.path.join(directory, rel)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            m = self.RX_VERSION_H.search(text)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        os.path.abspath(full),
                        extra={
                            "version_source_abs": os.path.abspath(full),
                            "origin": f"meta:{rel.replace(os.sep, '/')}",
                        },
                    )
                ]
        return []
