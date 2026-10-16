import os
import re
from checkers.base_checker import BaseChecker


class Cicap(BaseChecker):
    VENDOR = "c-icap_project"
    PRODUCT = "c-icap"
    LINK_SOURCE = "https://github.com/c-icap/c-icap-server.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
        r"(^|/)VERSION\.m4$",
        r"(^|/)include/c-icap-conf\.h$",
    ]
    CONTAINS_PATTERNS = [
        r"Copyright\s*\(C\)\s*(?:\d{4}(?:-\d{4})?\s+)?Christos\s+Tsantilas",
        r"Can\s+not\s+execute\s+ci_command_register_action",
        r"AC_INIT\(\s*\[?c.icap\]?",
    ]
    RX_VERSION_M4 = re.compile(
        r"([0-9]{1,4}(?:\.[0-9]+){1,3}[A-Za-z0-9]*|[0-9]{6}[A-Za-z0-9]*)"
    )
    RX_AC_INIT = re.compile(
        r"AC_INIT\(\s*\[?c.icap\]?\s*,\s*\[([0-9]+(?:\.[0-9]+){1,3})\]",
        re.IGNORECASE,
    )
    RX_HEX_VERSION = re.compile(
        r"#\s*define\s+C_ICAP_HEX_VERSION\s+0x([0-9A-Fa-f]{12})"
    )

    def _decode_hex_version(self, hex_str: str):
        try:
            val = int(hex_str, 16)
        except ValueError:
            return None
        major = (val >> 32) & 0xFFFF
        minor = (val >> 16) & 0xFFFF
        patch = val & 0xFFFF
        return f"{major}.{minor}.{patch}"

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        src_abs = os.path.abspath(path)
        base = os.path.basename(path)
        if base.upper() == "VERSION.M4":
            m = self.RX_VERSION_M4.search(s)
            if m:
                return [
                    self.make_result(
                        m.group(1), src_abs, extra={"version_source_abs": src_abs}
                    )
                ]
            return []
        if base == "c-icap-conf.h":
            m = self.RX_HEX_VERSION.search(s)
            if m:
                ver = self._decode_hex_version(m.group(1))
                if ver:
                    return [
                        self.make_result(
                            ver, src_abs, extra={"version_source_abs": src_abs}
                        )
                    ]
            return []
        m = self.RX_AC_INIT.search(s)
        if not m:
            return []
        return [
            self.make_result(m.group(1), src_abs, extra={"version_source_abs": src_abs})
        ]

    def check_meta(self, directory: str):
        conf_h = os.path.join(directory, "include", "c-icap-conf.h")
        if os.path.isfile(conf_h):
            try:
                with open(conf_h, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                text = ""
            m = self.RX_HEX_VERSION.search(text)
            if m:
                ver = self._decode_hex_version(m.group(1))
                if ver:
                    return [
                        self.make_result(
                            ver,
                            os.path.abspath(conf_h),
                            extra={
                                "version_source_file": os.path.relpath(
                                    conf_h, directory
                                ),
                                "origin": "meta:include/c-icap-conf.h",
                            },
                        )
                    ]
        version_m4 = os.path.join(directory, "VERSION.m4")
        if os.path.isfile(version_m4):
            try:
                with open(version_m4, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except OSError:
                text = ""
            m = self.RX_VERSION_M4.search(text)
            if m:
                return [
                    self.make_result(
                        m.group(1),
                        os.path.abspath(version_m4),
                        extra={
                            "version_source_file": os.path.relpath(
                                version_m4, directory
                            ),
                            "origin": "meta:VERSION.m4",
                        },
                    )
                ]
        full = os.path.join(directory, "configure.ac")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        m = self.RX_AC_INIT.search(text)
        if not m:
            return []
        return [
            self.make_result(
                m.group(1),
                os.path.abspath(full),
                extra={
                    "version_source_file": os.path.relpath(full, directory),
                    "origin": "meta:configure.ac",
                },
            )
        ]
