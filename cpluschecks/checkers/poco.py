import os
import re
from checkers.base_checker import BaseChecker


class Poco(BaseChecker):
    VENDOR = "pocoproject"
    PRODUCT = "poco"
    LINK_SOURCE = "https://github.com/pocoproject/poco.git"
    TAG_TEMPLATE = "poco-{version}-release"
    RX_RC = re.compile(r'#define\s+POCO_VERSION_STR\s+"([\w.\-]+)"')
    RX_VER = re.compile(r"^[vV]?\d+(?:\.\d+){1,4}(?:[-+][0-9A-Za-z._-]+)?$")

    def _read_version_text(self, text: str):
        v = (text or "").strip().splitlines()[0].strip().strip('"').strip("'")
        return v if v and len(v) <= 64 and self.RX_VER.match(v) else None

    def check_file_versions_only(self, content: str, path: str):
        full = os.path.abspath(path)
        norm = full.replace("\\", "/")
        base = os.path.basename(norm).lower()
        if base == "dllversion.rc":
            m = self.RX_RC.search(content or "")
            return (
                [
                    self.make_result(
                        m.group(1).strip(), full, extra={"version_source_abs": full}
                    )
                ]
                if m
                else []
            )
        if (
            base == "version"
            and os.path.basename(os.path.dirname(norm)).lower() == "poco"
        ):
            v = self._read_version_text(content)
            return (
                [self.make_result(v, full, extra={"version_source_abs": full})]
                if v
                else []
            )
        return []

    def check_file_contains_only(self, content: str, path: str):
        return []

    def check_meta(self, directory: str):
        if os.path.basename(directory).lower() != "poco":
            return []
        full = os.path.join(directory, "VERSION")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                v = self._read_version_text(f.read())
        except Exception:
            return []
        if not v:
            return []
        return [
            self.make_result(
                v,
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:poco/VERSION",
                },
            )
        ]
