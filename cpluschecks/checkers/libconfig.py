import os
import re
from checkers.base_checker import BaseChecker


class LibConfig(BaseChecker):
    VENDOR = "libconfig"
    PRODUCT = "libconfig"
    LINK_SOURCE = "https://github.com/hyperrealm/libconfig.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)libconfig\.h$",
        r"(^|/)libconfig\.h\+\+$",
        r"(^|/)configure\.ac$",
    ]
    CONTAINS_PATTERNS = [
        (r"\bLIBCONFIG_VER_MAJOR\b", 0),
        (r"\bLIBCONFIG_VERSION\b", 0),
        (r"\bAC_INIT\(\[libconfig\]", re.IGNORECASE),
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\(\[libconfig\],\s*\[(\d+\.\d+\.\d+)\]",
        r'#define\s+LIBCONFIG_VERSION\s+"([^"]+)"',
    ]
    RX_MAJOR = re.compile(r"#define\s+LIBCONFIG_VER_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+LIBCONFIG_VER_MINOR\s+(\d+)")
    RX_REV = re.compile(r"#define\s+LIBCONFIG_VER_REVISION\s+(\d+)")

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        results = super().check_file_versions_only(content, path)
        if results:
            return results
        s = content or ""
        major = self.RX_MAJOR.search(s)
        minor = self.RX_MINOR.search(s)
        rev = self.RX_REV.search(s)
        if not (major and minor and rev):
            return []
        src_abs = os.path.abspath(path)
        ver = f"{major.group(1)}.{minor.group(1)}.{rev.group(1)}"
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]
