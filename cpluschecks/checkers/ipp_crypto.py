import os
import re
from checkers.base_checker import BaseChecker


class CryptographyPrimitives(BaseChecker):
    VENDOR = "intel"
    PRODUCT = "cryptography_primitives"
    LINK_SOURCE = "https://github.com/intel/cryptography-primitives.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)include/ippcpversion\.h$",
        r"(^|/)ippcpversion\.h$",
        r"(^|/)README\.md$",
    ]
    RX_MAJOR = re.compile(r"#define\s+CRYPTO_LIB_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+CRYPTO_LIB_VERSION_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+CRYPTO_LIB_VERSION_PATCH\s+(\d+)")
    RX_VERSION_STR = re.compile(r'#define\s+CRYPTO_LIB_VERSION_STR\s+"([^"]+)"')
    RX_README = re.compile(
        r"Intel\(R\)\s+Cryptography\s+Primitives\s+Library\s+v?(\d+\.\d+\.\d+)",
        re.IGNORECASE,
    )

    def _extract_version(self, content: str):
        s = content or ""
        major = self.RX_MAJOR.search(s)
        minor = self.RX_MINOR.search(s)
        patch = self.RX_PATCH.search(s)
        if major and minor and patch:
            return f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
        m = self.RX_VERSION_STR.search(s)
        if m:
            m2 = re.match(r"(\d+\.\d+\.\d+)", m.group(1).strip())
            if m2:
                return m2.group(1)
        m = self.RX_README.search(s)
        if m:
            return m.group(1)
        return None

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        ver = self._extract_version(content)
        if not ver:
            return []
        src_abs = os.path.abspath(path)
        return [self.make_result(ver, src_abs, extra={"version_source_abs": src_abs})]
