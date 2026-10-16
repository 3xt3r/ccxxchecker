from checkers.base_checker import BaseChecker


class Asn1c(BaseChecker):
    VENDOR = "asn1c_project"
    PRODUCT = "asn1c"
    LINK_SOURCE = "https://github.com/vlm/asn1c.git"
    CONTAINS_PATTERNS = [
        r"ASN\.1\s+Compiler",
        r"Abstract\s+Syntax\s+Notation\s+1",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\(\s*\[asn1c\]\s*,\s*\[([^\]]+)\]",
    ]
