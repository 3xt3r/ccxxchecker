from checkers.base_checker import BaseChecker


class XapianCore(BaseChecker):
    VENDOR = "xapian"
    PRODUCT = "xapian-core"
    LINK_SOURCE = "https://github.com/easysoftware/xapian-core"
    CONTAINS_PATTERNS = [
        r"xapian_version_string\b",
        r"\bXAPHEAD\b",
        r"Copyright.*Olly Betts.*xapian",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)configure\.ac$",
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\(\s*\[xapian-core\]\s*,\s*\[([^\]]+)\]",
    ]
