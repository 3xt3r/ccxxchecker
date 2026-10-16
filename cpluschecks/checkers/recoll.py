from checkers.base_checker import BaseChecker


class Recoll(BaseChecker):
    VENDOR = "lesbonscomptes"
    PRODUCT = "recoll"
    LINK_SOURCE = "https://github.com/hamonikr/recoll"
    CONTAINS_PATTERNS = [
        r"Recoll is a desktop search tool",
        r"recoll\.org",
        r"#include\s+[\"<]recoll/",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)VERSION$",
        r"(^|/)configure\.ac$",
    ]
    VERSION_PATTERNS = [
        r"AC_INIT\(\s*\[Recoll\]\s*,\s*m4_esyscmd_s\(cat VERSION\)",
        r"^\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$",
    ]
