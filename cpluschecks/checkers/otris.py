from checkers.base_checker import BaseChecker


class Otris(BaseChecker):
    VENDOR = "totus-floreo"
    PRODUCT = "otris"
    LINK_SOURCE = "https://github.com/Totus-Floreo/otris"
    CONTAINS_PATTERNS = [
        r"otris is pretty logger",
        r"Open-Streaming-Solutions",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)go\.mod$",
    ]
    VERSION_PATTERNS = [
        r"module github\.com/Totus-Floreo/otris\s*$",
        r"github\.com/Totus-Floreo/otris\s+([0-9]+\.[0-9]+\.[0-9]+)",
    ]
