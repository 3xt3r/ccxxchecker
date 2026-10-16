from checkers.base_checker import BaseChecker


class Libpcap(BaseChecker):
    VENDOR = "tcpdump"
    PRODUCT = "libpcap"
    LINK_SOURCE = "https://github.com/the-tcpdump-group/libpcap.git"
    TAG_TEMPLATE = "libpcap-{version}"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)VERSION$",
    ]
    VERSION_PATTERNS = [
        r"^\s*v?([0-9]+(?:\.[0-9]+){1,3})\b",
    ]
    CONTAINS_PATTERNS = [
        r"Header\s+prepended\s+libpcap\s+to\s+each\s+bluetooth\s+h4\s+frame",
        r"\bPCAP_SOCKET\b.*\bcontrol\s+connection\b",
    ]
