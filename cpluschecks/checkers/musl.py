from checkers.base_checker import BaseChecker


class Musl(BaseChecker):
    VENDOR = "musl-libc"
    PRODUCT = "musl"
    LINK_SOURCE = "https://github.com/kraj/musl"
    CONTAINS_PATTERNS = [
        r"musl libc \(libc\.musl",
        r"Copyright.*Rich Felker.*musl",
        r"^musl as a replacement",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)VERSION$",
    ]
    VERSION_PATTERNS = [
        r"^([0-9]+\.[0-9]+\.[0-9]+)$",
    ]
