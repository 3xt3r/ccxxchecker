from checkers.base_checker import BaseChecker


class Highwayhash(BaseChecker):
    VENDOR = "google"
    PRODUCT = "highwayhash"
    LINK_SOURCE = "https://github.com/google/highwayhash.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)highwayhash/highwayhash_target\.cc$",
    ]
    CONTAINS_PATTERNS = [
        r"namespace\s+highwayhash\s*\{",
        r"\bHighwayHashCat\b",
    ]
