from checkers.base_checker import BaseChecker


class Boost(BaseChecker):
    VENDOR = "boost"
    PRODUCT = "boost"
    LINK_SOURCE = "https://github.com/boostorg/boost.git"
    MONOREPO_SINGLETON = True
    ROOT_ANCHOR_PATHS = ("Jamroot",)
    CONTAINS_PATTERNS = [
        r"The Boost libraries requiring",
        r"boostinspect:notab",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)Jamroot$",
    ]
    VERSION_PATTERNS = [
        r"constant\s+BOOST_VERSION\s*:\s*([0-9]+\.[0-9]+\.[0-9]+)",
    ]
