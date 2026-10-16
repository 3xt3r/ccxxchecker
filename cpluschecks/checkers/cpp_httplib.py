import re
from checkers.base_checker import BaseChecker


class CppHttplib(BaseChecker):
    VENDOR = "yhirose"
    PRODUCT = "httplib"
    LINK_SOURCE = "https://github.com/yhirose/cpp-httplib.git"
    TAG_TEMPLATE = "v{version}"
    CPE_TEMPLATE = "cpe:2.3:a:yhirose:cpp-httplib:{version}:*:*:*:*:*:*:*"
    STOP_AFTER_FIRST_VERSION = True

    # Каталог, где лежит httplib.h, становится кандидатом в корень компонента.
    ROOT_ANCHOR_PATHS = ("httplib.h",)

    CONTAINS_PATTERNS = [
        r"//\s*httplib\.h\s*\n//\s*\n//\s*Copyright \(c\) \d{4} Yuji Hirose",
        r"#\s*define\s+CPPHTTPLIB_HTTPLIB_H\b",
    ]

    # Версия есть в самом заголовке начиная с v0.11.0; в более старых
    # релизах её нет, они получат name@unknown.
    SOURCE_FILENAME_PATTERNS = [r"(^|/)httplib\.h$"]
    VERSION_PATTERNS = [
        r'#\s*define\s+CPPHTTPLIB_VERSION\s+"([0-9]+(?:\.[0-9]+){1,3})"',
    ]
    VERSION_GUARD_PATTERNS = [r"CPPHTTPLIB_HTTPLIB_H"]
