from checkers.base_checker import BaseChecker


class Clickhouse(BaseChecker):
    VENDOR = "yandex"
    PRODUCT = "clickhouse"
    LINK_SOURCE = "https://github.com/ClickHouse/ClickHouse.git"
    CONTAINS_PATTERNS = [
        r"clickhouse\.cloud",
        r"CLICKHOUSE_VERSION_STRING",
        r"#include\s+[\"<]Common/ClickHouseRevision\.h[>\"]",
    ]
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)CHANGELOG\.md$",
    ]
    VERSION_PATTERNS = [
        r"ClickHouse\s+release\s+v?([0-9]+(?:\.[0-9]+){1,2})\b",
    ]
