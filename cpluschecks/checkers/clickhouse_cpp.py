import os
import re
from checkers.base_checker import BaseChecker


class ClickhouseCPPChecker(BaseChecker):
    VENDOR = "yandex"
    PRODUCT = "clickhouse-cpp"
    LINK_SOURCE = "https://github.com/ClickHouse/clickhouse-cpp.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)clickhouse/version\.h$",
        r"(^|/)version\.h$",
    ]
    CONTAINS_PATTERNS = [
        r"\bCLICKHOUSE_CPP_VERSION_(?:MAJOR|MINOR|PATCH)\b",
    ]
    RX_MAJOR = re.compile(r"#define\s+CLICKHOUSE_CPP_VERSION_MAJOR\s+(\d+)")
    RX_MINOR = re.compile(r"#define\s+CLICKHOUSE_CPP_VERSION_MINOR\s+(\d+)")
    RX_PATCH = re.compile(r"#define\s+CLICKHOUSE_CPP_VERSION_PATCH\s+(\d+)")
    RX_BUILD = re.compile(r"#define\s+CLICKHOUSE_CPP_VERSION_BUILD\s+(\d+)")

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        s = content or ""
        major = self.RX_MAJOR.search(s)
        minor = self.RX_MINOR.search(s)
        patch = self.RX_PATCH.search(s)
        if not (major and minor and patch):
            return []
        build = self.RX_BUILD.search(s)
        if build and build.group(1) != "0":
            ver = f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}.{build.group(1)}"
        else:
            ver = f"{major.group(1)}.{minor.group(1)}.{patch.group(1)}"
        src_abs = os.path.abspath(path)
        return [
            self.make_result(
                ver, src_abs, extra={"version_source_abs": src_abs, "origin": "source"}
            )
        ]
