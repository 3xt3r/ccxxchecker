import os
import re
from checkers.base_checker import BaseChecker


class CppIpc(BaseChecker):
    """cpp-ipc (libipc), https://github.com/mutouyun/cpp-ipc."""

    VENDOR = "mutouyun"
    PRODUCT = "cpp-ipc"
    LINK_SOURCE = "https://github.com/mutouyun/cpp-ipc.git"
    STOP_AFTER_FIRST_VERSION = True
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)CMakeLists\.txt$",
        r"(^|/)include/libipc/(?:ipc|channel|route|shm|buffer|def|mutex|semaphore|condition)\.h$",
        r"(^|/)libipc/(?:ipc|channel|route|shm|buffer|def|mutex|semaphore|condition)\.h$",
    ]
    # Only distinctive evidence; a generic ipc namespace or CMake 'project' is insufficient.
    CONTAINS_PATTERNS = [
        r"#\s*include\s*[<\"]libipc/ipc\.h[>\"]",
        r"#\s*include\s*[<\"]libipc/(?:channel|route|shm)\.h[>\"]",
        r"\bLIBIPC_BUILD_(?:TESTS|DEMOS|SHARED_LIBS)\b",
    ]
    RX_CMAKE_VERSION = re.compile(
        r"\bproject\s*\(\s*(?:cpp-ipc|libipc)\s+VERSION\s+"
        r"([0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?)\b",
        re.IGNORECASE | re.MULTILINE,
    )

    def check_file_versions_only(self, content: str, path: str):
        if os.path.basename(path).lower() != "cmakelists.txt":
            return []
        m = self.RX_CMAKE_VERSION.search(content or "")
        if not m:
            return []
        full = os.path.abspath(path)
        return [self.make_result(m.group(1), full, extra={"version_source_abs": full})]

    def check_meta(self, directory: str):
        path = os.path.join(directory, "CMakeLists.txt")
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            return []
        result = self.check_file_versions_only(content, path)
        for item in result:
            item["origin"] = "meta:CMakeLists.txt"
        return result
