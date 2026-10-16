import os
from checkers.base_checker import BaseChecker


class Dpdk(BaseChecker):
    VENDOR = "dpdk"
    PRODUCT = "data_plane_development_kit"
    LINK_SOURCE = "https://github.com/DPDK/dpdk.git"
    SOURCE_FILENAME_PATTERNS = [
        r"(^|/)VERSION$",
    ]
    CONTAINS_PATTERNS = [
        r"RTE_LOG_REGISTER_DEFAULT",
    ]
    VERSION_PATTERNS = [
        r"^\s*([0-9]+(?:\.[0-9]+){1,2}(?:[-._A-Za-z0-9]+)?)\s*$",
    ]

    def _looks_like_dpdk_root(self, directory: str) -> bool:
        try:
            present = set(os.listdir(directory))
        except Exception:
            return False
        strong_markers = {
            "app",
            "buildtools",
            "config",
            "drivers",
            "examples",
            "kernel",
            "lib",
            "usertools",
        }
        if len(strong_markers & present) >= 2:
            return True
        return "dpdk" in directory.replace("\\", "/").lower()

    def check_file_versions_only(self, content: str, path: str):
        if not self.match_source_filename(path):
            return []
        directory = os.path.dirname(os.path.abspath(path))
        if not self._looks_like_dpdk_root(directory):
            return []
        return super().check_file_versions_only(content, path)

    def check_file_contains_only(self, content: str, path: str):
        directory = os.path.dirname(os.path.abspath(path))
        if not self._looks_like_dpdk_root(directory):
            return []
        return super().check_file_contains_only(content, path)
