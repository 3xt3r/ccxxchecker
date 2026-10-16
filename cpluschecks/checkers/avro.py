from checkers.base_checker import BaseChecker


class Avro(BaseChecker):
    VENDOR = "apache"
    PRODUCT = "avro"
    LINK_SOURCE = "https://github.com/apache/avro"
    SOURCE_FILENAME_PATTERNS = [
        r"(?:^|/)avro[/_-]",
        r"(?:^|/)avro\.[ch](?:pp|xx)?$",
        r"(?:^|/)avro\.h$",
    ]
    VERSION_PATTERNS = [
        (
            r"^(\d+\.\d+\.\d+(?:-[A-Za-z0-9._-]+)?)\s*$",
            1,
        ),
    ]
    CONTAINS_PATTERNS = [
        r"void\s+avro_consumer_free\s*\(\s*avro_consumer_t\s*\*\s*consumer\s*\)",
        r"namespace\s+avro\s*\{",
    ]

    def check_meta(self, directory: str) -> list:
        import os

        results = []
        version_txt = os.path.join(directory, "VERSION.txt")
        if not os.path.isfile(version_txt):
            return results
        try:
            content = open(version_txt, "r", encoding="utf-8", errors="ignore").read()
        except Exception:
            return results
        hits = self.check_file_versions_only(content, version_txt)
        results.extend(hits)
        return results
