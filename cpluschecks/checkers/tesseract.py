import os
import re
from checkers.base_checker import BaseChecker


class Tesseract(BaseChecker):
    VENDOR = "tesseract_project"
    PRODUCT = "tesseract"
    LINK_SOURCE = "https://github.com/tesseract-ocr/tesseract.git"
    STOP_AFTER_FIRST_VERSION = True
    CONTAINS_PATTERNS = [
        r"\bnamespace\s+tesseract\b",
    ]
    RX_VERSION = re.compile(r"^\s*V?(\d+\.\d+\.\d+)\s*$", re.MULTILINE)
    RX_CHANGELOG = re.compile(
        r"^\d{4}-\d{2}-\d{2}\s*-\s*V(\d+\.\d+\.\d+)", re.MULTILINE
    )

    def check_meta(self, directory: str):
        d = (directory or "").replace("\\", "/").lower()
        if "tesseract" not in d:
            return []
        for name, rx in (
            ("VERSION", self.RX_VERSION),
            ("ChangeLog", self.RX_CHANGELOG),
        ):
            full = os.path.join(directory, name)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue
            m = rx.search(text or "")
            if not m:
                continue
            return [
                self.make_result(
                    m.group(1).strip(),
                    os.path.abspath(full),
                    extra={
                        "version_source_abs": os.path.abspath(full),
                        "origin": f"meta:{name}",
                    },
                )
            ]
        return []
