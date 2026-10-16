import json
import os
from checkers.base_checker import BaseChecker


class Openvino(BaseChecker):
    VENDOR = "intel"
    PRODUCT = "openvino"
    LINK_SOURCE = "https://github.com/openvinotoolkit/openvino.git"
    CONTAINS_PATTERNS = [
        r"OPENVINO_ASSERT",
    ]

    def _extract_version(self, text: str):
        try:
            data = json.loads(text or "")
        except Exception:
            return None
        name = str(data.get("name", "")).lower()
        if "openvino" not in name:
            return None
        for key in ("version", "version-string", "version-semver"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def check_meta(self, directory: str):
        full = os.path.join(directory, "vcpkg.json")
        if not os.path.isfile(full):
            return []
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except Exception:
            return []
        ver = self._extract_version(text)
        if not ver:
            return []
        return [
            self.make_result(
                ver,
                full,
                extra={
                    "version_source_abs": full,
                    "origin": "meta:vcpkg.json",
                },
            )
        ]
