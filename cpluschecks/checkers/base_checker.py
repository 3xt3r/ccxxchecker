import os
import re
from typing import List, Iterable, Tuple, Pattern, Union, Optional, Dict, Set

RegexSpec = Union[
    str,
    Pattern,
    Tuple[str, int],
    Tuple[str, re.RegexFlag],
    Tuple[str, int, re.RegexFlag],
]


class BaseChecker:
    CONTAINS_PATTERNS: List[RegexSpec] = []
    VERSION_PATTERNS: List[RegexSpec] = []
    VERSION_GUARD_PATTERNS: List[RegexSpec] = []
    VENDOR: str = ""
    PRODUCT: str = ""
    LINK_SOURCE: str = ""
    TAG_TEMPLATE: str = ""
    STOP_AFTER_FIRST_VERSION: bool = True
    CPE_TEMPLATE: str = "cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    PREFER_SOURCE_FILENAMES: bool = True
    SOURCE_FILENAME_PATTERNS: List[str] = []
    MONOREPO_SINGLETON: bool = False
    ROOT_ANCHOR_PATHS: Tuple[str, ...] = ()
    ROOT_ANCHOR_MAX_UP: int = 12
    META_PROVES_IDENTITY: bool = False
    VERSION_PROVES_IDENTITY: bool = False

    def __init__(self) -> None:
        self.signature_reported: bool = False
        self._compiled_contains: List[Tuple[Pattern, int]] = self._compile_specs(
            self.CONTAINS_PATTERNS,
            default_flags=re.IGNORECASE,
        )
        self._compiled_versions: List[Tuple[Pattern, int]] = self._compile_specs(
            self.VERSION_PATTERNS,
            default_flags=re.IGNORECASE,
        )
        self._compiled_version_guards: List[Tuple[Pattern, int]] = self._compile_specs(
            self.VERSION_GUARD_PATTERNS,
            default_flags=re.IGNORECASE,
        )
        self._compiled_source_name_patterns: Optional[List[Pattern]] = None

    @staticmethod
    def _validate_group_idx(group_idx: int) -> int:
        if not isinstance(group_idx, int) or group_idx < 1:
            raise ValueError(f"Invalid regex group index: {group_idx!r}")
        return group_idx

    @classmethod
    def _compile_specs(
        cls,
        specs: Iterable[RegexSpec],
        default_flags: re.RegexFlag = 0,
    ) -> List[Tuple[Pattern, int]]:
        out: List[Tuple[Pattern, int]] = []
        for spec in specs:
            group_idx = 1
            flags: re.RegexFlag = default_flags
            if isinstance(spec, tuple):
                if len(spec) == 2:
                    pattern, second = spec
                    if isinstance(second, re.RegexFlag):
                        flags = second
                    elif isinstance(second, int):
                        if second == 0:
                            flags = re.RegexFlag(0)
                        else:
                            group_idx = cls._validate_group_idx(second)
                    else:
                        raise ValueError(f"Unsupported second tuple item: {second!r}")
                    pat = re.compile(pattern, flags)
                elif len(spec) == 3:
                    pattern, group_idx, flags = spec
                    group_idx = cls._validate_group_idx(group_idx)
                    if not isinstance(flags, (int, re.RegexFlag)):
                        raise ValueError(f"Unsupported regex flags: {flags!r}")
                    pat = re.compile(pattern, flags)
                else:
                    raise ValueError("Unsupported regex spec tuple length")
            elif isinstance(spec, str):
                pat = re.compile(spec, default_flags)
            else:
                pat = spec
            out.append((pat, group_idx))
        return out

    def _compile_source_name_patterns(self) -> List[Pattern]:
        pats: List[Pattern] = []
        for p in getattr(self, "SOURCE_FILENAME_PATTERNS", []) or []:
            pats.append(re.compile(p, re.IGNORECASE))
        return pats

    def match_source_filename(self, path: str) -> bool:
        if not getattr(self, "SOURCE_FILENAME_PATTERNS", None):
            return False
        if self._compiled_source_name_patterns is None:
            self._compiled_source_name_patterns = self._compile_source_name_patterns()
        norm = (path or "").replace("\\", "/")
        for rx in self._compiled_source_name_patterns:
            if rx.search(norm):
                return True
        return False

    def reset(self) -> None:
        self.signature_reported = False

    _CPE_ESCAPE_MAP = {
        "\\": r"\\",
        ":": r"\:",
        "?": r"\?",
        "*": r"\*",
    }

    @classmethod
    def _cpe_escape(cls, s: str) -> str:
        return "".join(cls._CPE_ESCAPE_MAP.get(ch, ch) for ch in (s or ""))

    def make_result(
        self, version: Optional[str], source_path: str, extra: Optional[Dict] = None
    ) -> Dict:
        ver = (version or "unknown").strip()
        cpe_ver = "*" if ver.lower() == "unknown" else self._cpe_escape(ver)
        vendor_norm = self._cpe_escape((self.VENDOR or "").lower())
        product_norm = self._cpe_escape((self.PRODUCT or "").lower())
        out: Dict = {
            "name": self.PRODUCT,
            "version": ver,
            "cpe": self.CPE_TEMPLATE.format(
                vendor=vendor_norm,
                product=product_norm,
                version=cpe_ver,
            ),
            "version_source": os.path.abspath(source_path) if source_path else "inline",
            "vendor": self.VENDOR,
            "link": self.LINK_SOURCE,
        }
        if extra:
            out.update(extra)
        return out

    def _version_guard_ok(self, content: str) -> bool:
        if not self._compiled_version_guards:
            return True
        for pat, _ in self._compiled_version_guards:
            if pat.search(content):
                return True
        return False

    def _check_contains(self, content: str, source_path: str) -> List[Dict]:
        results: List[Dict] = []
        if self.signature_reported:
            return results
        if not self._compiled_contains:
            return results
        for pat, _ in self._compiled_contains:
            if pat.search(content):
                self.signature_reported = True
                results.append(self.make_result("unknown", source_path))
                break
        return results

    def _check_versions(self, content: str, source_path: str) -> List[Dict]:
        results: List[Dict] = []
        if not self._compiled_versions:
            return results
        if not self._version_guard_ok(content):
            return results
        seen: Set[str] = set()
        for pat, group_idx in self._compiled_versions:
            for m in pat.finditer(content):
                try:
                    v = m.group(group_idx)
                except IndexError:
                    continue
                v = (v or "").strip().replace("_", ".")
                if not v or v in seen:
                    continue
                seen.add(v)
                results.append(self.make_result(v, source_path))
                if self.STOP_AFTER_FIRST_VERSION:
                    return results
        return results

    def check_file_versions_only(self, content: str, path: str) -> List[Dict]:
        src_full = os.path.abspath(path)
        return self._check_versions(content, src_full)

    def check_file_contains_only(self, content: str, path: str) -> List[Dict]:
        src_full = os.path.abspath(path)
        return self._check_contains(content, src_full)

    def check_meta(self, directory: str) -> List[Dict]:
        return []
