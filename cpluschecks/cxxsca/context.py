from __future__ import annotations
import threading
from dataclasses import dataclass, field
from pathlib import Path
from .models import FileRecord, TreeIndex
from .tree_index import METADATA_NAMES, METADATA_SUFFIXES, SOURCE_EXTENSIONS
from .util import path_parts, tokenize_text


@dataclass(slots=True)
class ComponentContext:
    tree: TreeIndex
    root_rel: str
    files: tuple[FileRecord, ...]
    child_roots: tuple[str, ...] = ()
    max_read_bytes: int = 512_000
    _content_cache: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _token_cache: set[str] | None = None

    @property
    def root_abs(self) -> Path:
        return self.tree.root / self.root_rel if self.root_rel else self.tree.root

    @property
    def display_root(self) -> str:
        return self.root_rel or "(root)"

    @property
    def source_files(self) -> tuple[FileRecord, ...]:
        return tuple(r for r in self.files if r.suffix in SOURCE_EXTENSIONS)

    @property
    def metadata_files(self) -> tuple[FileRecord, ...]:
        return tuple(
            r
            for r in self.files
            if r.name_lower in METADATA_NAMES or r.suffix in METADATA_SUFFIXES
        )

    @property
    def filenames(self) -> frozenset[str]:
        return frozenset(r.name_lower for r in self.files)

    @property
    def path_tokens(self) -> set[str]:
        out: set[str] = set()
        for part in path_parts(self.root_rel):
            out |= tokenize_text(part, min_len=3)
            low = part.lower()
            if len(low) >= 3:
                out.add(low)
        for rec in self.files[:5000]:
            stem = Path(rec.name_lower).stem
            out |= tokenize_text(stem, min_len=3)
        return out

    def read_text(self, rec: FileRecord, *, max_bytes: int | None = None) -> str:
        key = rec.rel_path
        with self._lock:
            cached = self._content_cache.get(key)
        if cached is not None:
            return cached
        limit = int(max_bytes or self.max_read_bytes)
        if rec.size > limit:
            try:
                with rec.abs_path.open("rb") as fh:
                    raw = fh.read(limit)
            except OSError:
                text = ""
            else:
                text = raw.decode("utf-8", errors="ignore")
        else:
            try:
                text = rec.abs_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
        with self._lock:
            self._content_cache[key] = text
        return text

    def identity_tokens(self, *, max_metadata_files: int = 24) -> set[str]:
        if self._token_cache is not None:
            return set(self._token_cache)
        out = set(self.path_tokens)
        meta = sorted(
            self.metadata_files,
            key=lambda r: (
                (
                    0
                    if r.name_lower
                    in {
                        "version",
                        "version.txt",
                        "configure.ac",
                        "configure.in",
                        "cmakelists.txt",
                        "meson.build",
                    }
                    else 1
                ),
                r.size,
                r.rel_path.lower(),
            ),
        )[:max_metadata_files]
        for rec in meta:
            out |= tokenize_text(
                self.read_text(rec, max_bytes=160_000), min_len=4, limit=500
            )
        self._token_cache = set(out)
        return out

    def source_sample(self, limit: int = 24) -> tuple[FileRecord, ...]:
        src = sorted(
            self.source_files,
            key=lambda r: (
                0 if r.suffix in {".h", ".hh", ".hpp", ".hxx"} else 1,
                r.size,
                r.rel_path.lower(),
            ),
        )
        return tuple(src[:limit])
