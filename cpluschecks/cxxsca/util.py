from __future__ import annotations
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

UNKNOWN_LIKE = {"", "unknown", "undefined", "n/a", "na", "none", "null"}
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_+.-]{2,}")
GENERIC_TOKENS = {
    "version",
    "include",
    "define",
    "project",
    "library",
    "source",
    "build",
    "copyright",
    "license",
    "file",
    "files",
    "main",
    "program",
    "return",
    "static",
    "const",
    "struct",
    "class",
    "public",
    "private",
    "protected",
    "void",
    "char",
    "int",
    "long",
    "short",
    "unsigned",
    "signed",
    "true",
    "false",
    "null",
    "nullptr",
    "string",
    "configure",
    "cmakelists",
    "makefile",
    "readme",
    "github",
    "https",
    "http",
    "author",
    "package",
    "release",
}


def normalize_version(value: str | None) -> str:
    s = (value or "").strip()
    return "unknown" if s.lower() in UNKNOWN_LIKE else s


def is_known_version(value: str | None) -> bool:
    return normalize_version(value) != "unknown"


def path_parts(rel: str) -> tuple[str, ...]:
    return tuple(p for p in (rel or "").replace("\\", "/").split("/") if p)


def is_under(rel_path: str, root_rel: str) -> bool:
    rel_path = (rel_path or "").strip("/")
    root_rel = (root_rel or "").strip("/")
    if not root_rel:
        return True
    return rel_path == root_rel or rel_path.startswith(root_rel + "/")


def repo_token_from_url(url: str) -> str:
    s = (url or "").strip().rstrip("/")
    if not s:
        return ""
    parsed = urlsplit(s)
    path = parsed.path or s
    base = re.split(r"[/:]", path)[-1]
    if base.lower().endswith(".git"):
        base = base[:-4]
    return base.lower()


def weak_name_match(segment: str, token: str) -> bool:
    s = (segment or "").lower().removesuffix(".git")
    t = (token or "").lower()
    if not s or not t:
        return False
    if s == t:
        return True
    return (
        s.startswith(t + "-")
        or s.startswith(t + "_")
        or s.endswith("-" + t)
        or s.endswith("_" + t)
        or f"-{t}-" in s
        or f"_{t}_" in s
    )


def tokenize_text(text: str, *, min_len: int = 4, limit: int | None = None) -> set[str]:
    out: set[str] = set()
    for m in TOKEN_RE.finditer(text or ""):
        t = m.group(0).lower().strip("._+-")
        if len(t) < min_len or t in GENERIC_TOKENS:
            continue
        out.add(t)
        if limit is not None and len(out) >= limit:
            break
    return out


def regex_literal_tokens(value: object) -> set[str]:
    if value is None:
        return set()
    pattern = getattr(value, "pattern", None)
    if pattern is None:
        pattern = str(value)
    pattern = re.sub(r"\\[AbBdDsSwWZz]", " ", pattern)
    return tokenize_text(pattern, min_len=4, limit=40)


def idf(total_docs: int, doc_freq: int) -> float:
    return 1.0 + math.log((total_docs + 1.0) / (doc_freq + 1.0))


def relpath(path: Path, root: Path) -> str:
    try:
        r = path.resolve().relative_to(root.resolve()).as_posix()
        return r
    except Exception:
        return path.as_posix()
