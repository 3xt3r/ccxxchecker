from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass

TOKEN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*|0x[0-9A-Fa-f]+|\d+(?:\.\d+)?|==|!=|<=|>=|&&|\|\||->|::|[{}()\[\];,+*/%&|^!~=<>?:.-]"
)
CONTROL_WORDS = {"if", "for", "while", "switch", "catch", "else", "do"}
TYPE_WORDS = {"struct", "class", "enum", "union"}


@dataclass(frozen=True, slots=True)
class CodeSegment:
    kind: str
    raw: str
    normalized: str
    exact_hash: str
    normalized_hash: str
    token_count: int
    start_line: int


def _strip_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"
    quote = ""
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                out.append(" ")
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                out.append(" ")
                i += 2
                continue
            if ch in {'"', "'"}:
                state = "string"
                quote = ch
                out.append(ch)
                i += 1
                continue
            out.append(ch)
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                out.append("\n")
                state = "code"
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                out.append(" ")
                i += 2
            else:
                if ch == "\n":
                    out.append("\n")
                i += 1
            continue
        if state == "string":
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
    return "".join(out)


def normalize_segment(text: str) -> str:
    clean = _strip_comments(text.replace("\r\n", "\n").replace("\r", "\n"))
    toks = TOKEN.findall(clean)
    return " ".join(toks)


SNIPPET_K_TOKENS = 12
SNIPPET_WINDOW = 16
SNIPPET_MAX_PER_SEGMENT = 32


def _snippet_hash(tokens: list[str]) -> tuple[int, str]:
    material = "\x1f".join(tokens).encode("utf-8", errors="ignore")
    digest = hashlib.blake2b(material, digest_size=16, person=b"cxxsca15").digest()
    return int.from_bytes(digest, "big"), digest.hex()


def snippet_fingerprints(
    normalized: str,
    *,
    k_tokens: int = SNIPPET_K_TOKENS,
    window: int = SNIPPET_WINDOW,
    max_fingerprints: int = SNIPPET_MAX_PER_SEGMENT,
) -> tuple[str, ...]:
    toks = TOKEN.findall(normalized)
    k = max(4, int(k_tokens))
    if len(toks) < k:
        return ()
    grams = [_snippet_hash(toks[i : i + k]) for i in range(len(toks) - k + 1)]
    w = max(1, min(int(window), len(grams)))
    selected: list[tuple[int, str]] = []
    last_pos = -1
    for start in range(0, len(grams) - w + 1):
        end = start + w
        min_value = min(value for value, _ in grams[start:end])
        pos = max(i for i in range(start, end) if grams[i][0] == min_value)
        if pos != last_pos:
            selected.append((pos, grams[pos][1]))
            last_pos = pos
    if not selected and grams:
        min_value = min(value for value, _ in grams)
        pos = max(i for i, row in enumerate(grams) if row[0] == min_value)
        selected.append((pos, grams[pos][1]))
    unique: list[tuple[int, str]] = []
    seen: set[str] = set()
    for pos, fp in selected:
        if fp in seen:
            continue
        seen.add(fp)
        unique.append((pos, fp))
    cap = max(1, int(max_fingerprints))
    if len(unique) > cap:
        if cap == 1:
            unique = [unique[len(unique) // 2]]
        else:
            picks = {round(i * (len(unique) - 1) / (cap - 1)) for i in range(cap)}
            unique = [row for i, row in enumerate(unique) if i in picks]
    return tuple(fp for _, fp in unique)


def _segment(
    raw: str, kind: str, start_line: int, *, min_tokens: int
) -> CodeSegment | None:
    normalized = normalize_segment(raw)
    token_count = len(TOKEN.findall(normalized))
    if token_count < min_tokens:
        return None
    exact_material = "\n".join(line.rstrip() for line in raw.strip().splitlines())
    return CodeSegment(
        kind=kind,
        raw=raw,
        normalized=normalized,
        exact_hash=hashlib.sha256(
            exact_material.encode("utf-8", errors="ignore")
        ).hexdigest(),
        normalized_hash=hashlib.sha256(
            normalized.encode("utf-8", errors="ignore")
        ).hexdigest(),
        token_count=token_count,
        start_line=start_line,
    )


def _matching_brace(text: str, open_pos: int) -> int | None:
    depth = 0
    i = open_pos
    state = "code"
    quote = ""
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if ch in {'"', "'"}:
                state = "string"
                quote = ch
                i += 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                state = "code"
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                i += 1
            continue
        if state == "string":
            if ch == "\\" and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
    return None


def _header_start(text: str, brace_pos: int, max_back: int = 1200) -> int:
    start = max(0, brace_pos - max_back)
    chunk = text[start:brace_pos]
    last = max(chunk.rfind(";"), chunk.rfind("}"), chunk.rfind("\n#"))
    return start + last + 1


def _looks_like_function(header: str) -> bool:
    stripped = _strip_comments(header).strip()
    if not stripped or "(" not in stripped or ")" not in stripped:
        return False
    low = stripped.lower()
    if any(re.search(rf"\b{w}\s*\([^)]*\)\s*$", low) for w in CONTROL_WORDS):
        return False
    if (
        any(re.search(rf"\b{w}\b", low) for w in TYPE_WORDS)
        and ")" not in low.split("{")[-1]
    ):
        return False
    before = stripped[: stripped.rfind("(")]
    return bool(
        re.search(r"(?:operator\s*[^\s]+|[~A-Za-z_][A-Za-z0-9_:<>~]*)\s*$", before)
    )


def extract_segments(
    text: str,
    *,
    min_function_tokens: int = 28,
    min_type_tokens: int = 24,
    min_macro_tokens: int = 16,
) -> list[CodeSegment]:
    segments: list[CodeSegment] = []
    consumed: list[tuple[int, int]] = []
    i = 0
    while True:
        brace = text.find("{", i)
        if brace < 0:
            break
        end = _matching_brace(text, brace)
        if end is None:
            break
        hs = _header_start(text, brace)
        header = text[hs:brace]
        low = _strip_comments(header).lower()
        kind = ""
        min_tokens = min_function_tokens
        if _looks_like_function(header):
            kind = "function"
        elif re.search(r"\b(struct|class|enum|union)\b", low):
            kind = "type"
            min_tokens = min_type_tokens
        if kind:
            raw = text[hs : end + 1]
            seg = _segment(
                raw, kind, text.count("\n", 0, hs) + 1, min_tokens=min_tokens
            )
            if seg:
                segments.append(seg)
                consumed.append((hs, end + 1))
            i = end + 1
        else:
            i = brace + 1
    lines = text.splitlines(keepends=True)
    pos = 0
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if re.match(r"^\s*#\s*define\b", line):
            raw_lines = [line]
            j = idx
            while raw_lines[-1].rstrip().endswith("\\") and j + 1 < len(lines):
                j += 1
                raw_lines.append(lines[j])
            raw = "".join(raw_lines)
            seg = _segment(raw, "macro", idx + 1, min_tokens=min_macro_tokens)
            if seg:
                segments.append(seg)
            for k in range(idx, j + 1):
                pos += len(lines[k])
            idx = j + 1
            continue
        pos += len(line)
        idx += 1
    unique: dict[tuple[str, str], CodeSegment] = {}
    for seg in segments:
        unique.setdefault((seg.kind, seg.normalized_hash), seg)
    return list(unique.values())
