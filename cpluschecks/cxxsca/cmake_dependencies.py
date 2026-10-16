from __future__ import annotations
import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit
from .checker_catalog import CheckerCatalog
from .models import ResolvedComponent, TreeIndex
from .util import is_known_version, normalize_version, repo_token_from_url

_CMAKE_ARCHIVE_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tgz",
    ".tbz2",
    ".txz",
    ".zip",
    ".7z",
    ".gz",
    ".bz2",
    ".xz",
)
_EXTERNAL_PROJECT_KEYWORDS = {
    "PREFIX",
    "TMP_DIR",
    "STAMP_DIR",
    "LOG_DIR",
    "DOWNLOAD_DIR",
    "SOURCE_DIR",
    "BINARY_DIR",
    "INSTALL_DIR",
    "DOWNLOAD_COMMAND",
    "URL",
    "URL_HASH",
    "URL_MD5",
    "DOWNLOAD_NAME",
    "DOWNLOAD_EXTRACT_TIMESTAMP",
    "DOWNLOAD_NO_EXTRACT",
    "DOWNLOAD_NO_PROGRESS",
    "TIMEOUT",
    "INACTIVITY_TIMEOUT",
    "HTTP_USERNAME",
    "HTTP_PASSWORD",
    "HTTP_HEADER",
    "TLS_VERIFY",
    "TLS_CAINFO",
    "NETRC",
    "NETRC_FILE",
    "GIT_REPOSITORY",
    "GIT_TAG",
    "GIT_REMOTE_NAME",
    "GIT_SUBMODULES",
    "GIT_SUBMODULES_RECURSE",
    "GIT_SHALLOW",
    "GIT_PROGRESS",
    "GIT_CONFIG",
    "SVN_REPOSITORY",
    "SVN_REVISION",
    "SVN_USERNAME",
    "SVN_PASSWORD",
    "SVN_TRUST_CERT",
    "HG_REPOSITORY",
    "HG_TAG",
    "CVS_REPOSITORY",
    "CVS_MODULE",
    "CVS_TAG",
    "UPDATE_COMMAND",
    "UPDATE_DISCONNECTED",
    "PATCH_COMMAND",
    "CONFIGURE_COMMAND",
    "CMAKE_COMMAND",
    "CMAKE_GENERATOR",
    "CMAKE_GENERATOR_PLATFORM",
    "CMAKE_GENERATOR_TOOLSET",
    "CMAKE_GENERATOR_INSTANCE",
    "CMAKE_ARGS",
    "CMAKE_CACHE_ARGS",
    "CMAKE_CACHE_DEFAULT_ARGS",
    "SOURCE_SUBDIR",
    "CONFIGURE_HANDLED_BY_BUILD",
    "BUILD_COMMAND",
    "BUILD_IN_SOURCE",
    "BUILD_ALWAYS",
    "BUILD_BYPRODUCTS",
    "INSTALL_COMMAND",
    "INSTALL_BYPRODUCTS",
    "TEST_COMMAND",
    "TEST_BEFORE_INSTALL",
    "TEST_AFTER_INSTALL",
    "TEST_EXCLUDE_FROM_MAIN",
    "LOG_DOWNLOAD",
    "LOG_UPDATE",
    "LOG_PATCH",
    "LOG_CONFIGURE",
    "LOG_BUILD",
    "LOG_INSTALL",
    "LOG_TEST",
    "LOG_MERGED_STDOUTERR",
    "LOG_OUTPUT_ON_FAILURE",
    "USES_TERMINAL_DOWNLOAD",
    "USES_TERMINAL_UPDATE",
    "USES_TERMINAL_PATCH",
    "USES_TERMINAL_CONFIGURE",
    "USES_TERMINAL_BUILD",
    "USES_TERMINAL_INSTALL",
    "USES_TERMINAL_TEST",
    "DEPENDS",
    "EXCLUDE_FROM_ALL",
    "STEP_TARGETS",
    "INDEPENDENT_STEP_TARGETS",
    "LIST_SEPARATOR",
    "COMMAND",
}
_FETCHCONTENT_KEYWORDS = {
    "QUIET",
    "EXCLUDE_FROM_ALL",
    "SYSTEM",
    "OVERRIDE_FIND_PACKAGE",
    "FIND_PACKAGE_ARGS",
    "SOURCE_DIR",
    "BINARY_DIR",
    "SUBBUILD_DIR",
    "SOURCE_SUBDIR",
    "DOWNLOAD_COMMAND",
    "URL",
    "URL_HASH",
    "URL_MD5",
    "DOWNLOAD_NAME",
    "DOWNLOAD_NO_EXTRACT",
    "DOWNLOAD_EXTRACT_TIMESTAMP",
    "DOWNLOAD_NO_PROGRESS",
    "TIMEOUT",
    "INACTIVITY_TIMEOUT",
    "HTTP_USERNAME",
    "HTTP_PASSWORD",
    "HTTP_HEADER",
    "TLS_VERIFY",
    "TLS_CAINFO",
    "NETRC",
    "NETRC_FILE",
    "GIT_REPOSITORY",
    "GIT_TAG",
    "GIT_REMOTE_NAME",
    "GIT_SUBMODULES",
    "GIT_SUBMODULES_RECURSE",
    "GIT_SHALLOW",
    "GIT_PROGRESS",
    "GIT_CONFIG",
    "SVN_REPOSITORY",
    "SVN_REVISION",
    "SVN_USERNAME",
    "SVN_PASSWORD",
    "SVN_TRUST_CERT",
    "HG_REPOSITORY",
    "HG_TAG",
    "CVS_REPOSITORY",
    "CVS_MODULE",
    "CVS_TAG",
    "UPDATE_COMMAND",
    "UPDATE_DISCONNECTED",
    "PATCH_COMMAND",
}
_HASH_ALG_MAP = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_256": "SHA3-256",
    "SHA3_384": "SHA3-384",
    "SHA3_512": "SHA3-512",
}
_SEMVER_RE = re.compile(
    r"(?<![0-9A-Za-z])[vV]?(\d+\.\d+(?:\.\d+){0,2}[A-Za-z]?(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?)(?![0-9A-Za-z])"
)
_UNDERSCORE_VERSION_RE = re.compile(
    r"(?<!\d)[vV]?(\d{1,3})_(\d{1,3})(?:_(\d{1,4}))?(?!\d)"
)
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_CMAKE_COMPONENT_ALIASES = {
    "zeromq": "libzmq",
    "zmq": "libzmq",
    "libcg": "libcgroup",
    "tbb": "onetbb",
    "oneapitbb": "onetbb",
    "avrocpp": "avro",
    "sqlite3": "sqlite",
}


@dataclass(slots=True)
class _CMakeState:
    variables: dict[str, str]
    variable_conditions: dict[str, tuple[str, ...]]
    active_conditions: tuple[str, ...] = ()


@dataclass(slots=True)
class _IfFrame:
    base_states: list[_CMakeState]
    completed_states: list[_CMakeState]
    branch_labels: list[str]
    has_else: bool = False


def _clone_states(states: list[_CMakeState]) -> list[_CMakeState]:
    return [
        _CMakeState(
            dict(state.variables),
            dict(state.variable_conditions),
            tuple(state.active_conditions),
        )
        for state in states
    ]


def _with_condition(states: list[_CMakeState], label: str) -> list[_CMakeState]:
    label = " ".join((label or "").split())
    out: list[_CMakeState] = []
    for state in states:
        active = (
            tuple((*state.active_conditions, label))
            if label
            else tuple(state.active_conditions)
        )
        out.append(
            _CMakeState(dict(state.variables), dict(state.variable_conditions), active)
        )
    return out


def _leave_condition_scope(states: list[_CMakeState]) -> list[_CMakeState]:
    out: list[_CMakeState] = []
    for state in states:
        active = state.active_conditions[:-1] if state.active_conditions else ()
        out.append(
            _CMakeState(dict(state.variables), dict(state.variable_conditions), active)
        )
    return out


def _merge_equivalent_states(states: list[_CMakeState]) -> list[_CMakeState]:
    merged: dict[tuple, _CMakeState] = {}
    for state in states:
        cond_key = tuple(
            sorted(
                (name, tuple(conds))
                for name, conds in state.variable_conditions.items()
            )
        )
        key = (
            tuple(sorted(state.variables.items())),
            cond_key,
            tuple(state.active_conditions),
        )
        if key not in merged:
            merged[key] = _CMakeState(
                dict(state.variables),
                dict(state.variable_conditions),
                tuple(state.active_conditions),
            )
    return list(merged.values())


def _dedup_conditions(parts) -> tuple[str, ...]:
    out: list[str] = []
    for part in parts:
        text = " ".join((part or "").split())
        if text and text not in out:
            out.append(text)
    return tuple(out)


def _condition_expression(parts) -> str:
    return " && ".join(_dedup_conditions(parts))


def _branch_label(kind: str, body: str) -> str:
    expr = " ".join((body or "").split())
    return f"{kind}({expr})" if expr else kind


def _identity_arg_variables(args: dict[str, list[str]]) -> set[str]:
    names: set[str] = set()
    for key in ("URL", "URL_HASH", "URL_MD5", "GIT_REPOSITORY", "GIT_TAG"):
        for value in args.get(key) or []:
            names.update(_VAR_RE.findall(value))
    return names


def _declaration_conditions_for_state(
    args: dict[str, list[str]],
    state: _CMakeState,
) -> tuple[str, ...]:
    parts: list[str] = list(state.active_conditions)
    for var in sorted(_identity_arg_variables(args)):
        parts.extend(state.variable_conditions.get(var, ()))
    expression = _condition_expression(parts)
    return (expression,) if expression else ()


def _relevant_cmake_variables(commands: list[tuple[str, str, int]]) -> set[str]:
    relevant: set[str] = set()
    set_values: dict[str, list[str]] = {}
    identity_keys = {
        "URL",
        "URL_HASH",
        "URL_MD5",
        "GIT_REPOSITORY",
        "GIT_TAG",
    }
    for command, body, _line in commands:
        low = command.lower()
        tokens = _tokenize(body)
        if not tokens:
            continue
        if low == "set" and len(tokens) >= 2:
            set_values.setdefault(tokens[0], []).append(";".join(tokens[1:]))
            continue
        if low in {"external_project_add", "externalproject_add"}:
            args = _parse_keyword_args(tokens, _EXTERNAL_PROJECT_KEYWORDS)
        elif low == "fetchcontent_declare":
            args = _parse_keyword_args(tokens, _FETCHCONTENT_KEYWORDS)
        else:
            continue
        for key in identity_keys:
            for value in args.get(key) or []:
                relevant.update(_VAR_RE.findall(value))
    changed = True
    while changed:
        changed = False
        for var in tuple(relevant):
            for raw in set_values.get(var, []):
                for dep in _VAR_RE.findall(raw):
                    if dep not in relevant:
                        relevant.add(dep)
                        changed = True
    return relevant


def _strip_comments(text: str) -> str:
    out: list[str] = []
    in_quote = False
    escape = False
    i = 0
    while i < len(text):
        ch = text[i]
        if escape:
            out.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and in_quote:
            out.append(ch)
            escape = True
            i += 1
            continue
        if ch == '"':
            in_quote = not in_quote
            out.append(ch)
            i += 1
            continue
        if ch == "#" and not in_quote:
            while i < len(text) and text[i] != "\n":
                i += 1
            if i < len(text):
                out.append("\n")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _iter_commands(text: str):
    clean = _strip_comments(text)
    n = len(clean)
    i = 0
    while i < n:
        m = re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*\(", clean[i:])
        if not m:
            break
        start = i + m.start()
        open_pos = i + m.end() - 1
        name_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", clean[start:])
        if not name_match:
            i = open_pos + 1
            continue
        name = name_match.group(1)
        depth = 1
        j = open_pos + 1
        in_quote = False
        escape = False
        while j < n and depth:
            ch = clean[j]
            if escape:
                escape = False
            elif ch == "\\" and in_quote:
                escape = True
            elif ch == '"':
                in_quote = not in_quote
            elif not in_quote:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            j += 1
        if depth != 0:
            break
        body = clean[open_pos + 1 : j - 1]
        line = clean.count("\n", 0, start) + 1
        yield name, body, line
        i = j


def _tokenize(body: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        while i < n and body[i].isspace():
            i += 1
        if i >= n:
            break
        if body[i] == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                ch = body[i]
                if ch == "\\" and i + 1 < n:
                    buf.append(body[i + 1])
                    i += 2
                    continue
                if ch == '"':
                    i += 1
                    break
                buf.append(ch)
                i += 1
            tokens.append("".join(buf))
            continue
        start = i
        while i < n and not body[i].isspace():
            i += 1
        tokens.append(body[start:i])
    return [t for t in tokens if t]


def _resolve_vars(value: str, variables: dict[str, str]) -> str:
    out = value or ""
    for _ in range(12):
        changed = False

        def repl(match: re.Match[str]) -> str:
            nonlocal changed
            key = match.group(1)
            if key not in variables:
                return match.group(0)
            changed = True
            return variables[key]

        new = _VAR_RE.sub(repl, out)
        out = new
        if not changed:
            break
    return out


def _parse_keyword_args(tokens: list[str], keywords: set[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    i = 1
    while i < len(tokens):
        key = tokens[i].upper()
        if key not in keywords:
            i += 1
            continue
        i += 1
        vals: list[str] = []
        while i < len(tokens) and tokens[i].upper() not in keywords:
            vals.append(tokens[i])
            i += 1
        out.setdefault(key, []).extend(vals)
    return out


def _strip_archive_suffix(name: str) -> str:
    low = name.lower()
    for suffix in _CMAKE_ARCHIVE_SUFFIXES:
        if low.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _version_from_text(value: str) -> str:
    if not value:
        return "unknown"
    matches = list(_SEMVER_RE.finditer(value))
    if matches:
        version = matches[-1].group(1)
        version = re.sub(r"\.dirty$", "", version, flags=re.IGNORECASE)
        return version
    underscore = list(_UNDERSCORE_VERSION_RE.finditer(value))
    if underscore:
        m = underscore[-1]
        parts = [m.group(1), m.group(2)]
        if m.group(3) is not None:
            parts.append(m.group(3))
        return ".".join(parts)
    return "unknown"


def _version_from_url(url: str) -> str:
    if not url:
        return "unknown"
    path = urlsplit(url).path if "://" in url else url.split("?", 1)[0].split("#", 1)[0]
    base = path.rstrip("/").split("/")[-1]
    return _version_from_text(_strip_archive_suffix(base))


def _parse_hash(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if "=" not in raw:
        return "", ""
    alg, content = raw.split("=", 1)
    alg = alg.strip().upper().replace("-", "")
    content = content.strip()
    mapped = _HASH_ALG_MAP.get(alg, "")
    if not mapped:
        return "", ""
    if not re.fullmatch(r"[0-9A-Fa-f]+", content):
        return "", ""
    return mapped, content.upper()


def _normal_name(value: str) -> str:
    s = (value or "").strip().lower()
    s = re.sub(r"^(?:ext|external|thirdparty|third_party|dep|dependency)[-_]+", "", s)
    return re.sub(r"[^a-z0-9]+", "", s)


def _archive_component_hint(url: str) -> str:
    path = urlsplit(url).path if "://" in url else url.split("?", 1)[0]
    base = _strip_archive_suffix(path.rstrip("/").split("/")[-1])
    if not base:
        return ""
    m = _SEMVER_RE.search(base)
    if m:
        base = base[: m.start()].rstrip("-_.")
    return base


def _component_alias(value: str) -> str:
    if not value:
        return ""
    return _CMAKE_COMPONENT_ALIASES.get(_normal_name(value), value)


def _canonical_component(
    target: str, source_url: str, git_repo: str, catalog: CheckerCatalog
) -> str:
    candidates = [
        target,
        _archive_component_hint(source_url),
        repo_token_from_url(git_repo),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        for lookup in dict.fromkeys((_component_alias(candidate), candidate)):
            exact = catalog.profile_for_component(lookup)
            if exact:
                return exact.product
    normalized_candidates = {_normal_name(_component_alias(c)) for c in candidates if c}
    normalized_candidates.update(_normal_name(c) for c in candidates if c)
    normalized_candidates.discard("")
    for profile in catalog.profiles:
        forms = {
            _normal_name(profile.product),
            _normal_name(profile.repo_token),
            _normal_name(profile.product + "cpp"),
            _normal_name(profile.product + "c"),
            _normal_name("lib" + profile.product),
        }
        if normalized_candidates & forms:
            return profile.product
    fallback = (
        target
        or _archive_component_hint(source_url)
        or repo_token_from_url(git_repo)
        or "unknown"
    )
    return _component_alias(fallback).strip()


def _declaration_component(
    *,
    target: str,
    kind: str,
    args: dict[str, list[str]],
    variables: dict[str, str],
    source_file: str,
    source_root: str,
    catalog: CheckerCatalog,
    declaration_conditions: tuple[str, ...] = (),
) -> ResolvedComponent | None:
    if not target:
        return None

    def first(key: str) -> str:
        vals = args.get(key) or []
        return _resolve_vars(vals[0], variables) if vals else ""

    source_url = first("URL")
    url_hash_raw = first("URL_HASH")
    if not url_hash_raw and first("URL_MD5"):
        url_hash_raw = "MD5=" + first("URL_MD5")
    git_repo = first("GIT_REPOSITORY")
    git_tag = first("GIT_TAG")
    if not any((source_url, git_repo)):
        return None
    name = _canonical_component(target, source_url, git_repo, catalog)
    version = _version_from_url(source_url)
    if not is_known_version(version):
        resolved_tag = _resolve_vars(git_tag, variables)
        version = _version_from_text(resolved_tag)
    profile = catalog.profile_for_component(name)
    vendor = profile.vendor if profile else ""
    vcs = git_repo or (profile.vcs if profile else "")
    cpe = ""
    if profile and is_known_version(version):
        try:
            cpe = profile.cls().make_result(version, "").get("cpe", "") or ""
        except Exception:
            cpe = ""
    hash_alg, hash_value = _parse_hash(url_hash_raw)
    depends = tuple(
        dict.fromkeys(
            _resolve_vars(v, variables).strip()
            for v in (args.get("DEPENDS") or [])
            if _resolve_vars(v, variables).strip()
        )
    )
    methods = (f"build:{kind}",)
    return ResolvedComponent(
        name=name,
        version=normalize_version(version),
        confidence=0.995,
        root=source_root,
        vendor=vendor,
        vcs=vcs,
        cpe=cpe,
        tag_template=(
            (getattr(profile.cls, "TAG_TEMPLATE", "") or "").strip()
            if profile
            else ""
        ),
        identity_confirmed=True,
        identity_methods=methods,
        methods=methods,
        evidence_files=(source_file,),
        declaration_kind=kind,
        declaration_source_url=source_url,
        declaration_hash_alg=hash_alg,
        declaration_hash_value=hash_value,
        declaration_hash_raw=url_hash_raw,
        declared_dependencies=depends,
        declaration_target=target,
        declaration_conditions=declaration_conditions,
    )


def discover_cmake_declared_components(
    tree: TreeIndex, catalog: CheckerCatalog
) -> list[ResolvedComponent]:
    out: list[ResolvedComponent] = []
    for rec in tree.files:
        if rec.name_lower != "cmakelists.txt" and rec.suffix != ".cmake":
            continue
        try:
            text = rec.abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        commands = list(_iter_commands(text))
        relevant_vars = _relevant_cmake_variables(commands)
        active_states: list[_CMakeState] = [_CMakeState({}, {})]
        if_stack: list[_IfFrame] = []
        for command, body, _line in commands:
            low = command.lower()
            tokens = _tokenize(body)
            if low == "if":
                base = _clone_states(active_states)
                label = _branch_label("if", body)
                if_stack.append(_IfFrame(base, [], [label]))
                active_states = _with_condition(base, label)
                continue
            if low == "elseif" and if_stack:
                frame = if_stack[-1]
                frame.completed_states.extend(active_states)
                label = _branch_label("elseif", body)
                frame.branch_labels.append(label)
                active_states = _with_condition(frame.base_states, label)
                continue
            if low == "else" and if_stack:
                frame = if_stack[-1]
                frame.completed_states.extend(active_states)
                frame.has_else = True
                label = "else(" + " | ".join(frame.branch_labels) + ")"
                active_states = _with_condition(frame.base_states, label)
                continue
            if low == "endif" and if_stack:
                frame = if_stack.pop()
                frame.completed_states.extend(active_states)
                if not frame.has_else:
                    label = "else(" + " | ".join(frame.branch_labels) + ")"
                    frame.completed_states.extend(
                        _with_condition(frame.base_states, label)
                    )
                active_states = _merge_equivalent_states(
                    _leave_condition_scope(frame.completed_states)
                )
                continue
            if not tokens:
                continue
            if low == "set" and len(tokens) >= 2:
                var_name = tokens[0]
                if var_name not in relevant_vars:
                    continue
                value_tokens = tokens[1:]
                for stop in ("CACHE", "PARENT_SCOPE"):
                    upper = [t.upper() for t in value_tokens]
                    if stop in upper:
                        value_tokens = value_tokens[: upper.index(stop)]
                        break
                raw_value = ";".join(value_tokens)
                referenced = _VAR_RE.findall(raw_value)
                for state in active_states:
                    provenance: list[str] = list(state.active_conditions)
                    for ref in referenced:
                        provenance.extend(state.variable_conditions.get(ref, ()))
                    state.variables[var_name] = _resolve_vars(
                        raw_value, state.variables
                    )
                    state.variable_conditions[var_name] = _dedup_conditions(provenance)
                active_states = _merge_equivalent_states(active_states)
                continue
            if low in {"external_project_add", "externalproject_add"}:
                args = _parse_keyword_args(tokens, _EXTERNAL_PROJECT_KEYWORDS)
                kind = "cmake:ExternalProject_Add"
            elif low == "fetchcontent_declare":
                args = _parse_keyword_args(tokens, _FETCHCONTENT_KEYWORDS)
                kind = "cmake:FetchContent_Declare"
            else:
                continue
            for state in active_states:
                item = _declaration_component(
                    target=tokens[0],
                    kind=kind,
                    args=args,
                    variables=state.variables,
                    source_file=rec.rel_path,
                    source_root=rec.directory,
                    catalog=catalog,
                    declaration_conditions=_declaration_conditions_for_state(
                        args, state
                    ),
                )
                if item:
                    out.append(item)
    unique: dict[tuple[str, str, str, str], ResolvedComponent] = {}
    for item in out:
        key = (
            item.name.lower(),
            normalize_version(item.version),
            item.declaration_source_url,
            item.declaration_kind,
        )
        old = unique.get(key)
        if old is None:
            unique[key] = item
            continue
        unique[key] = replace(
            old,
            evidence_files=tuple(
                sorted(set(old.evidence_files) | set(item.evidence_files))
            ),
            declared_dependencies=tuple(
                sorted(set(old.declared_dependencies) | set(item.declared_dependencies))
            ),
            declaration_conditions=tuple(
                sorted(
                    set(old.declaration_conditions) | set(item.declaration_conditions)
                )
            ),
        )
    return sorted(
        unique.values(),
        key=lambda c: (c.name.lower(), c.version, c.declaration_source_url),
    )


def merge_declared_components(
    existing: list[ResolvedComponent],
    declared: list[ResolvedComponent],
) -> tuple[list[ResolvedComponent], int, int]:
    out = list(existing)
    merged = 0
    added = 0

    def merge_into(old: ResolvedComponent, new: ResolvedComponent) -> ResolvedComponent:
        use_new_version = (not is_known_version(old.version)) and is_known_version(
            new.version
        )
        return replace(
            old,
            version=new.version if use_new_version else old.version,
            confidence=max(old.confidence, new.confidence),
            vendor=old.vendor or new.vendor,
            vcs=old.vcs or new.vcs,
            cpe=(new.cpe if use_new_version else old.cpe) or new.cpe,
            identity_confirmed=True,
            identity_methods=tuple(
                sorted(set(old.identity_methods) | set(new.identity_methods))
            ),
            methods=tuple(sorted(set(old.methods) | set(new.methods))),
            evidence_files=tuple(
                sorted(set(old.evidence_files) | set(new.evidence_files))
            ),
            declaration_kind=new.declaration_kind or old.declaration_kind,
            declaration_source_url=new.declaration_source_url
            or old.declaration_source_url,
            declaration_hash_alg=new.declaration_hash_alg or old.declaration_hash_alg,
            declaration_hash_value=new.declaration_hash_value
            or old.declaration_hash_value,
            declaration_hash_raw=new.declaration_hash_raw or old.declaration_hash_raw,
            declared_dependencies=tuple(
                sorted(set(old.declared_dependencies) | set(new.declared_dependencies))
            ),
            declaration_target=new.declaration_target or old.declaration_target,
            declaration_conditions=tuple(
                sorted(
                    set(old.declaration_conditions) | set(new.declaration_conditions)
                )
            ),
        )

    for item in declared:
        exact_idx = next(
            (
                i
                for i, old in enumerate(out)
                if old.name.lower() == item.name.lower()
                and is_known_version(old.version)
                and is_known_version(item.version)
                and normalize_version(old.version) == normalize_version(item.version)
            ),
            None,
        )
        if exact_idx is not None:
            out[exact_idx] = merge_into(out[exact_idx], item)
            merged += 1
            continue
        if is_known_version(item.version):
            unknown_idx = next(
                (
                    i
                    for i, old in enumerate(out)
                    if old.name.lower() == item.name.lower()
                    and not is_known_version(old.version)
                ),
                None,
            )
            if unknown_idx is not None:
                out[unknown_idx] = merge_into(out[unknown_idx], item)
                merged += 1
                continue
        out.append(item)
        added += 1
    deduped: list[ResolvedComponent] = []
    seen: dict[tuple[str, str, str], int] = {}
    for item in sorted(
        out,
        key=lambda c: (c.name.lower(), normalize_version(c.version), c.root.lower()),
    ):
        key = (
            item.name.lower(),
            normalize_version(item.version),
            item.declaration_source_url or item.root,
        )
        if key not in seen:
            seen[key] = len(deduped)
            deduped.append(item)
            continue
        idx = seen[key]
        deduped[idx] = merge_into(deduped[idx], item)
    return deduped, merged, added
