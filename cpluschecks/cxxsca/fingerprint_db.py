from __future__ import annotations
import configparser
import os
import sqlite3
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable
from .segments import extract_segments, snippet_fingerprints
from .tree_index import (
    HARD_TEST_DIRS,
    SOURCE_EXTENSIONS,
    is_hard_test_component,
    is_hard_test_filename,
)

NESTED_VENDOR_DIRS = {
    "third_party",
    "third-party",
    "3rdparty",
    "3rd_party",
    "vendor",
    "vendors",
    "external",
    "extern",
    "deps",
    "dependencies",
    "contrib",
    "thirdparty",
}
TEST_SCOPE_DIRS = {
    "test",
    "tests",
    "testing",
    "testsuite",
    "testsuites",
    "bench",
    "benchmark",
    "benchmarks",
    "example",
    "examples",
    "demo",
    "demos",
    "fuzz",
    "fuzzer",
    "fuzzers",
    "oss-fuzz",
}
AUXILIARY_SCOPE_DIRS = {
    "doc",
    "docs",
    "documentation",
    "tool",
    "tools",
    "script",
    "scripts",
    "ci",
    ".github",
    "cmake",
}


def _normalize_rel_path(value: str) -> str:
    return value.replace("\\", "/").strip("/")


def _has_vendor_boundary(rel_path: str) -> bool:
    parts = [part.lower() for part in Path(_normalize_rel_path(rel_path)).parts]
    return any(part in NESTED_VENDOR_DIRS for part in parts)


def _read_gitmodules(
    repo_root: Path, cache: dict[Path, dict[str, str]]
) -> dict[str, str]:
    repo_root = repo_root.resolve()
    cached = cache.get(repo_root)
    if cached is not None:
        return cached
    gitmodules = repo_root / ".gitmodules"
    entries: dict[str, str] = {}
    if not gitmodules.is_file():
        cache[repo_root] = entries
        return entries
    parser = configparser.RawConfigParser(interpolation=None)
    try:
        parser.read(gitmodules, encoding="utf-8")
    except (OSError, configparser.Error):
        cache[repo_root] = entries
        return entries
    for section in parser.sections():
        if not section.lower().startswith("submodule "):
            continue
        try:
            path = _normalize_rel_path(parser.get(section, "path"))
            url = parser.get(section, "url").strip()
        except (configparser.Error, KeyError):
            continue
        if path and url:
            entries[path] = url
    cache[repo_root] = entries
    return entries


def _is_relative_submodule_url(url: str) -> bool:
    value = url.strip().replace("\\", "/")
    return value.startswith("../") or value.startswith("./")


def _is_owned_nested_git(
    label_dir: Path,
    current_path: Path,
    *,
    gitmodules_cache: dict[Path, dict[str, str]],
) -> bool:
    try:
        rel_from_label = current_path.relative_to(label_dir).as_posix()
    except ValueError:
        return False
    if not rel_from_label or _has_vendor_boundary(rel_from_label):
        return False
    repo_root = current_path.parent
    while True:
        try:
            current_path.relative_to(repo_root)
            repo_root.relative_to(label_dir)
        except ValueError:
            break
        entries = _read_gitmodules(repo_root, gitmodules_cache)
        if entries:
            rel = _normalize_rel_path(current_path.relative_to(repo_root).as_posix())
            url = entries.get(rel)
            if url is not None:
                return _is_relative_submodule_url(url)
        if repo_root == label_dir:
            break
        repo_root = repo_root.parent
    return False


def source_scope(rel_path: str) -> str:
    parts = [part.lower() for part in Path(rel_path).parts[:-1]]
    if any(part in NESTED_VENDOR_DIRS for part in parts):
        return "VENDORED"
    if any(part in TEST_SCOPE_DIRS for part in parts):
        return "TEST"
    if any(part in AUXILIARY_SCOPE_DIRS for part in parts):
        return "AUXILIARY"
    return "PRIMARY"


TABLE_SCHEMA = """
PRAGMA journal_mode=DELETE;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS segments (
 id INTEGER PRIMARY KEY, exact_hash BLOB NOT NULL, normalized_hash BLOB NOT NULL,
 component TEXT NOT NULL, source_label TEXT NOT NULL, kind TEXT NOT NULL,
 source_path TEXT NOT NULL, token_count INTEGER NOT NULL, scope TEXT NOT NULL,
 UNIQUE(exact_hash,normalized_hash,component,scope)
);
CREATE TABLE IF NOT EXISTS snippets (
 fingerprint BLOB NOT NULL, component TEXT NOT NULL, scope TEXT NOT NULL,
 PRIMARY KEY(fingerprint,component,scope)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hash_stats (
 hash_kind TEXT NOT NULL, hash BLOB NOT NULL,
 component_frequency INTEGER NOT NULL, primary_component_frequency INTEGER NOT NULL,
 PRIMARY KEY(hash_kind,hash)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS snippet_hash_stats (
 fingerprint BLOB PRIMARY KEY,
 component_frequency INTEGER NOT NULL, primary_component_frequency INTEGER NOT NULL
) WITHOUT ROWID;
"""
INDEX_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_segments_exact ON segments(exact_hash);
CREATE INDEX IF NOT EXISTS idx_segments_normalized ON segments(normalized_hash);
"""
REQUIRED_SCHEMA_VERSION = "identity-compact-v8"


def _blob(value: str) -> bytes:
    return bytes.fromhex(value)


class FingerprintDB:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, 'conn', None)
        if conn is None:
            conn = sqlite3.connect(f'file:{self.path.resolve()}?mode=ro', uri=True, timeout=30.0)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def initialize(self, *, reset: bool = False) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if reset:
            for suffix in ('', '-wal', '-shm'):
                target = Path(str(self.path) + suffix)
                if target.exists():
                    target.unlink()
        con = sqlite3.connect(self.path)
        try:
            if not reset:
                try:
                    version = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
                except sqlite3.OperationalError:
                    version = None
                if version and version[0] != REQUIRED_SCHEMA_VERSION:
                    raise RuntimeError(f'Existing DB schema {version[0]} is not {REQUIRED_SCHEMA_VERSION}')
            con.executescript(TABLE_SCHEMA)
            con.execute("INSERT OR REPLACE INTO meta VALUES('schema_version',?)", (REQUIRED_SCHEMA_VERSION,))
            con.commit()
        finally:
            con.close()

    def schema_version(self) -> str:
        try:
            row=self._conn().execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            return row[0] if row else ''
        except sqlite3.OperationalError:
            return ''

    def validate_compatible(self) -> None:
        if self.schema_version() != REQUIRED_SCHEMA_VERSION:
            raise RuntimeError('Incompatible fingerprint DB; rebuild with compact v8 builder')

    def total_components(self) -> int:
        row=self._conn().execute("SELECT value FROM meta WHERE key='component_count'").fetchone()
        return int(row[0]) if row else 0

    def lookup_hashes(self, exact_hashes: Iterable[str], normalized_hashes: Iterable[str]) -> tuple[dict[str,list[dict]],dict[str,list[dict]]]:
        conn=self._conn()
        def lookup(column, values, kind):
            vals=list(dict.fromkeys(v for v in values if v))
            out=defaultdict(list)
            for start in range(0,len(vals),400):
                chunk=vals[start:start+400]
                blobs=[_blob(x) for x in chunk]
                placeholders=','.join('?' for _ in chunk)
                rows=conn.execute(
                    f'SELECT s.{column} AS h,s.component,s.source_label,s.kind,s.source_path,s.token_count,s.scope,'
                    f'COALESCE(hs.component_frequency,1) AS component_frequency,'
                    f'COALESCE(hs.primary_component_frequency,0) AS primary_component_frequency '
                    f'FROM segments s LEFT JOIN hash_stats hs ON hs.hash_kind=? AND hs.hash=s.{column} '
                    f'WHERE s.{column} IN ({placeholders})', [kind,*blobs])
                for row in rows:
                    item=dict(row)
                    item['h']=row['h'].hex()
                    out[item['h']].append(item)
            return dict(out)
        return lookup('exact_hash',exact_hashes,'exact'),lookup('normalized_hash',normalized_hashes,'normalized')

    def lookup_snippet_hashes(self, fingerprints: Iterable[str]) -> dict[str,list[dict]]:
        conn=self._conn()
        vals=list(dict.fromkeys(v for v in fingerprints if v))
        out=defaultdict(list)
        for start in range(0,len(vals),400):
            chunk=vals[start:start+400]
            q=','.join('?' for _ in chunk)
            rows=conn.execute(
                f'SELECT s.fingerprint AS h,s.component,s.scope,'
                f'COALESCE(hs.component_frequency,1) AS component_frequency,'
                f'COALESCE(hs.primary_component_frequency,0) AS primary_component_frequency '
                f'FROM snippets s LEFT JOIN snippet_hash_stats hs ON hs.fingerprint=s.fingerprint '
                f'WHERE s.fingerprint IN ({q})', [_blob(x) for x in chunk])
            for row in rows:
                item=dict(row)
                item['h']=row['h'].hex()
                out[item['h']].append(item)
        return dict(out)

    def ingest_component_incremental(self, component: str, source_label: str, source_dir: str | Path,
                                     *,max_file_bytes: int=2_000_000,min_primary_segments:int=2,progress:bool=True) -> dict:
        raise RuntimeError('Compact v8 requires full rebuild for now; incremental ingest is not supported')

    @classmethod
    def build_from_catalog(cls, catalog_root: str | Path, out_db: str | Path, *,
                           max_file_bytes:int=2_000_000, reset:bool=True, progress:bool=False) -> dict:
        catalog_root=Path(catalog_root).resolve()
        if not catalog_root.is_dir():
            raise FileNotFoundError(catalog_root)
        db=cls(out_db)
        db.initialize(reset=reset)
        jobs=[(component.name,label.name,label) for component in sorted(catalog_root.iterdir()) if component.is_dir() and not is_hard_test_component(component.name)
              for label in sorted(component.iterdir()) if label.is_dir()]
        conn=sqlite3.connect(db.path,timeout=120)
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA temp_store=MEMORY')
        started=time.perf_counter()
        total_files=total_segments=total_snippets=0
        components=set()
        try:
            for i,(component,source_label,label_dir) in enumerate(jobs,1):
                components.add(component)
                start=time.perf_counter()
                file_count=seg_count=snip_count=0
                gitmodules_cache={}
                for current,dirs,files in os.walk(label_dir,followlinks=False):
                    base=Path(current)
                    if base != label_dir and ((base/'.git').is_dir() or (base/'.git').is_file()):
                        if not _is_owned_nested_git(label_dir,base,gitmodules_cache=gitmodules_cache):
                            dirs[:]=[]
                            continue
                    dirs[:]=[d for d in dirs if d.lower() not in HARD_TEST_DIRS and d.lower()!='.git' and not (base/d).is_symlink()]
                    if base.name.lower() in NESTED_VENDOR_DIRS:
                        dirs[:]=[]
                    for filename in files:
                        if is_hard_test_filename(filename):
                            continue
                        path=base/filename
                        if path.is_symlink() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                            continue
                        try:
                            if path.stat().st_size>max_file_bytes:
                                continue
                            content=path.read_text(encoding='utf-8',errors='ignore')
                        except OSError:
                            continue
                        file_count+=1
                        relative=path.relative_to(label_dir).as_posix()
                        scope=source_scope(relative)
                        segments=extract_segments(content)
                        srows=[(_blob(seg.exact_hash),_blob(seg.normalized_hash),component,source_label,seg.kind,relative,seg.token_count,scope) for seg in segments]
                        if srows:
                            conn.executemany('INSERT OR IGNORE INTO segments(exact_hash,normalized_hash,component,source_label,kind,source_path,token_count,scope) VALUES(?,?,?,?,?,?,?,?)',srows)
                            seg_count+=len(srows)
                        snippet_rows={(_blob(fp),component,scope) for seg in segments for fp in snippet_fingerprints(seg.normalized)}
                        if snippet_rows:
                            conn.executemany('INSERT OR IGNORE INTO snippets(fingerprint,component,scope) VALUES(?,?,?)',snippet_rows)
                            snip_count+=len(snippet_rows)
                conn.commit()
                total_files+=file_count;total_segments+=seg_count;total_snippets+=snip_count
                if progress:
                    print(f'[{i}/{len(jobs)}] {component}/{source_label} files={file_count} segments={seg_count} snippet_occurrences={snip_count} {time.perf_counter()-start:.2f}s',flush=True)
            if progress: print('[index] computing frequencies...',flush=True)
            conn.executescript("""
            INSERT INTO hash_stats SELECT 'exact',exact_hash,COUNT(DISTINCT component),COUNT(DISTINCT CASE WHEN scope='PRIMARY' THEN component END) FROM segments GROUP BY exact_hash;
            INSERT INTO hash_stats SELECT 'normalized',normalized_hash,COUNT(DISTINCT component),COUNT(DISTINCT CASE WHEN scope='PRIMARY' THEN component END) FROM segments GROUP BY normalized_hash;
            INSERT INTO snippet_hash_stats SELECT fingerprint,COUNT(DISTINCT component),COUNT(DISTINCT CASE WHEN scope='PRIMARY' THEN component END) FROM snippets GROUP BY fingerprint;
            """)
            if progress:print('[index] building segment lookup indexes...',flush=True)
            conn.executescript(INDEX_SCHEMA)
            for key,value in [('schema_version',REQUIRED_SCHEMA_VERSION),('component_count',str(len(components))),('source_label_count',str(len(jobs)))]:
                conn.execute('INSERT OR REPLACE INTO meta VALUES(?,?)',(key,value))
            conn.commit()
            conn.execute('PRAGMA optimize')
        finally:
            conn.close()
        import json
        statistics={'components':len(components),'source_labels':len(jobs),'files':total_files,'segment_occurrences':total_segments,'snippet_occurrences':total_snippets,'db_bytes':db.path.stat().st_size,'seconds':round(time.perf_counter()-started,2),'schema':REQUIRED_SCHEMA_VERSION}
        return statistics
