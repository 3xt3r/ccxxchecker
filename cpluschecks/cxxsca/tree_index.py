from __future__ import annotations
import os
import re
from collections import defaultdict
from pathlib import Path
from .models import FileRecord, TreeIndex

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
    ".tcc",
    ".inl",
    ".inc",
    ".m",
    ".mm",
    ".cu",
    ".cuh",
    ".s",
    ".S",
}
METADATA_NAMES = {
    "version",
    "version.txt",
    "version.in",
    "version.mk",
    "version.m4",
    "release",
    "release.txt",
    "configure",
    "configure.ac",
    "configure.in",
    "cmakelists.txt",
    "meson.build",
    "meson_options.txt",
    "makefile",
    "makefile.am",
    "makefile.in",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
    "conan.lock",
    "workspace",
    "module.bazel",
    "build.bazel",
    "build",
    "jamroot",
    "readme",
    "readme.md",
    "readme.rst",
    "changelog",
    "changelog.md",
    "changes",
    "changes.md",
    "news",
    "news.md",
    "license",
    "license.md",
    "copying",
}
METADATA_SUFFIXES = {
    ".cmake",
    ".m4",
    ".mk",
    ".pc",
    ".in",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
}
SKIP_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".cache",
    "build",
    "dist",
    "out",
    ".idea",
    ".vscode",
    "cmake-build-debug",
    "cmake-build-release",
    "target",
}
HARD_TEST_DIRS = {
    "test",
    "tests",
    "testing",
    "testsuite",
    "testsuites",
    "testdata",
    "test_data",
    "test-data",
    "unittest",
    "unittests",
    "unit_test",
    "unit_tests",
    "unit-test",
    "unit-tests",
    "integration_test",
    "integration_tests",
    "integration-test",
    "integration-tests",
    "gtest",
    "googletest",
    "google_test",
    "google-test",
    "gmock",
    "googlemock",
    "google_mock",
    "google-mock",
}
HARD_TEST_COMPONENT_TOKENS = {"gtest", "googletest", "gmock", "googlemock"}
SOFT_SKIP_DIRS = {
    "doc",
    "docs",
    "example",
    "examples",
    "bench",
    "benchmark",
    "benchmarks",
    "samples",
}


def _component_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def is_hard_test_component(name: str) -> bool:
    return _component_token(name) in HARD_TEST_COMPONENT_TOKENS


def is_hard_test_filename(name: str) -> bool:
    low = name.lower()
    stem = Path(low).stem
    if stem in HARD_TEST_DIRS:
        return True
    if stem.startswith(("test_", "gtest", "gmock")):
        return True
    if stem.endswith(("_test", "_tests", "_unittest", "_unittests")):
        return True
    return False


def is_hard_test_path(rel_path: str) -> bool:
    parts = Path(rel_path).parts
    if not parts:
        return False
    dirs = (part.lower() for part in parts[:-1])
    return any(part in HARD_TEST_DIRS for part in dirs) or is_hard_test_filename(
        parts[-1]
    )


class TreeIndexer:
    def __init__(self, *, include_soft_skips: bool = False) -> None:
        self.include_soft_skips = include_soft_skips

    @staticmethod
    def is_interesting_file(name: str) -> bool:
        low = name.lower()
        suffix = Path(name).suffix.lower()
        return (
            suffix in SOURCE_EXTENSIONS
            or low in METADATA_NAMES
            or suffix in METADATA_SUFFIXES
        )

    def build(self, root: str | Path) -> TreeIndex:
        root = Path(root).resolve()
        if not root.is_dir():
            raise ValueError(f"scan root is not a directory: {root}")
        root_is_hard_test_component = is_hard_test_component(root.name)
        records: list[FileRecord] = []
        by_dir: dict[str, list[FileRecord]] = defaultdict(list)
        by_name: dict[str, list[FileRecord]] = defaultdict(list)
        directories: set[str] = {""}
        git_roots: set[str] = set()
        if root_is_hard_test_component:
            return TreeIndex(
                root=root,
                files=(),
                by_dir={},
                by_name={},
                directories=frozenset({""}),
                git_roots=frozenset(),
            )
        for current, dirs, files in os.walk(root):
            current_path = Path(current)
            rel_dir = current_path.relative_to(root).as_posix()
            if rel_dir == ".":
                rel_dir = ""
            directories.add(rel_dir)
            if ".git" in dirs or ".git" in files:
                git_roots.add(rel_dir)
            pruned: list[str] = []
            for d in dirs:
                low = d.lower()
                if low in SKIP_DIRS or low in HARD_TEST_DIRS:
                    continue
                if not self.include_soft_skips and low in SOFT_SKIP_DIRS:
                    continue
                pruned.append(d)
            dirs[:] = pruned
            for name in files:
                if is_hard_test_filename(name):
                    continue
                if not self.is_interesting_file(name):
                    continue
                p = current_path / name
                try:
                    size = p.stat().st_size
                except OSError:
                    continue
                rel = p.relative_to(root).as_posix()
                rec = FileRecord(
                    abs_path=p,
                    rel_path=rel,
                    directory=rel_dir,
                    name=name,
                    name_lower=name.lower(),
                    suffix=p.suffix.lower(),
                    size=size,
                )
                records.append(rec)
                by_dir[rel_dir].append(rec)
                by_name[rec.name_lower].append(rec)
        records.sort(key=lambda r: r.rel_path.lower())
        return TreeIndex(
            root=root,
            files=tuple(records),
            by_dir={k: tuple(v) for k, v in by_dir.items()},
            by_name={k: tuple(v) for k, v in by_name.items()},
            directories=frozenset(directories),
            git_roots=frozenset(git_roots),
        )
