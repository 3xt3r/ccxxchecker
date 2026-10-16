from __future__ import annotations
import sqlite3
from pathlib import Path
from cxxsca.fingerprint_db import FingerprintDB

CPP = r"""
namespace boost {
namespace demo {
template <class T>
struct accumulator {
    T value{};
    void add(T const& x) {
        value += x;
        value ^= static_cast<T>(value << 1);
    }
};
template <class T>
inline T fold_value(T v) {
    v ^= static_cast<T>(v >> 7);
    v *= static_cast<T>(0x9e3779b1u);
    return v;
}
} // namespace demo
} // namespace boost
"""


def _write_git_file(path: Path) -> None:
    path.write_text("gitdir: ../../.git/modules/demo\n", encoding="utf-8")


def _segment_count(db_path: Path, component: str) -> int:
    con = sqlite3.connect(db_path)
    try:
        return con.execute(
            "SELECT COUNT(*) FROM segments WHERE component=? AND scope='PRIMARY'",
            (component,),
        ).fetchone()[0]
    finally:
        con.close()


def test_declared_relative_submodule_is_indexed_as_owned(tmp_path: Path):
    ref = tmp_path / "catalog" / "boost" / "reference"
    sub = ref / "libs" / "algorithm"
    sub.mkdir(parents=True)
    (ref / ".gitmodules").write_text(
        '[submodule "algorithm"]\n'
        "    path = libs/algorithm\n"
        "    url = ../algorithm.git\n",
        encoding="utf-8",
    )
    _write_git_file(sub / ".git")
    (sub / "algorithm.hpp").write_text(CPP, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["files"] == 1
    assert _segment_count(db_path, "boost") >= 2


def test_absolute_external_submodule_remains_pruned(tmp_path: Path):
    ref = tmp_path / "catalog" / "umbrella" / "reference"
    sub = ref / "libs" / "foreign"
    sub.mkdir(parents=True)
    (ref / ".gitmodules").write_text(
        '[submodule "foreign"]\n'
        "    path = libs/foreign\n"
        "    url = https://github.com/other/foreign.git\n",
        encoding="utf-8",
    )
    _write_git_file(sub / ".git")
    (sub / "foreign.hpp").write_text(CPP, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["files"] == 0
    assert stats["nested_roots_pruned"] >= 1
    assert _segment_count(db_path, "umbrella") == 0


def test_relative_submodule_under_vendor_boundary_is_pruned(tmp_path: Path):
    ref = tmp_path / "catalog" / "umbrella" / "reference"
    sub = ref / "third_party" / "helper"
    sub.mkdir(parents=True)
    (ref / ".gitmodules").write_text(
        '[submodule "helper"]\n'
        "    path = third_party/helper\n"
        "    url = ../helper.git\n",
        encoding="utf-8",
    )
    _write_git_file(sub / ".git")
    (sub / "helper.hpp").write_text(CPP, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["files"] == 0
    assert stats["nested_roots_pruned"] >= 1
    assert _segment_count(db_path, "umbrella") == 0


def test_unlisted_nested_git_remains_pruned(tmp_path: Path):
    ref = tmp_path / "catalog" / "umbrella" / "reference"
    nested = ref / "libs" / "mystery"
    nested.mkdir(parents=True)
    (ref / ".gitmodules").write_text("", encoding="utf-8")
    _write_git_file(nested / ".git")
    (nested / "mystery.hpp").write_text(CPP, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["files"] == 0
    assert _segment_count(db_path, "umbrella") == 0
