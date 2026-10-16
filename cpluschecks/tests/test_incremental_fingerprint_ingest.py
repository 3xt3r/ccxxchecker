from pathlib import Path
import sqlite3
import pytest
from cxxsca.fingerprint_db import FingerprintDB


def _fn(name: str, offset: int = 0) -> str:
    lines = [f"    total += values[(i + {offset}) % 8] + {n};" for n in range(40)]
    return (
        f"int {name}(const int *values, int count) {{\n"
        "    int total = count;\n"
        "    for (int i = 0; i < count; ++i) {\n"
        + "\n".join(lines)
        + "\n    }\n    return total;\n}\n"
    )


def _write_component(root: Path, name: str, offset: int) -> Path:
    d = root / name / "reference"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.c").write_text(
        _fn(name + "_a", offset) + _fn(name + "_b", offset + 1), encoding="utf-8"
    )
    return d


def _rows(db: Path, table: str, component: str):
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            f"SELECT * FROM {table} WHERE component=? ORDER BY id", (component,)
        ).fetchall()
    finally:
        conn.close()


def test_incremental_ingest_replaces_only_one_component_and_keeps_global_meta(
    tmp_path: Path,
):
    catalog = tmp_path / "catalog"
    alpha = _write_component(catalog, "alpha", 0)
    _write_component(catalog, "beta", 100)
    db_path = tmp_path / "fingerprints.sqlite"
    FingerprintDB.build_from_catalog(catalog, db_path, progress=False)
    beta_segments_before = _rows(db_path, "segments", "beta")
    beta_snippets_before = _rows(db_path, "snippets", "beta")
    alpha_segments_before = _rows(db_path, "segments", "alpha")
    (alpha / "alpha.c").write_text(
        _fn("alpha_new_a", 7) + _fn("alpha_new_b", 8), encoding="utf-8"
    )
    stats = FingerprintDB(db_path).ingest_component_incremental(
        "alpha", "reference", alpha, progress=False
    )
    assert stats["component_count"] == 2
    assert stats["source_label_count"] == 2
    assert stats["old_segments_replaced"] == len(alpha_segments_before)
    assert stats["segments"] >= 2
    assert stats["snippets"] >= 1
    assert _rows(db_path, "segments", "beta") == beta_segments_before
    assert _rows(db_path, "snippets", "beta") == beta_snippets_before
    assert _rows(db_path, "segments", "alpha") != alpha_segments_before
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM hash_stats").fetchone()[0] > 0
        assert conn.execute("SELECT COUNT(*) FROM snippet_hash_stats").fetchone()[0] > 0
        assert (
            conn.execute(
                "SELECT value FROM meta WHERE key='component_count'"
            ).fetchone()[0]
            == "2"
        )
        assert (
            conn.execute(
                "SELECT value FROM meta WHERE key='source_label_count'"
            ).fetchone()[0]
            == "2"
        )
    finally:
        conn.close()


def test_incremental_ingest_refuses_empty_identity_without_touching_existing_rows(
    tmp_path: Path,
):
    catalog = tmp_path / "catalog"
    _write_component(catalog, "alpha", 0)
    db_path = tmp_path / "fingerprints.sqlite"
    FingerprintDB.build_from_catalog(catalog, db_path, progress=False)
    before = _rows(db_path, "segments", "alpha")
    bad = tmp_path / "bad"
    tests = bad / "tests"
    tests.mkdir(parents=True)
    (tests / "only_test.c").write_text(_fn("test_only", 1), encoding="utf-8")
    with pytest.raises(RuntimeError, match="target DB was not changed"):
        FingerprintDB(db_path).ingest_component_incremental(
            "alpha", "reference", bad, progress=False
        )
    assert _rows(db_path, "segments", "alpha") == before
