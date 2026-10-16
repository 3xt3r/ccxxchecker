from pathlib import Path
from cxxsca.fingerprint_db import FingerprintDB, source_scope
from cxxsca.fingerprint_engine import FingerprintEngine
from cxxsca.segments import extract_segments
from cxxsca.tree_index import TreeIndexer

GTESTISH = r"""\nint gtest_alpha(int x) { int y = x + 17; y *= 3; y ^= 41; return y; }\nint gtest_beta(int x) { int y = x + 23; y *= 5; y ^= 43; return y; }\nint gtest_gamma(int x) { int y = x + 29; y *= 7; y ^= 47; return y; }\n"""
PRIMARY_A = r"""\nint alpha_unique_one(int x) { int y=x+101; y*=11; y^=53; return y; }\nint alpha_unique_two(int x) { int y=x+103; y*=13; y^=59; return y; }\n"""
SHARED = r"""\nint shared_helper(int x) { int y=x+7; y*=17; y^=61; return y; }\n"""


def test_scope_classifier_marks_non_primary_code():
    assert source_scope("src/core.c") == "PRIMARY"
    assert source_scope("include/lib/api.h") == "PRIMARY"
    assert source_scope("test/gtest/gtest.cc") == "TEST"
    assert source_scope("tests/unit/foo.cpp") == "TEST"
    assert source_scope("vendor/foo/foo.c") == "VENDORED"
    assert source_scope("tools/generator.cpp") == "AUXILIARY"


def test_test_and_gtest_code_is_not_inserted_or_scanned(tmp_path: Path):
    fmt = tmp_path / "catalog" / "fmt" / "reference"
    (fmt / "test" / "gtest").mkdir(parents=True)
    (fmt / "include" / "fmt").mkdir(parents=True)
    (fmt / "test" / "gtest" / "gtest.cc").write_text(GTESTISH, encoding="utf-8")
    (fmt / "include" / "fmt" / "format.h").write_text(PRIMARY_A, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    build_stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    db = FingerprintDB(db_path)
    db.validate_compatible()
    gtest_seg = extract_segments(GTESTISH)[0]
    exact, normalized = db.lookup_hashes(
        [gtest_seg.exact_hash], [gtest_seg.normalized_hash]
    )
    assert not exact.get(gtest_seg.exact_hash)
    assert not normalized.get(gtest_seg.normalized_hash)
    assert build_stats["hard_test_dirs_skipped"] >= 1
    target = tmp_path / "scan"
    target.mkdir()
    (target / "gtest.cc").write_text(GTESTISH, encoding="utf-8")
    (target / "real.cpp").write_text(PRIMARY_A, encoding="utf-8")
    tree = TreeIndexer().build(target)
    assert {rec.name for rec in tree.files} == {"real.cpp"}


def test_dedicated_googletest_catalog_component_is_skipped(tmp_path: Path):
    gtest = tmp_path / "catalog" / "googletest" / "reference" / "src"
    gtest.mkdir(parents=True)
    (gtest / "gtest-all.cc").write_text(GTESTISH, encoding="utf-8")
    alpha = tmp_path / "catalog" / "alpha" / "reference" / "src"
    alpha.mkdir(parents=True)
    (alpha / "alpha.c").write_text(PRIMARY_A, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    db = FingerprintDB(db_path)
    assert stats["hard_test_components_skipped"] == 1
    assert db.total_components() == 1
    gtest_seg = extract_segments(GTESTISH)[0]
    exact, _ = db.lookup_hashes([gtest_seg.exact_hash], [])
    assert not exact.get(gtest_seg.exact_hash)


def test_component_frequency_is_stored_and_used_as_idf(tmp_path: Path):
    for name in ("alpha", "beta"):
        root = tmp_path / "catalog" / name / "reference" / "src"
        root.mkdir(parents=True)
        (root / "shared.c").write_text(SHARED, encoding="utf-8")
    alpha = tmp_path / "catalog" / "alpha" / "reference" / "src"
    (alpha / "unique.c").write_text(PRIMARY_A, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    db = FingerprintDB(db_path)
    shared_seg = extract_segments(SHARED)[0]
    unique_seg = extract_segments(PRIMARY_A)[0]
    exact, _ = db.lookup_hashes([shared_seg.exact_hash, unique_seg.exact_hash], [])
    shared_rows = exact[shared_seg.exact_hash]
    unique_rows = exact[unique_seg.exact_hash]
    assert {row["primary_component_frequency"] for row in shared_rows} == {2}
    assert {row["primary_component_frequency"] for row in unique_rows} == {1}
    assert FingerprintEngine._normalized_idf(2, 1) > FingerprintEngine._normalized_idf(
        2, 2
    )
