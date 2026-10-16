from pathlib import Path
from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.fingerprint_db import FingerprintDB
from cxxsca.models import FingerprintSummary
from cxxsca.resolver import EvidenceResolver
from cxxsca.segments import extract_segments

BOOSTISH = r"""
namespace boost {
namespace detail {
template <class T>
struct hash_impl {
    std::size_t operator()(T const& value) const {
        std::size_t seed = 1469598103934665603ULL;
        seed ^= static_cast<std::size_t>(value);
        seed *= 1099511628211ULL;
        seed ^= (seed >> 17);
        return seed;
    }
};
template <typename T>
inline T rotate_value(T value, unsigned shift) {
    const unsigned bits = sizeof(T) * 8;
    shift %= bits;
    return static_cast<T>((value << shift) | (value >> (bits - shift)));
}
}  // namespace detail
}  // namespace boost
"""


def _fp(
    component: str,
    *,
    coverage: float,
    exact: int,
    matched: int,
    total: int,
    files: int,
    shared: int,
    mean_idf: float = 0.92
) -> FingerprintSummary:
    return FingerprintSummary(
        component=component,
        confidence=0.95,
        coverage=coverage,
        exact_matches=exact,
        normalized_matches=0,
        matched_segments=matched,
        total_segments=total,
        matched_files=files,
        sampled_files=max(files, 1),
        mean_idf=mean_idf,
        high_idf_matches=matched,
        shared_matches=shared,
        shared_ratio=(shared / matched if matched else 0.0),
        weighted_score=float(matched),
        methods=("hash:exact",),
    )


def test_namespace_wrapped_cpp_is_not_skipped():
    segments = extract_segments(BOOSTISH)
    assert len(segments) >= 2
    assert {s.kind for s in segments} & {"function", "type"}


def test_namespace_wrapped_headers_are_indexed_as_primary(tmp_path: Path):
    ref = tmp_path / "catalog" / "boost" / "reference" / "include" / "boost"
    ref.mkdir(parents=True)
    (ref / "demo.hpp").write_text(BOOSTISH, encoding="utf-8")
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["segments"] >= 2
    import sqlite3

    con = sqlite3.connect(db_path)
    try:
        count = con.execute(
            "SELECT COUNT(*) FROM segments WHERE component='boost' AND scope='PRIMARY'"
        ).fetchone()[0]
    finally:
        con.close()
    assert count >= 2


def test_high_shared_canonical_root_is_allowed():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "zlib",
        coverage=1.0,
        exact=281,
        matched=281,
        total=281,
        files=21,
        shared=230,
    )
    result = resolver.resolve("zlib/reference", [], [fp])
    assert result is not None
    assert result.name == "zlib"


def test_high_shared_near_complete_vendor_copy_is_allowed():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "zlib",
        coverage=0.975,
        exact=274,
        matched=274,
        total=281,
        files=21,
        shared=229,
    )
    result = resolver.resolve(
        "opencv/reference/3rdparty/anonymous-compressor", [], [fp]
    )
    assert result is not None
    assert result.name == "zlib"


def test_high_shared_partial_foreign_match_is_still_rejected():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "opencv",
        coverage=0.6194,
        exact=95,
        matched=96,
        total=155,
        files=11,
        shared=73,
        mean_idf=0.8987,
    )
    assert resolver.resolve("clickhouse-cpp/reference/contrib/gtest", [], [fp]) is None
