from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.models import FingerprintSummary
from cxxsca.resolver import EvidenceResolver


def _fp(
    component: str,
    *,
    coverage: float,
    exact: int,
    normalized: int,
    matched: int,
    total: int,
    files: int,
    shared: int = 0,
) -> FingerprintSummary:
    methods = []
    if exact:
        methods.append("hash:exact")
    if normalized:
        methods.append("hash:normalized")
    return FingerprintSummary(
        component=component,
        confidence=0.99,
        coverage=coverage,
        exact_matches=exact,
        normalized_matches=normalized,
        matched_segments=matched,
        total_segments=total,
        matched_files=files,
        sampled_files=max(files, 1),
        mean_idf=1.0,
        high_idf_matches=matched,
        shared_matches=shared,
        shared_ratio=(shared / matched if matched else 0.0),
        weighted_score=float(matched),
        methods=tuple(methods),
    )


def test_one_shared_file_cannot_name_large_foreign_context():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "data_plane_development_kit",
        coverage=0.2907,
        exact=132,
        normalized=0,
        matched=132,
        total=454,
        files=1,
    )
    assert resolver.resolve("libarchive/reference", [], [fp]) is None


def test_two_foreign_files_cannot_name_large_context():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "fmt",
        coverage=0.9032,
        exact=140,
        normalized=0,
        matched=140,
        total=155,
        files=2,
    )
    assert resolver.resolve("clickhouse-cpp/reference/contrib/gtest", [], [fp]) is None


def test_multi_file_fingerprint_can_recover_renamed_vendor_component():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "libharu",
        coverage=1.0,
        exact=873,
        normalized=0,
        matched=873,
        total=873,
        files=5,
    )
    result = resolver.resolve("vendor/anonymous-pdf-code", [], [fp])
    assert result is not None
    assert result.name == "libharu"
    assert result.version == "unknown"


def test_named_compact_root_can_use_two_files():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "zstandard",
        coverage=0.70,
        exact=1146,
        normalized=13,
        matched=1159,
        total=1639,
        files=2,
    )
    result = resolver.resolve("vendor/zstandard", [], [fp])
    assert result is not None
    assert result.name == "zstandard"


def test_many_common_hashes_still_cannot_open_identity_gate():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = FingerprintSummary(
        component="fmt",
        confidence=0.98,
        coverage=0.90,
        exact_matches=140,
        normalized_matches=0,
        matched_segments=140,
        total_segments=155,
        matched_files=13,
        sampled_files=33,
        mean_idf=0.30,
        high_idf_matches=0,
        shared_matches=140,
        shared_ratio=1.0,
        weighted_score=18.0,
        methods=("hash:exact",),
    )
    assert resolver.resolve("clickhouse-cpp/reference/contrib/gtest", [], [fp]) is None


def test_real_v05_gtest_opencv_shape_is_rejected_by_shared_ratio():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = FingerprintSummary(
        component="opencv",
        confidence=0.9432,
        coverage=0.6194,
        exact_matches=95,
        normalized_matches=1,
        matched_segments=96,
        total_segments=155,
        matched_files=11,
        sampled_files=33,
        mean_idf=0.8987,
        high_idf_matches=96,
        shared_matches=73,
        shared_ratio=73 / 96,
        weighted_score=67.3367,
        methods=("hash:exact", "hash:normalized"),
    )
    assert resolver.resolve("clickhouse-cpp/reference/contrib/gtest", [], [fp]) is None


def test_medium_shared_ratio_requires_root_affinity():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "zstandard",
        coverage=0.70,
        exact=70,
        normalized=0,
        matched=100,
        total=143,
        files=8,
        shared=30,
    )
    assert resolver.resolve("vendor/anonymous-compressor", [], [fp]) is None
    result = resolver.resolve("vendor/zstd", [], [fp])
    assert result is not None
    assert result.name == "zstandard"


def test_low_shared_ratio_still_allows_strong_vendor_recovery():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _fp(
        "libharu",
        coverage=1.0,
        exact=873,
        normalized=0,
        matched=873,
        total=873,
        files=61,
        shared=4,
    )
    result = resolver.resolve("poco/reference/dependencies/hpdf", [], [fp])
    assert result is not None
    assert result.name == "libharu"
