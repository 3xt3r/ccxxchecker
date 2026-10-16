from __future__ import annotations
from cxxsca.engine import ScanEngine
from cxxsca.models import ResolvedComponent


def _resolved(
    *,
    name: str = "mongoose",
    version: str = "7.23",
    root: str = "mongoose/reference",
    confidence: float = 0.8,
    exact: int = 10,
    normalized: int = 0,
    methods: tuple[str, ...] = ("hash:exact",),
    evidence: tuple[str, ...] = ("a.cpp",),
) -> ResolvedComponent:
    return ResolvedComponent(
        name=name,
        version=version,
        confidence=confidence,
        root=root,
        identity_methods=tuple(m for m in methods if m.startswith("hash:")),
        methods=methods,
        evidence_files=evidence,
        fingerprint_coverage=1.0,
        fingerprint_exact_matches=exact,
        fingerprint_normalized_matches=normalized,
        fingerprint_matched_segments=exact + normalized,
        fingerprint_total_segments=exact + normalized,
        fingerprint_matched_files=2,
        fingerprint_sampled_files=2,
        fingerprint_mean_idf=1.0,
        fingerprint_high_idf_matches=exact + normalized,
        fingerprint_weighted_score=float(exact + normalized),
    )


def test_exact_same_name_version_root_is_merged_once():
    weak = _resolved(confidence=0.80, exact=8, evidence=("weak.cpp",))
    strong = _resolved(
        confidence=0.995,
        exact=20,
        methods=("checker:version", "hash:exact"),
        evidence=("strong.cpp",),
    )
    out, collapsed = ScanEngine._dedupe_exact_results([weak, strong])
    assert collapsed == 1
    assert len(out) == 1
    merged = out[0]
    assert merged.name == "mongoose"
    assert merged.version == "7.23"
    assert merged.root == "mongoose/reference"
    assert merged.confidence == 0.995
    assert merged.fingerprint_exact_matches == 20
    assert merged.fingerprint_matched_segments == 20
    assert set(merged.evidence_files) == {"weak.cpp", "strong.cpp"}
    assert set(merged.methods) == {"checker:version", "hash:exact"}


def test_same_component_different_version_is_not_deduped():
    out, collapsed = ScanEngine._dedupe_exact_results(
        [
            _resolved(name="zlib", version="1.3.2", root="zlib/reference"),
            _resolved(name="zlib", version="1.3.2.1", root="zlib/reference"),
        ]
    )
    assert collapsed == 0
    assert len(out) == 2


def test_same_component_version_different_root_is_not_deduped():
    out, collapsed = ScanEngine._dedupe_exact_results(
        [
            _resolved(name="boost", version="unknown", root="userver/third_party/pfr"),
            _resolved(
                name="boost", version="unknown", root="userver/third_party/uboost_coro"
            ),
        ]
    )
    assert collapsed == 0
    assert len(out) == 2


def test_exact_dedup_unions_hash_identity_methods_without_inflating_snapshot():
    exact = _resolved(
        name="grpc",
        version="1.84.0-dev",
        root="grpc/reference",
        confidence=0.99,
        exact=30,
        methods=("hash:exact",),
    )
    normalized = _resolved(
        name="grpc",
        version="1.84.0-dev",
        root="grpc/reference",
        confidence=0.98,
        exact=10,
        normalized=5,
        methods=("hash:exact", "hash:normalized"),
    )
    out, collapsed = ScanEngine._dedupe_exact_results([exact, normalized])
    assert collapsed == 1
    assert len(out) == 1
    merged = out[0]
    assert merged.identity_methods == ("hash:exact", "hash:normalized")
    assert merged.fingerprint_exact_matches == 30
    assert merged.fingerprint_matched_segments == 30
