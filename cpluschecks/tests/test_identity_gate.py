from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.models import Evidence, EvidenceKind, FingerprintSummary, ResolvedComponent
from cxxsca.resolver import EvidenceResolver
from cxxsca.engine import ScanEngine


def test_version_and_context_score_cannot_create_identity():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    evidence = [
        Evidence(
            kind=EvidenceKind.VERSION,
            component="avro",
            version="1.15.3",
            confidence=0.96,
            method="checker:version",
            source_file="poco/reference/VERSION",
            identity_confirming=False,
        ),
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="avro",
            confidence=0.70,
            method="checker:context-score",
            identity_confirming=False,
        ),
    ]
    assert resolver.resolve("poco/reference", evidence, []) is None


def _strong_fp(component: str) -> FingerprintSummary:
    return FingerprintSummary(
        component=component,
        confidence=0.985,
        coverage=0.80,
        exact_matches=40,
        normalized_matches=2,
        matched_segments=42,
        total_segments=52,
        matched_files=5,
        sampled_files=7,
        mean_idf=0.98,
        high_idf_matches=41,
        shared_matches=1,
        shared_ratio=1 / 42,
        weighted_score=55.0,
        methods=("hash:exact", "hash:normalized"),
        source_examples=("vendor/random/avro.c",),
    )


def test_signature_alone_cannot_open_identity_gate():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    evidence = [
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="avro",
            confidence=0.99,
            method="checker:signature",
            source_file="vendor/random/avro.c",
            identity_confirming=True,
        ),
        Evidence(
            kind=EvidenceKind.VERSION,
            component="avro",
            version="1.13.0",
            confidence=0.96,
            method="checker:version",
            source_file="vendor/random/VERSION.txt",
            identity_confirming=False,
        ),
    ]
    assert resolver.resolve("vendor/random", evidence, []) is None


def test_fingerprint_opens_gate_and_checker_version_is_attached():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    evidence = [
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="avro",
            confidence=0.78,
            method="checker:signature",
            source_file="vendor/random/avro.c",
            identity_confirming=True,
        ),
        Evidence(
            kind=EvidenceKind.VERSION,
            component="avro",
            version="1.13.0",
            confidence=0.96,
            method="checker:version",
            source_file="vendor/random/VERSION.txt",
            identity_confirming=False,
        ),
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="avro",
            confidence=0.60,
            method="checker:context-score",
            identity_confirming=False,
        ),
    ]
    resolved = resolver.resolve("vendor/random", evidence, [_strong_fp("avro")])
    assert resolved is not None
    assert resolved.name == "avro"
    assert resolved.version == "1.13.0"
    assert resolved.identity_confirmed is True
    assert set(resolved.identity_methods) == {"hash:exact", "hash:normalized"}
    assert "checker:signature" in resolved.methods
    assert "checker:version" in resolved.methods


def test_unknown_version_keeps_checker_wildcard_cpe():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    evidence = [
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="zlib",
            version="unknown",
            confidence=0.78,
            method="checker:signature",
            source_file="third_party/zlib/zlib.h",
            cpe="cpe:2.3:a:madler:zlib:*:*:*:*:*:*:*:*",
            identity_confirming=True,
        )
    ]
    resolved = resolver.resolve("third_party/zlib", evidence, [_strong_fp("zlib")])
    assert resolved is not None
    assert resolved.version == "unknown"
    assert resolved.cpe == "cpe:2.3:a:madler:zlib:*:*:*:*:*:*:*:*"


def test_checker_cannot_bypass_weak_fingerprint_gate():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    evidence = [
        Evidence(
            kind=EvidenceKind.IDENTITY,
            component="libuv",
            confidence=0.999,
            method="checker:signature",
            source_file="third_party/http-parser/include/http_parser.h",
            identity_confirming=True,
        )
    ]
    weak = FingerprintSummary(
        component="libuv",
        confidence=0.99,
        coverage=0.01,
        exact_matches=1,
        normalized_matches=0,
        matched_segments=1,
        total_segments=100,
        matched_files=1,
        sampled_files=10,
        mean_idf=1.0,
        high_idf_matches=1,
        shared_matches=0,
        shared_ratio=0.0,
        weighted_score=1.0,
        methods=("hash:exact",),
    )
    assert resolver.resolve("third_party/http-parser", evidence, [weak]) is None


def _component(
    name: str, version: str, root: str, *, methods=("hash:exact",)
) -> ResolvedComponent:
    return ResolvedComponent(
        name=name,
        version=version,
        confidence=0.95,
        root=root,
        identity_methods=methods,
        methods=methods,
        fingerprint_coverage=1.0 if "hash:exact" in methods else None,
        fingerprint_exact_matches=5 if "hash:exact" in methods else 0,
        fingerprint_matched_segments=5 if "hash:exact" in methods else 0,
        fingerprint_total_segments=5 if "hash:exact" in methods else 0,
    )


def test_nested_same_component_is_collapsed_and_known_version_wins():
    parent = _component(
        "brotli", "1.2.0", "brotli/reference", methods=("checker:signature",)
    )
    child = _component("brotli", "unknown", "brotli/reference/c/include/brotli")
    final, collapsed = ScanEngine._collapse_nested_components([child, parent])
    assert collapsed == 1
    assert len(final) == 1
    assert final[0].root == "brotli/reference"
    assert final[0].version == "1.2.0"
    assert set(final[0].identity_methods) == {"checker:signature", "hash:exact"}


def test_nested_same_component_with_different_known_versions_is_preserved():
    parent = _component("libhtp", "0.5.48", "vendor/libhtp")
    child = _component("libhtp", "0.5.49", "vendor/libhtp/legacy-copy")
    final, collapsed = ScanEngine._collapse_nested_components([parent, child])
    assert collapsed == 0
    assert len(final) == 2


def test_sibling_copies_are_preserved():
    a = _component("fmt", "12.1.0", "vendor/a/fmt")
    b = _component("fmt", "12.2.1", "vendor/b/fmt")
    final, collapsed = ScanEngine._collapse_nested_components([a, b])
    assert collapsed == 0
    assert len(final) == 2
