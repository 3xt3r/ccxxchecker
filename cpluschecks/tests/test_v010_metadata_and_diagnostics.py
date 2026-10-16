from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.cyclonedx import component_to_cdx
from cxxsca.engine import ScanEngine
from cxxsca.models import (
    CheckerMetadataObservation,
    Evidence,
    EvidenceKind,
    FingerprintSummary,
    ResolvedComponent,
)
from cxxsca.resolver import EvidenceResolver


def _resolved(name: str, root: str) -> ResolvedComponent:
    return ResolvedComponent(
        name=name,
        version="unknown",
        confidence=0.99,
        root=root,
        identity_methods=("hash:exact",),
        methods=("hash:exact",),
        fingerprint_coverage=1.0,
        fingerprint_exact_matches=10,
        fingerprint_matched_segments=10,
        fingerprint_total_segments=10,
        fingerprint_matched_files=3,
        fingerprint_mean_idf=1.0,
        fingerprint_high_idf_matches=10,
    )


def test_same_component_ancestor_version_is_inherited():
    engine = ScanEngine()
    component = _resolved("cppkafka", "cppkafka/reference/include/cppkafka")
    observation = CheckerMetadataObservation(
        root="cppkafka/reference",
        component="cppkafka",
        version="0.4.1",
        confidence=0.98,
        methods=("checker:root-anchor", "checker:version"),
        evidence_files=("cppkafka/reference/CMakeLists.txt",),
    )
    out, inherited = engine._propagate_ancestor_metadata([component], [observation])
    assert inherited == 1
    assert out[0].version == "0.4.1"
    assert out[0].metadata_version_source_root == "cppkafka/reference"
    assert "checker:version" in out[0].methods
    assert out[0].identity_methods == ("hash:exact",)


def test_ancestor_version_does_not_cross_dependency_boundary():
    engine = ScanEngine()
    component = _resolved("libharu", "poco/reference/dependencies/hpdf")
    observation = CheckerMetadataObservation(
        root="poco/reference",
        component="libharu",
        version="2.4.6",
        confidence=0.99,
        methods=("checker:version",),
    )
    out, inherited = engine._propagate_ancestor_metadata([component], [observation])
    assert inherited == 0
    assert out[0].version == "unknown"


def test_generic_version_without_identity_anchor_is_not_exported_as_ancestor_metadata():
    evidence = [
        Evidence(
            kind=EvidenceKind.VERSION,
            component="avro",
            version="1.15.3",
            confidence=0.96,
            method="checker:version",
            source_file="poco/reference/VERSION",
            identity_confirming=False,
        )
    ]
    assert ScanEngine._collect_checker_metadata("poco/reference", evidence) == []


def test_resolver_reports_exact_rejection_reason():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
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
    resolved, rejected = resolver.resolve_with_diagnostics(
        "third_party/http-parser", [], [weak]
    )
    assert resolved is None
    assert len(rejected) == 1
    assert rejected[0].component == "libuv"
    assert rejected[0].reject_reason == "resolver:matched_segments<2"


def test_cyclonedx_exposes_inherited_version_source_root():
    component = _resolved("cppkafka", "cppkafka/reference/include/cppkafka")
    component.version = "0.4.1"
    component.metadata_version_source_root = "cppkafka/reference"
    cdx = component_to_cdx(component)
    props = {p["name"]: p["value"] for p in cdx["properties"]}
    assert props["metadata.version.source_root"] == "cppkafka/reference"
