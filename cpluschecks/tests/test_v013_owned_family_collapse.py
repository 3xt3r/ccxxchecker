from __future__ import annotations
from cxxsca.engine import ScanEngine
from cxxsca.models import ResolvedComponent


def _resolved(
    root: str, *, version: str = "1.93.0", source_root: str = "boost/reference"
) -> ResolvedComponent:
    return ResolvedComponent(
        name="boost",
        version=version,
        confidence=0.99,
        root=root,
        identity_methods=("hash:exact",),
        methods=("hash:exact", "checker:version"),
        evidence_files=(f"{root}/evidence.hpp",),
        fingerprint_coverage=1.0,
        fingerprint_exact_matches=10,
        fingerprint_matched_segments=10,
        fingerprint_total_segments=10,
        fingerprint_matched_files=2,
        fingerprint_sampled_files=2,
        fingerprint_mean_idf=1.0,
        fingerprint_high_idf_matches=10,
        fingerprint_weighted_score=12.0,
        metadata_version_source_root=source_root,
    )


def test_sibling_owned_submodules_collapse_to_common_metadata_root():
    components = [
        _resolved("boost/reference/libs/algorithm"),
        _resolved("boost/reference/libs/asio/include/boost"),
        _resolved("boost/reference/libs/chrono"),
    ]
    out, collapsed = ScanEngine._collapse_metadata_families(components)
    assert collapsed == 2
    assert len(out) == 1
    merged = out[0]
    assert merged.name == "boost"
    assert merged.version == "1.93.0"
    assert merged.root == "boost/reference"
    assert merged.metadata_version_source_root == "boost/reference"
    assert merged.fingerprint_exact_matches == 30
    assert merged.fingerprint_matched_segments == 30
    assert merged.fingerprint_total_segments == 30
    assert merged.fingerprint_matched_files == 6


def test_vendored_copy_is_not_absorbed_into_canonical_family():
    canonical = [
        _resolved("boost/reference/libs/algorithm"),
        _resolved("boost/reference/libs/asio/include/boost"),
    ]
    vendored = _resolved(
        "userver/reference/third_party/pfr/include/boost",
        version="unknown",
        source_root="",
    )
    out, collapsed = ScanEngine._collapse_metadata_families(canonical + [vendored])
    assert collapsed == 1
    assert len(out) == 2
    roots = {item.root for item in out}
    assert "boost/reference" in roots
    assert "userver/reference/third_party/pfr/include/boost" in roots


def test_same_source_root_but_different_versions_do_not_collapse():
    components = [
        _resolved("boost/reference/libs/algorithm", version="1.92.0"),
        _resolved("boost/reference/libs/asio", version="1.93.0"),
    ]
    out, collapsed = ScanEngine._collapse_metadata_families(components)
    assert collapsed == 0
    assert len(out) == 2


def test_family_collapse_refuses_vendor_boundary_even_if_metadata_is_forged():
    components = [
        _resolved("project/reference/include/boost", source_root="project/reference"),
        _resolved(
            "project/reference/third_party/boost",
            source_root="project/reference",
        ),
    ]
    out, collapsed = ScanEngine._collapse_metadata_families(components)
    assert collapsed == 0
    assert len(out) == 2
