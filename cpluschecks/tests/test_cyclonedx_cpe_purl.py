from cxxsca.cyclonedx import component_to_cdx
from cxxsca.models import ResolvedComponent


def test_known_component_has_plain_generic_purl_and_checker_cpe():
    c = ResolvedComponent(
        name="zlib",
        version="1.3.2",
        confidence=0.99,
        root="third_party/zlib",
        cpe="cpe:2.3:a:madler:zlib:1.3.2:*:*:*:*:*:*:*",
    )
    out = component_to_cdx(c)
    assert out["purl"] == "pkg:generic/zlib@1.3.2"
    assert "#" not in out["purl"]
    assert out["bom-ref"].startswith("urn:uuid:")
    assert out["cpe"] == "cpe:2.3:a:madler:zlib:1.3.2:*:*:*:*:*:*:*"


def test_unknown_component_also_has_plain_generic_purl_and_wildcard_cpe():
    c = ResolvedComponent(
        name="zlib",
        version="unknown",
        confidence=0.99,
        root="third_party/zlib",
        cpe="cpe:2.3:a:madler:zlib:*:*:*:*:*:*:*:*",
    )
    out = component_to_cdx(c)
    assert out["purl"] == "pkg:generic/zlib@unknown"
    assert "#" not in out["purl"]
    assert out["bom-ref"].startswith("urn:uuid:")
    assert out["cpe"] == "cpe:2.3:a:madler:zlib:*:*:*:*:*:*:*:*"
