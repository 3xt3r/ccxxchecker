from pathlib import Path
import sqlite3
from cxxsca.checker_catalog import CheckerCatalog
from cxxsca.fingerprint_db import FingerprintDB, REQUIRED_SCHEMA_VERSION
from cxxsca.models import FingerprintSummary
from cxxsca.resolver import EvidenceResolver
from cxxsca.segments import normalize_segment, snippet_fingerprints


def _long_function(name: str = "calculate", changed: bool = False) -> str:
    body = []
    for i in range(1, 45):
        if changed and i == 22:
            body.append("    total = total * 3 + values[22];")
        else:
            body.append(f"    total = total + values[{i % 8}] + {i};")
    return (
        f"int {name}(const int *values, int count) {{\n"
        "    int total = count;\n" + "\n".join(body) + "\n    return total;\n}\n"
    )


def test_winnowing_survives_local_modification_while_whole_segment_hash_changes():
    original = normalize_segment(_long_function())
    modified = normalize_segment(_long_function(changed=True))
    assert original != modified
    a = set(snippet_fingerprints(original))
    b = set(snippet_fingerprints(modified))
    assert a and b
    retained = len(a & b) / max(1, min(len(a), len(b)))
    assert retained >= 0.60


def test_v015_db_builds_separate_snippet_index(tmp_path: Path):
    src = tmp_path / "catalog" / "demo" / "reference"
    src.mkdir(parents=True)
    (src / "demo.c").write_text(_long_function(), encoding="utf-8")
    db_path = tmp_path / "fingerprints.sqlite"
    stats = FingerprintDB.build_from_catalog(
        tmp_path / "catalog", db_path, progress=False
    )
    assert stats["segments"] >= 1
    assert stats["snippets"] >= 1
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM snippets").fetchone()[0] >= 1
        assert (
            conn.execute("SELECT COUNT(*) FROM snippet_hash_stats").fetchone()[0] >= 1
        )
        schema = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0]
        assert schema == REQUIRED_SCHEMA_VERSION == "identity-only-v7-snippet-winnowing"
    finally:
        conn.close()


def _summary(*, seed: int) -> FingerprintSummary:
    return FingerprintSummary(
        component="demo",
        confidence=0.90,
        coverage=0.01 if seed else 0.0,
        exact_matches=seed,
        normalized_matches=0,
        matched_segments=seed,
        total_segments=100,
        matched_files=1 if seed else 0,
        sampled_files=5,
        mean_idf=0.95 if seed else 0.0,
        high_idf_matches=seed,
        shared_matches=0,
        shared_ratio=0.0,
        weighted_score=float(seed),
        snippet_matches=40,
        snippet_total=80,
        snippet_coverage=0.50,
        snippet_matched_files=4,
        snippet_mean_idf=0.90,
        snippet_high_idf_matches=30,
        snippet_shared_matches=0,
        snippet_shared_ratio=0.0,
        snippet_weighted_score=36.0,
        methods=("hash:exact",) if seed else (),
        supporting_methods=("hash:snippet-winnowing",),
    )


def test_snippet_only_cannot_open_identity_gate():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    accepted, reason = resolver.fingerprint_gate_decision(
        "foreign/root", _summary(seed=0)
    )
    assert not accepted
    assert reason == "resolver:matched_segments<2"


def test_one_exact_seed_plus_strong_snippets_can_confirm_modified_source():
    resolver = EvidenceResolver(CheckerCatalog(checker_classes=[]))
    fp = _summary(seed=1)
    accepted, reason = resolver.fingerprint_gate_decision("foreign/root", fp)
    assert accepted
    assert reason == "accepted:snippet_supported_seed"
    result = resolver.resolve("foreign/root", [], [fp])
    assert result is not None
    assert result.name == "demo"
    assert result.identity_methods == ("hash:exact",)
    assert "hash:snippet-winnowing" in result.methods
    assert "hash:snippet-winnowing" not in result.identity_methods
