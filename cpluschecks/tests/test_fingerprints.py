from pathlib import Path
from cxxsca import ScanConfig, ScanEngine
from cxxsca.fingerprint_db import FingerprintDB
from cxxsca.segments import extract_segments

ORIGINAL = r"""
/* upstream comment */
int demo_parse(const char *buf, int len) {
    int total = 0;
    for (int i = 0; i < len; ++i) {
        if (buf[i] == ':') total += i;
        else total ^= (unsigned char)buf[i];
    }
    return total;
}
int demo_checksum(const unsigned char *p, int n) {
    unsigned long s = 2166136261u;
    for (int i = 0; i < n; ++i) {
        s ^= p[i];
        s *= 16777619u;
    }
    return (int)(s & 0x7fffffff);
}
"""
REFORMATTED = r"""
// local corporate comment
int demo_parse( const char *buf , int len )
{
 int total=0;
 for(int i=0;i<len;++i){
   if(buf[i]==':') total+=i; else total^=(unsigned char)buf[i];
 }
 return total;
}
int demo_checksum(const unsigned char *p,int n)
{
 unsigned long s=2166136261u;
 for(int i=0;i<n;++i){s^=p[i];s*=16777619u;}
 return (int)(s&0x7fffffff);
}
"""


def test_normalized_segment_hash_survives_formatting():
    a = extract_segments(ORIGINAL)
    b = extract_segments(REFORMATTED)
    assert len(a) >= 2 and len(b) >= 2
    assert {s.normalized_hash for s in a} & {s.normalized_hash for s in b}


def test_fingerprint_only_detection_has_unknown_version(tmp_path: Path):
    catalog = tmp_path / "catalog" / "demo-lib" / "snapshot-1"
    catalog.mkdir(parents=True)
    (catalog / "demo.c").write_text(ORIGINAL, encoding="utf-8")
    db = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db)
    assert stats["segments"] >= 2
    target = tmp_path / "scan" / "vendor" / "renamed-http-code"
    target.mkdir(parents=True)
    (target / "parser.c").write_text(REFORMATTED, encoding="utf-8")
    (target / "parser.h").write_text(
        "typedef struct demo_state { int a; int b; int c; int d; } demo_state;\n",
        encoding="utf-8",
    )
    result = ScanEngine(
        ScanConfig(
            threads=1,
            fingerprint_db=str(db),
            fingerprint_policy="always",
            max_checkers_per_context=3,
        )
    ).scan(tmp_path / "scan")
    matches = [c for c in result.components if c.name == "demo-lib"]
    assert matches
    assert matches[0].version == "unknown"
    assert matches[0].fingerprint_normalized_matches >= 1


def test_multiple_catalog_snapshots_are_identity_only(tmp_path: Path):
    for label in ("0.9.0", "1.0.0", "1.1.0"):
        snapshot = tmp_path / "catalog" / "demo-lib" / label
        snapshot.mkdir(parents=True)
        (snapshot / "demo.c").write_text(ORIGINAL, encoding="utf-8")
    db = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db)
    assert stats["source_labels"] == 3
    target = tmp_path / "scan" / "vendor" / "anonymous"
    target.mkdir(parents=True)
    (target / "demo.c").write_text(ORIGINAL, encoding="utf-8")
    (target / "demo.h").write_text(
        "typedef struct demo_state { int a; int b; int c; int d; } demo_state;\n",
        encoding="utf-8",
    )
    result = ScanEngine(
        ScanConfig(
            threads=1,
            fingerprint_db=str(db),
            fingerprint_policy="always",
            max_checkers_per_context=2,
        )
    ).scan(tmp_path / "scan")
    match = next(c for c in result.components if c.name == "demo-lib")
    assert match.version == "unknown"
    assert match.fingerprint_exact_matches <= match.fingerprint_coverage * 10 + 10


def test_checker_only_cannot_survive_empty_fingerprint_db(tmp_path: Path):
    target = tmp_path / "vendor" / "anonymous-htp"
    (target / "htp").mkdir(parents=True)
    (target / "configure.ac").write_text(
        "AC_INIT([LibHTP], [m4_esyscmd(./get-version.sh VERSION)])\n",
        encoding="utf-8",
    )
    (target / "htp" / "htp.c").write_text(
        "/* @author Ivan Ristic <ivanr@webkreator.com> */\n"
        "int htp_demo(int x) { if (x > 2) return x + 1; return x - 1; }\n",
        encoding="utf-8",
    )
    (target / "htp" / "htp.h").write_text(
        "typedef struct htp_demo_t { int x; int y; int z; } htp_demo_t;\n",
        encoding="utf-8",
    )
    db = tmp_path / "empty.sqlite"
    FingerprintDB(db).initialize(reset=True)
    result = ScanEngine(
        ScanConfig(
            threads=1,
            fingerprint_db=str(db),
            fingerprint_policy="fallback",
        )
    ).scan(tmp_path)
    assert not [c for c in result.components if c.name == "libhtp"]
    assert result.stats.fingerprint_contexts > 0


def test_fingerprint_policy_off_emits_no_confirmed_components(tmp_path: Path):
    target = tmp_path / "vendor" / "anonymous-htp"
    (target / "htp").mkdir(parents=True)
    (target / "VERSION").write_text("PKG_VERSION = 0.5.49\n", encoding="utf-8")
    (target / "configure.ac").write_text("AC_INIT([LibHTP], [x])\n", encoding="utf-8")
    (target / "htp" / "htp.c").write_text(
        "/* @author Ivan Ristic <ivanr@webkreator.com> */\n"
        "int htp_demo(int x) { return x + 1; }\n",
        encoding="utf-8",
    )
    result = ScanEngine(ScanConfig(threads=1, fingerprint_policy="off")).scan(tmp_path)
    assert result.components == []


def test_duplicate_snapshots_do_not_inflate_identity_score(tmp_path: Path):
    target = tmp_path / "scan" / "vendor" / "anonymous"
    target.mkdir(parents=True)
    (target / "demo.c").write_text(ORIGINAL, encoding="utf-8")
    (target / "demo.h").write_text(
        "typedef struct demo_state { int a; int b; int c; int d; } demo_state;\n",
        encoding="utf-8",
    )

    def run_with_labels(labels: tuple[str, ...]):
        catalog_root = tmp_path / ("catalog-" + str(len(labels)))
        for label in labels:
            snapshot = catalog_root / "demo-lib" / label
            snapshot.mkdir(parents=True)
            (snapshot / "demo.c").write_text(ORIGINAL, encoding="utf-8")
        db = tmp_path / ("fp-" + str(len(labels)) + ".sqlite")
        FingerprintDB.build_from_catalog(catalog_root, db)
        result = ScanEngine(
            ScanConfig(
                threads=1,
                fingerprint_db=str(db),
                fingerprint_policy="always",
                max_checkers_per_context=2,
            )
        ).scan(tmp_path / "scan")
        return next(c for c in result.components if c.name == "demo-lib")

    one = run_with_labels(("one",))
    three = run_with_labels(("one", "two", "three"))
    assert three.version == "unknown"
    assert three.fingerprint_exact_matches == one.fingerprint_exact_matches
    assert three.fingerprint_normalized_matches == one.fingerprint_normalized_matches
    assert abs(three.confidence - one.confidence) < 1e-12


def test_catalog_nested_vendor_tree_is_not_owned_by_parent(tmp_path: Path):
    parent = tmp_path / "catalog" / "parent-lib" / "reference"
    nested = parent / "contrib" / "child-lib"
    nested.mkdir(parents=True)
    (parent / "main.c").write_text(ORIGINAL, encoding="utf-8")
    (nested / "child.c").write_text(
        r"""
        int child_alpha(int x) { int y=x+11; y*=7; y^=3; return y; }
        int child_beta(int x) { int y=x+17; y*=9; y^=5; return y; }
        """,
        encoding="utf-8",
    )
    db_path = tmp_path / "fp.sqlite"
    stats = FingerprintDB.build_from_catalog(tmp_path / "catalog", db_path)
    assert stats["nested_roots_pruned"] >= 1
    child_segments = extract_segments((nested / "child.c").read_text(encoding="utf-8"))
    assert child_segments
    db = FingerprintDB(db_path)
    exact, _ = db.lookup_hashes([s.exact_hash for s in child_segments], [])
    assert not exact
