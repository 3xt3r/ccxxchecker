from pathlib import Path
from cxxsca import ScanConfig, ScanEngine
from cxxsca.fingerprint_db import FingerprintDB


def _write_libhtp(root: Path, rel: str, version: str):
    d = root / rel
    (d / "htp").mkdir(parents=True, exist_ok=True)
    (d / "VERSION").write_text(f"PKG_VERSION = {version}\n", encoding="utf-8")
    (d / "configure.ac").write_text(
        "AC_INIT([LibHTP], [m4_esyscmd(./get-version.sh VERSION)])\n",
        encoding="utf-8",
    )
    (d / "htp" / "htp.c").write_text(
        "/* @author Ivan Ristic <ivanr@webkreator.com> */\n"
        "int htp_demo(int x) { if (x > 2) return x + 1; return x - 1; }\n"
        "int htp_demo2(int x) { int y=x*7; if (y > 10) y-=3; return y; }\n"
        "int htp_demo3(int x) { int y=x*11; y^=19; if (y < 3) y+=23; return y; }\n"
        "int htp_demo4(int x) { int y=x+31; y*=5; if (y > 100) y-=17; return y; }\n",
        encoding="utf-8",
    )
    (d / "htp" / "htp.h").write_text(
        "typedef struct htp_demo_t { int x; int y; int z; } htp_demo_t;\n",
        encoding="utf-8",
    )


def _build_libhtp_db(tmp_path: Path) -> Path:
    catalog = tmp_path / "catalog"
    _write_libhtp(catalog, "libhtp/reference", "9.9.9-catalog-label-is-not-version")
    db = tmp_path / "fingerprints.sqlite"
    FingerprintDB.build_from_catalog(catalog, db)
    return db


def test_libhtp_renamed_vendor_root(tmp_path: Path):
    db = _build_libhtp_db(tmp_path)
    scan = tmp_path / "scan"
    _write_libhtp(scan, "third_party/htp", "0.5.49")
    result = ScanEngine(
        ScanConfig(threads=1, fingerprint_db=str(db), fingerprint_policy="fallback")
    ).scan(scan)
    found = [(c.name, c.version, c.root) for c in result.components]
    assert ("libhtp", "0.5.49", "third_party/htp") in found
    hit = next(c for c in result.components if c.name == "libhtp")
    assert set(hit.identity_methods) <= {"hash:exact", "hash:normalized"}
    assert hit.identity_methods
    assert "checker:version" in hit.methods


def test_two_libhtp_copies_are_preserved(tmp_path: Path):
    db = _build_libhtp_db(tmp_path)
    scan = tmp_path / "scan"
    _write_libhtp(scan, "vendor/htp-old", "0.5.48")
    _write_libhtp(scan, "vendor/htp-new", "0.5.49")
    result = ScanEngine(
        ScanConfig(threads=1, fingerprint_db=str(db), fingerprint_policy="fallback")
    ).scan(scan)
    versions = sorted(
        (c.version, c.root) for c in result.components if c.name == "libhtp"
    )
    assert versions == [("0.5.48", "vendor/htp-old"), ("0.5.49", "vendor/htp-new")]
