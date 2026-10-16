from pathlib import Path
from cxxsca import ScanConfig, ScanEngine
from cxxsca.fingerprint_db import FingerprintDB


def _write_root_libhtp(root: Path, version: str):
    root.mkdir(parents=True, exist_ok=True)
    (root / "VERSION").write_text(f"PKG_VERSION = {version}\n", encoding="utf-8")
    (root / "configure.ac").write_text("AC_INIT([LibHTP], [x])\n", encoding="utf-8")
    (root / "htp.c").write_text(
        "/* @author Ivan Ristic <ivanr@webkreator.com> */\n"
        "int htp_root_demo(int a) { int x=a; x+=2; x*=3; return x; }\n"
        "int htp_root_demo2(int a) { int x=a; x^=17; x+=11; return x; }\n"
        "int htp_root_demo3(int a) { int x=a*13; x^=29; x-=7; return x; }\n"
        "int htp_root_demo4(int a) { int x=a+37; x*=3; x^=5; return x; }\n",
        encoding="utf-8",
    )
    (root / "htp.h").write_text(
        "typedef struct htp_root { int a; int b; int c; } htp_root;\n",
        encoding="utf-8",
    )


def test_root_level_component_does_not_create_literal_root_directory(tmp_path: Path):
    catalog_root = tmp_path / "catalog"
    _write_root_libhtp(catalog_root / "libhtp" / "reference", "9.9.9")
    db = tmp_path / "fingerprints.sqlite"
    FingerprintDB.build_from_catalog(catalog_root, db)
    scan = tmp_path / "scan"
    _write_root_libhtp(scan, "0.5.49")
    result = ScanEngine(
        ScanConfig(threads=1, fingerprint_db=str(db), fingerprint_policy="fallback")
    ).scan(scan)
    hits = [c for c in result.components if c.name == "libhtp"]
    assert hits
    assert hits[0].root == "(root)"
    assert hits[0].version == "0.5.49"
