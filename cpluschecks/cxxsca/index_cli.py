from __future__ import annotations
import argparse
import json
from .fingerprint_db import FingerprintDB


def main() -> int:
    p = argparse.ArgumentParser(
        description="Build local C/C++ OSS identity fingerprint database"
    )
    p.add_argument(
        "catalog",
        help="catalog/<component>/<source-label>/source-tree; source-label is provenance only",
    )
    p.add_argument("--db", required=True, help="Output SQLite database")
    p.add_argument("--max-file-bytes", type=int, default=2_000_000)
    p.add_argument("--quiet", action="store_true", help="Disable per-snapshot progress")
    args = p.parse_args()
    stats = FingerprintDB.build_from_catalog(
        args.catalog,
        args.db,
        max_file_bytes=args.max_file_bytes,
        reset=True,
        progress=not args.quiet,
    )
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0
