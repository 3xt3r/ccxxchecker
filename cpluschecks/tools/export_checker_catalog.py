from __future__ import annotations
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cxxsca.checker_catalog import discover_checker_classes


def main() -> int:
    catalog: dict[str, str] = {}
    for cls in discover_checker_classes():
        vendor = (getattr(cls, "VENDOR", "") or "").strip().lower()
        product = (getattr(cls, "PRODUCT", "") or "").strip().lower()
        link_source = (getattr(cls, "LINK_SOURCE", "") or "").strip()
        if not (vendor and product and link_source):
            continue
        catalog[f"{vendor}:{product}"] = link_source
    json.dump(catalog, sys.stdout, ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
