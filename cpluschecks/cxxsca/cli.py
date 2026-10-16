from __future__ import annotations
import argparse
from .engine import ScanConfig, ScanEngine


def main() -> int:
    p = argparse.ArgumentParser(
        description="Component-context C/C++ source SCA scanner"
    )
    p.add_argument(
        "path", help="Source tree or directory containing several repositories"
    )
    p.add_argument(
        "--sbom", required=True, help="Output CycloneDX SBOM with known versions"
    )
    p.add_argument(
        "--unknown", required=True, help="Output CycloneDX SBOM with unknown versions"
    )
    p.add_argument(
        "--stats", default="", help="Optional JSON performance/detection stats"
    )
    p.add_argument(
        "--fingerprint-rejections",
        default="",
        help="Optional JSON report with every rejected fingerprint candidate and reject_reason",
    )
    p.add_argument("--fingerprint-db", default="", help="SQLite fingerprint database")
    p.add_argument(
        "--fingerprint-policy",
        choices=("off", "fallback", "always"),
        default="fallback",
        help=(
            "Fingerprint policy. In strict v0.10 identity mode, fallback/always both "
            "validate every context with fingerprints; off emits no confirmed components."
        ),
    )
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--max-checkers", type=int, default=10)
    p.add_argument(
        "--include-tests-docs",
        action="store_true",
        help="Include soft-skipped docs/examples/benchmarks. Test/gtest paths remain hard-excluded.",
    )
    args = p.parse_args()
    cfg = ScanConfig(
        threads=args.threads,
        max_checkers_per_context=args.max_checkers,
        fingerprint_db=args.fingerprint_db,
        fingerprint_policy=args.fingerprint_policy,
        include_soft_skips=args.include_tests_docs,
    )
    engine = ScanEngine(cfg)
    result = engine.scan(args.path)
    engine.write_outputs(
        result,
        args.sbom,
        args.unknown,
        args.stats or None,
        args.fingerprint_rejections or None,
    )
    print(
        f"[v2] files={result.stats.files_indexed} contexts={result.stats.component_contexts} "
        f"components={len(result.components)} checker_calls={result.stats.checker_invocations} "
        f"fp_contexts={result.stats.fingerprint_contexts} fp_segments={result.stats.fingerprint_segments} "
        f"cmake_declared={result.stats.cmake_declarations_found}"
    )
    for c in result.components:
        print(
            f"[FOUND] {c.name}@{c.version} root={c.root} confidence={c.confidence:.3f} "
            f"methods={','.join(c.methods)}"
        )
    return 0
