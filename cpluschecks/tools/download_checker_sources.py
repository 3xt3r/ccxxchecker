from __future__ import annotations
import argparse
import ast
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SKIP_FILES = {"__init__.py", "base_checker.py"}
PRINT_LOCK = threading.Lock()


@dataclass(slots=True)
class SourceSpec:
    checker_file: str
    checker_class: str
    product: str
    vendor: str
    url: str
    destination: str = ""


@dataclass(slots=True)
class DownloadResult:
    checker_file: str
    product: str
    url: str
    destination: str
    status: str
    elapsed_seconds: float
    message: str = ""


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def _literal_string(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        value = ast.literal_eval(node)
    except Exception:
        return ""
    return value.strip() if isinstance(value, str) else ""


def _class_constants(class_node: ast.ClassDef) -> dict[str, str]:
    values: dict[str, str] = {}
    for node in class_node.body:
        if isinstance(node, ast.Assign):
            value = _literal_string(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {
                    "PRODUCT",
                    "VENDOR",
                    "LINK_SOURCE",
                }:
                    values[target.id] = value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id in {
                "PRODUCT",
                "VENDOR",
                "LINK_SOURCE",
            }:
                values[node.target.id] = _literal_string(node.value)
    return values


def discover_sources(checkers_dir: Path) -> tuple[list[SourceSpec], list[str]]:
    specs: list[SourceSpec] = []
    warnings: list[str] = []
    for path in sorted(checkers_dir.glob("*.py")):
        if path.name in SKIP_FILES:
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
        except Exception as exc:
            warnings.append(f"{path.name}: cannot parse: {exc}")
            continue
        found_in_file = False
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            values = _class_constants(node)
            url = values.get("LINK_SOURCE", "").strip()
            product = values.get("PRODUCT", "").strip()
            vendor = values.get("VENDOR", "").strip()
            if not url:
                continue
            if not product:
                product = path.stem
            specs.append(
                SourceSpec(
                    checker_file=path.name,
                    checker_class=node.name,
                    product=product,
                    vendor=vendor,
                    url=url,
                )
            )
            found_in_file = True
        if not found_in_file:
            warnings.append(f"{path.name}: no literal LINK_SOURCE found")
    unique: dict[tuple[str, str], SourceSpec] = {}
    for spec in specs:
        unique[(spec.product.casefold(), spec.url)] = spec
    return (
        sorted(unique.values(), key=lambda s: (s.product.casefold(), s.url)),
        warnings,
    )


def safe_dir_name(value: str) -> str:
    value = value.strip()
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", value)
    value = re.sub(r"\s+", "_", value)
    value = value.strip(" ._")
    return value or "unknown_component"


def split_names(values: Iterable[str]) -> set[str]:
    result: set[str] = set()
    for raw in values:
        for part in raw.split(","):
            part = part.strip().casefold()
            if part:
                result.add(part)
    return result


def matches_name(spec: SourceSpec, names: set[str]) -> bool:
    if not names:
        return False
    candidates = {
        spec.product.casefold(),
        Path(spec.checker_file).stem.casefold(),
        spec.checker_class.casefold(),
    }
    return bool(candidates & names)


def build_destination(
    spec: SourceSpec,
    out_dir: Path,
    label: str,
    flat: bool,
) -> Path:
    if flat:
        return out_dir / safe_dir_name(Path(spec.checker_file).stem)
    return out_dir / safe_dir_name(spec.product) / safe_dir_name(label)


def run_git(
    args: list[str],
    *,
    timeout: int,
    cwd: Path | None = None,
) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        output = ""
        if exc.stdout:
            output = (
                exc.stdout
                if isinstance(exc.stdout, str)
                else exc.stdout.decode("utf-8", "replace")
            )
        return 124, f"timeout after {timeout}s\n{output}".strip()
    except OSError as exc:
        return 127, str(exc)


def clone_one(
    spec: SourceSpec,
    destination: Path,
    *,
    depth: int,
    full_history: bool,
    submodules: bool,
    update: bool,
    timeout: int,
    dry_run: bool,
) -> DownloadResult:
    started = time.perf_counter()
    destination = destination.resolve()
    spec.destination = str(destination)
    if dry_run:
        return DownloadResult(
            checker_file=spec.checker_file,
            product=spec.product,
            url=spec.url,
            destination=str(destination),
            status="DRY_RUN",
            elapsed_seconds=0.0,
            message="would clone",
        )
    if destination.exists():
        git_dir = destination / ".git"
        if not git_dir.exists():
            return DownloadResult(
                checker_file=spec.checker_file,
                product=spec.product,
                url=spec.url,
                destination=str(destination),
                status="ERROR",
                elapsed_seconds=time.perf_counter() - started,
                message="destination exists but is not a Git working tree",
            )
        if not update:
            return DownloadResult(
                checker_file=spec.checker_file,
                product=spec.product,
                url=spec.url,
                destination=str(destination),
                status="SKIPPED",
                elapsed_seconds=time.perf_counter() - started,
                message="already exists; use --update to fetch/pull",
            )
        rc, output = run_git(
            ["git", "-C", str(destination), "pull", "--ff-only"],
            timeout=timeout,
        )
        if rc != 0:
            return DownloadResult(
                checker_file=spec.checker_file,
                product=spec.product,
                url=spec.url,
                destination=str(destination),
                status="ERROR",
                elapsed_seconds=time.perf_counter() - started,
                message=f"git pull failed: {output[-1200:]}",
            )
        if submodules:
            rc, sm_output = run_git(
                [
                    "git",
                    "-C",
                    str(destination),
                    "submodule",
                    "update",
                    "--init",
                    "--recursive",
                    "--depth",
                    "1",
                ],
                timeout=timeout,
            )
            if rc != 0:
                return DownloadResult(
                    checker_file=spec.checker_file,
                    product=spec.product,
                    url=spec.url,
                    destination=str(destination),
                    status="PARTIAL",
                    elapsed_seconds=time.perf_counter() - started,
                    message=f"updated repository, but submodules failed: {sm_output[-1200:]}",
                )
        return DownloadResult(
            checker_file=spec.checker_file,
            product=spec.product,
            url=spec.url,
            destination=str(destination),
            status="UPDATED",
            elapsed_seconds=time.perf_counter() - started,
            message=output[-800:],
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone"]
    if not full_history:
        cmd += ["--depth", str(max(1, depth)), "--single-branch"]
    if submodules:
        cmd += ["--recurse-submodules"]
        if not full_history:
            cmd += ["--shallow-submodules"]
    cmd += [spec.url, str(destination)]
    rc, output = run_git(cmd, timeout=timeout)
    elapsed = time.perf_counter() - started
    if rc != 0:
        if destination.exists() and not (destination / ".git").exists():
            shutil.rmtree(destination, ignore_errors=True)
        return DownloadResult(
            checker_file=spec.checker_file,
            product=spec.product,
            url=spec.url,
            destination=str(destination),
            status="ERROR",
            elapsed_seconds=elapsed,
            message=output[-1600:],
        )
    return DownloadResult(
        checker_file=spec.checker_file,
        product=spec.product,
        url=spec.url,
        destination=str(destination),
        status="CLONED",
        elapsed_seconds=elapsed,
        message=output[-800:],
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Clone upstream repositories declared by checkers/*.py. "
            "Default output layout is catalog/<PRODUCT>/reference/."
        )
    )
    p.add_argument(
        "--checkers",
        default="checkers",
        help="Directory containing checker .py files (default: checkers)",
    )
    p.add_argument(
        "--out",
        default="catalog",
        help="Output directory (default: catalog)",
    )
    p.add_argument(
        "--label",
        default="reference",
        help="Catalog source label (default: reference)",
    )
    p.add_argument(
        "--flat",
        action="store_true",
        help="Use <out>/<checker-name>/ instead of catalog layout",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Parallel Git clones (default: 4)",
    )
    p.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Shallow clone depth (default: 1)",
    )
    p.add_argument(
        "--full-history",
        action="store_true",
        help="Clone complete Git history; can be very large",
    )
    p.add_argument(
        "--submodules",
        action="store_true",
        help="Clone/update Git submodules too; can massively increase size",
    )
    p.add_argument(
        "--update",
        action="store_true",
        help="git pull --ff-only for repositories that already exist",
    )
    p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="NAME[,NAME...]",
        help="Only these checker/product names; may be repeated",
    )
    p.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="NAME[,NAME...]",
        help="Exclude checker/product names; may be repeated",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Timeout per repository in seconds (default: 1800)",
    )
    p.add_argument(
        "--report",
        default="download_sources_report.json",
        help="JSON report path (default: download_sources_report.json)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be cloned without downloading anything",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if shutil.which("git") is None:
        print("ERROR: git is not available in PATH", file=sys.stderr)
        return 2
    checkers_dir = Path(args.checkers).resolve()
    out_dir = Path(args.out).resolve()
    if not checkers_dir.is_dir():
        print(f"ERROR: checker directory not found: {checkers_dir}", file=sys.stderr)
        return 2
    specs, warnings = discover_sources(checkers_dir)
    for warning in warnings:
        log(f"[WARN] {warning}")
    only = split_names(args.only)
    exclude = split_names(args.exclude)
    if only:
        specs = [s for s in specs if matches_name(s, only)]
    if exclude:
        specs = [s for s in specs if not matches_name(s, exclude)]
    if not specs:
        print("No checker repositories selected.")
        return 1
    jobs: list[tuple[SourceSpec, Path]] = []
    for spec in specs:
        dest = build_destination(spec, out_dir, args.label, args.flat)
        spec.destination = str(dest)
        jobs.append((spec, dest))
    print(
        f"[DISCOVERED] repositories={len(jobs)} "
        f"workers={max(1, args.workers)} "
        f"layout={'flat' if args.flat else 'catalog'} "
        f"history={'full' if args.full_history else f'depth={max(1,args.depth)}'} "
        f"submodules={'yes' if args.submodules else 'no'}"
    )
    if args.dry_run:
        for i, (spec, dest) in enumerate(jobs, 1):
            print(f"[{i:03}/{len(jobs):03}] {spec.product} <- {spec.url}")
            print(f"           -> {dest}")
    results: list[DownloadResult] = []
    started_all = time.perf_counter()
    if args.dry_run:
        for spec, dest in jobs:
            results.append(
                clone_one(
                    spec,
                    dest,
                    depth=args.depth,
                    full_history=args.full_history,
                    submodules=args.submodules,
                    update=args.update,
                    timeout=args.timeout,
                    dry_run=True,
                )
            )
    else:
        workers = max(1, min(args.workers, len(jobs)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    clone_one,
                    spec,
                    dest,
                    depth=args.depth,
                    full_history=args.full_history,
                    submodules=args.submodules,
                    update=args.update,
                    timeout=args.timeout,
                    dry_run=False,
                ): (i, spec)
                for i, (spec, dest) in enumerate(jobs, 1)
            }
            completed = 0
            for future in as_completed(futures):
                completed += 1
                _, spec = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = DownloadResult(
                        checker_file=spec.checker_file,
                        product=spec.product,
                        url=spec.url,
                        destination=spec.destination,
                        status="ERROR",
                        elapsed_seconds=0.0,
                        message=f"unexpected exception: {exc}",
                    )
                results.append(result)
                log(
                    f"[{completed:03}/{len(jobs):03}] "
                    f"{result.status:8} "
                    f"{result.product:28} "
                    f"{result.elapsed_seconds:8.2f}s"
                )
                if result.status in {"ERROR", "PARTIAL"} and result.message:
                    log(f"    {result.message.splitlines()[-1][:300]}")
    total_elapsed = time.perf_counter() - started_all
    results.sort(key=lambda r: (r.product.casefold(), r.url))
    counts: dict[str, int] = {}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1
    report = {
        "checkers_dir": str(checkers_dir),
        "out_dir": str(out_dir),
        "layout": "flat" if args.flat else "catalog",
        "source_label": None if args.flat else args.label,
        "full_history": bool(args.full_history),
        "depth": None if args.full_history else max(1, args.depth),
        "submodules": bool(args.submodules),
        "workers": max(1, args.workers),
        "dry_run": bool(args.dry_run),
        "elapsed_seconds": round(total_elapsed, 3),
        "counts": counts,
        "warnings": warnings,
        "results": [asdict(r) for r in results],
    }
    report_path = Path(args.report)
    if report_path.parent != Path("."):
        report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print()
    print("[SUMMARY]")
    print(f"selected={len(results)} elapsed={total_elapsed:.2f}s")
    for status in sorted(counts):
        print(f"{status.lower()}={counts[status]}")
    print(f"report={report_path}")
    errors = counts.get("ERROR", 0)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
