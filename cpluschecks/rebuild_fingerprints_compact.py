#!/usr/bin/env python3
"""Automatically build a multi-release C/C++ identity fingerprint catalog/DB.

Run from any directory: python rebuild_fingerprints.py --project /path/to/cxxsca
Requires git, Python >= 3.10; no extra Python dependencies.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

PERCENTILES = (10, 25, 50, 75, 90)  # additionally include the latest stable release
VERSION_RX = re.compile(r"(?i)^(?:(?:v|release[-_/]|version[-_/])?)(\d+(?:[._]\d+){1,5})(?:[.-]?(?:stable|final))?$")
UNSTABLE_RX = re.compile(r"(?i)(?:alpha|beta|rc\d*|pre\d*|preview|snapshot|nightly|dev\d*|test|experimental)")


def run(args, *, cwd=None, timeout=240, capture=True):
    env = os.environ.copy()
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1"})
    return subprocess.run(args, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                          capture_output=capture, timeout=timeout, check=False)


def discover(checkers: Path):
    """Parse class constants; do not import/execute checker code."""
    result = {}
    for path in sorted(checkers.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                values = {}
                for assignment in node.body:
                    if isinstance(assignment, ast.Assign):
                        names = [n.id for n in assignment.targets if isinstance(n, ast.Name)]
                        value = assignment.value
                    elif isinstance(assignment, ast.AnnAssign) and isinstance(assignment.target, ast.Name):
                        names, value = [assignment.target.id], assignment.value
                    else:
                        continue
                    if value is not None and isinstance(value, ast.Constant) and isinstance(value.value, str):
                        for name in names:
                            values[name] = value.value
                product, repo = values.get("PRODUCT", "").strip(), values.get("LINK_SOURCE", "").strip()
                if not product or not repo:
                    continue
                url = urlsplit(repo)
                if url.scheme != "https" or url.hostname not in {"github.com", "gitlab.com", "codeberg.org", "git.savannah.gnu.org"}:
                    continue
                if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+\-]*", product):
                    continue
                result.setdefault(product.lower(), repo.rstrip("/"))
        except (SyntaxError, OSError) as exc:
            print(f"[WARN] Cannot inspect {path.name}: {exc}", file=sys.stderr)
    return result


def tags_for(repo, timeout, component=None):
    proc = run(["git", "ls-remote", "--tags", "--refs", repo], timeout=timeout)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip()[-350:] or "git ls-remote failed")
    version_tags = {}
    for line in proc.stdout.splitlines():
        ref = line.split("\t")[-1]
        if not ref.startswith("refs/tags/"):
            continue
        tag = ref.removeprefix("refs/tags/")
        if UNSTABLE_RX.search(tag):
            continue
        match = VERSION_RX.fullmatch(tag)
        if not match and component:
            # Projects such as Suricata use component-prefixed tags: suricata-7.0.0.
            # Only strip the *current component name* to avoid unrelated release tags.
            prefix = re.match(r"^" + re.escape(component) + r"[-_/]", tag, flags=re.I)
            if prefix:
                match = VERSION_RX.fullmatch(tag[prefix.end():])
        if not match:
            continue
        ver = tuple(int(x) for x in match.group(1).replace("_", ".").split("."))
        # Different names may designate the same numeric release. Prefer the shorter tag.
        if ver not in version_tags or len(tag) < len(version_tags[ver]):
            version_tags[ver] = tag
    return [version_tags[ver] for ver in sorted(version_tags)]


def choose(tags):
    """Round-half-up nearest rank in an ordered release population."""
    positions = sorted({len(tags) - 1} | {min(len(tags)-1, (p*(len(tags)-1)*2+100)//200) for p in PERCENTILES})
    return [tags[i] for i in positions]


def safe_label(tag):
    """Never interpolate a tag into a path without canonicalization."""
    name = re.sub(r"[^A-Za-z0-9._-]", "_", tag)
    return "release_" + name[:100]


def download(repo, tag, target, timeout):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cxxsca-fetch-", dir=target.parent) as temp:
        temporary = Path(temp) / "checkout"
        # No submodule initialization or arbitrary build hooks.
        cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
               "clone", "--quiet", "--depth", "1", "--single-branch", "--no-recurse-submodules",
               "--branch", tag, repo, str(temporary)]
        proc = run(cmd, timeout=timeout)
        if proc.returncode:
            raise RuntimeError(proc.stderr.strip()[-350:] or "git clone failed")
        shutil.rmtree(temporary / ".git", ignore_errors=True)
        # Clean Git metadata in nested dirs, but do not follow symbolic links.
        for base, dirs, files in os.walk(temporary, followlinks=False):
            for directory in list(dirs):
                path = Path(base) / directory
                if path.is_symlink() or directory == ".git":
                    if path.is_symlink():
                        path.unlink()
                    else:
                        shutil.rmtree(path, ignore_errors=True)
                    dirs.remove(directory)
            for file in files:
                path = Path(base) / file
                if path.is_symlink():
                    path.unlink()
        # Published only after a complete checkout.
        temporary.rename(target)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--project", type=Path, default=Path(__file__).resolve().parent,
                   help="directory with checkers/ and build_fingerprint_index.py")
    p.add_argument("--catalog", type=Path, default=None, help="directory for downloaded reference trees")
    p.add_argument("--db", type=Path, default=None, help="output SQLite database")
    p.add_argument("--only", nargs="*", default=[], help="component names to process; default: all checkers")
    p.add_argument("--max-components", type=int, default=0, help="limit for testing, 0 = all")
    p.add_argument("--timeout", type=int, default=600, help="Git timeout per command, seconds")
    p.add_argument("--no-build", action="store_true", help="download reference trees only")
    p.add_argument("--dry-run", action="store_true", help="list repos and chosen tags without downloading")
    p.add_argument("--skip-failed", action="store_true", help="build even if some components have no downloaded releases")
    p.add_argument("--clean-catalog", action="store_true", help="DELETE catalog before download (fresh rebuild)")
    args = p.parse_args()
    project = args.project.resolve()
    catalog = (args.catalog or (project / "fingerprint_catalog")).resolve()
    db = (args.db or (project / "fingerprints_compact.sqlite")).resolve()
    if not (project / "checkers").is_dir() or not (project / "build_fingerprint_index.py").is_file():
        p.error("--project must contain checkers/ and build_fingerprint_index.py")
    if catalog == project or catalog == project.parent or catalog == Path(catalog.anchor) or db == catalog or catalog in db.parents:
        p.error("unsafe --catalog path")
    if args.clean_catalog and not args.dry_run:
        shutil.rmtree(catalog) if catalog.exists() else None
    if not args.dry_run:
        catalog.mkdir(parents=True, exist_ok=True)
    components = discover(project / "checkers")
    if args.only:
        selected = {item.lower() for item in args.only}
        missing = selected - components.keys()
        if missing:
            p.error("unknown/unsupported checker names: " + ", ".join(sorted(missing)))
        components = {name: url for name, url in components.items() if name in selected}
    if args.max_components > 0:
        components = dict(list(components.items())[:args.max_components])
    if not components:
        p.error("no supported repository URLs discovered")
    manifest = {"strategy": "p10_p25_p50_p75_p90_latest", "source": "checker LINK_SOURCE", "components": {}, "errors": {}}
    for index, (name, repo) in enumerate(components.items(), 1):
        print(f"[{index}/{len(components)}] {name}: {repo}", flush=True)
        try:
            all_tags = tags_for(repo, args.timeout, name)
            if not all_tags:
                raise RuntimeError("no stable numeric version tags found")
            picked = choose(all_tags)
            info = {"repo": repo, "available_releases": len(all_tags), "selected_tags": picked, "downloaded": []}
            manifest["components"][name] = info
            print(f"  stable tags={len(all_tags)} selected={picked}", flush=True)
            for tag in picked:
                target = catalog / name / safe_label(tag)
                if args.dry_run:
                    continue
                if target.is_dir() and any(target.iterdir()):
                    print(f"  cached: {tag}", flush=True)
                    info["downloaded"].append(tag)
                    continue
                if target.exists():
                    shutil.rmtree(target)
                try:
                    download(repo, tag, target, args.timeout)
                    info["downloaded"].append(tag)
                    print(f"  downloaded: {tag}", flush=True)
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    info.setdefault("failed_tags", {})[tag] = str(exc)
                    print(f"  FAILED {tag}: {exc}", file=sys.stderr, flush=True)
            if not args.dry_run and not info["downloaded"]:
                manifest["errors"][name] = "all selected release downloads failed"
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            manifest["errors"][name] = str(exc)
            print(f"  FAILED: {exc}", file=sys.stderr, flush=True)
    if not args.dry_run:
        manifest_path = catalog / "build_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Manifest: {manifest_path}")
    failed = manifest["errors"]
    incomplete = {name: list(info.get("failed_tags", {})) for name, info in manifest["components"].items() if info.get("failed_tags")}
    if (failed or incomplete) and not args.skip_failed:
        print(f"[ERROR] {len(failed)} components failed and {len(incomplete)} have incomplete release snapshots; DB NOT rebuilt. Use --skip-failed to allow partial DB.", file=sys.stderr)
        return 2
    if not args.dry_run and not args.no_build:
        print("[BUILD] Rebuilding fingerprint database from the catalog...", flush=True)
        proc = subprocess.run([sys.executable, str(project / "build_fingerprint_index.py"), str(catalog), "--db", str(db)], cwd=project)
        if proc.returncode:
            return proc.returncode
        print(f"[DONE] {db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
