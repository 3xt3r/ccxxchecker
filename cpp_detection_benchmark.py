#!/usr/bin/env python3
"""Reproducible C/C++ product-presence benchmark for CycloneDX JSON scanners.

No third-party Python packages required. Supply local source trees and a scanner
command template containing {src} and {out}. See --help for examples.
"""
import argparse
import csv
import hashlib
import json
import random
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

EXTENSIONS = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx'}
IGNORE = {'.git', '.svn', '.hg', 'node_modules', '.venv', 'venv', '__pycache__', 'build', '.tox'}
MODES = ('original', 'format_30', 'code_10', 'code_30', 'code_50', 'partial_10', 'partial_25', 'partial_50', 'cmake_only')


def slug(s):
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', s).strip('._') or 'product'


def source_files(root):
    return sorted((p for p in root.rglob('*') if p.is_file() and p.suffix.lower() in EXTENSIONS and not any(x in IGNORE for x in p.relative_to(root).parts)), key=lambda p: p.as_posix())


def clone_tree(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*IGNORE), symlinks=False)


def change_content(p, kind):
    try:
        data = p.read_bytes()
        # Preserve binary files and files containing non-UTF8 sequences.
        text = data.decode('utf-8')
    except (UnicodeError, OSError):
        return False
    if '\x00' in text:
        return False
    # Test non-semantic edits separately from actual text edits.
    if kind == 'format':
        text = '/* cpp-benchmark: comment-only */\n' + text
    else:
        # A harmless preprocessor-disabled source-code block. This changes
        # bytes, but is NOT a real semantic code modification; report accordingly.
        text += '\n#if 0\nstatic int cpp_benchmark_synthetic_code = 42;\n#endif\n'
    p.write_text(text, encoding='utf-8')
    return True


def make_case(src, dst, mode, seed, product):
    clone_tree(src, dst)
    files = source_files(dst)
    rng = random.Random(seed)
    before = len(files)
    changed = 0
    if mode.startswith(('format_', 'code_')):
        pct = int(mode.split('_')[1])
        chosen = rng.sample(files, min(len(files), round(len(files) * pct / 100)))
        changed = sum(change_content(p, 'format' if mode.startswith('format_') else 'code') for p in chosen)
    elif mode.startswith('partial_'):
        pct = int(mode.split('_')[1])
        retained = set(rng.sample(files, min(len(files), max(1, round(len(files) * pct / 100))))) if files else set()
        for p in files:
            if p not in retained:
                p.unlink()
        # Remove build declarations so they don't turn a source subset into a
        # declaration-based hit, while preserving non-source files for context.
        for p in list(dst.rglob('*')):
            if p.is_file() and (p.name == 'CMakeLists.txt' or p.suffix.lower() in {'.cmake', '.pro'}):
                p.unlink()
    elif mode == 'cmake_only':
        shutil.rmtree(dst)
        dst.mkdir(parents=True)
        (dst / 'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.16)\nproject(benchmark LANGUAGES CXX)\ninclude(FetchContent)\nFetchContent_Declare(' + slug(product) + ' URL https://invalid.example.test/source.tar.gz)\n# Declaration only; no downloaded code.\n', encoding='utf-8')
    return dict(source_files_before=before, source_files_after=len(source_files(dst)), files_modified=changed)


def props(component, key):
    return [str(p.get('value', '')) for p in component.get('properties', []) if p.get('name') == key]


def evidence_kind(component):
    methods = ','.join(props(component, 'detection.identity_methods') + props(component, 'detection.methods')).lower()
    if any(x in methods for x in ('hash:exact', 'hash:normalized', 'hash:snippet', 'checker:signature', 'checker:root-anchor')):
        return 'DETECTED'
    if any(x in methods for x in ('build:', 'cmake:', 'meson:', 'autoconf:')):
        return 'DECLARED'
    return 'UNCONFIRMED'


def collect_components(obj):
    if isinstance(obj, dict) and isinstance(obj.get('components'), list):
        return obj['components']
    if isinstance(obj, list):
        return obj
    raise ValueError('Expected CycloneDX JSON object with components[] or a component list')


def compare_names(found, expected, aliases):
    norm = lambda x: re.sub(r'[^a-z0-9]+', '', str(x).casefold())
    return norm(found) in {norm(expected), *(norm(a) for a in aliases.get(expected, []))}


def parse_product(s):
    if '=' not in s:
        raise argparse.ArgumentTypeError('Use PRODUCT=/absolute/or/relative/path')
    name, path = s.split('=', 1)
    if not name.strip() or not Path(path).is_dir():
        raise argparse.ArgumentTypeError(f'Invalid source directory: {s}')
    return name.strip(), Path(path).expanduser().resolve()


def run_scanner(template, src, out, timeout):
    cmd = template.replace('{src}', shlex.quote(str(src))).replace('{out}', shlex.quote(str(out)))
    # Execute as shell to support user's CLI flags and redirection. The command
    # template is trusted input supplied by the user.
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python3 cpp_detection_benchmark.py --product flatbuffers=/src/flatbuffers --product brotli=/src/brotli \\\n    --scanner "python3 scan.py --src {src} --output {out}" --output-dir ./cpp-results\n\n'
               'Scanner must write CycloneDX JSON at {out}; product names are compared using --aliases JSON.')
    ap.add_argument('--product', action='append', type=parse_product, required=True, help='Repeat PRODUCT=SOURCE_DIR')
    ap.add_argument('--scanner', required=True, help='CLI command template with {src} and {out}')
    ap.add_argument('--output-dir', default='./cpp-benchmark-results')
    ap.add_argument('--aliases', help='Optional JSON mapping product -> alternative SBOM names')
    ap.add_argument('--repeats', type=int, default=3, help='Independent deterministic samples per mutation/partial case (default 3)')
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--timeout', type=int, default=1800, help='Scanner timeout in seconds')
    ap.add_argument('--keep-cases', action='store_true', help='Keep prepared source trees (can take substantial disk space)')
    ap.add_argument('--max-files', type=int, default=0, help='Skip huge projects with more than N source files (0 = unlimited)')
    args = ap.parse_args()
    if '{src}' not in args.scanner or '{out}' not in args.scanner:
        ap.error('--scanner must contain both {src} and {out}')
    if args.repeats < 1:
        ap.error('--repeats must be >= 1')
    names = [n for n, _ in args.product]
    if len(names) != len(set(names)):
        ap.error('Duplicate product names')
    aliases = json.loads(Path(args.aliases).read_text(encoding='utf-8')) if args.aliases else {}
    root = Path(args.output_dir).expanduser().resolve()
    if root == Path('/') or any(root == src or root in src.parents for _, src in args.product):
        ap.error('Unsafe output directory')
    if any(root == src or src in root.parents for _, src in args.product):
        ap.error('Output directory must not be inside a source tree')
    root.mkdir(parents=True, exist_ok=True)
    case_root = root / 'cases'
    sbom_root = root / 'sboms'
    sbom_root.mkdir(exist_ok=True)
    case_root.mkdir(exist_ok=True)
    rows = []
    case_specs = []
    for name, src in args.product:
        nfiles = len(source_files(src))
        if args.max_files and nfiles > args.max_files:
            print(f'SKIP {name}: {nfiles} source files > --max-files', file=sys.stderr)
            continue
        for mode in MODES:
            count = 1 if mode in ('original', 'cmake_only') else args.repeats
            for repeat in range(count):
                case_specs.append((name, src, mode, repeat))
    for i, (name, src, mode, repeat) in enumerate(case_specs, 1):
        case_id = f'{slug(name)}__{mode}__r{repeat+1}'
        case_path = case_root / case_id
        sbom = sbom_root / (case_id + '.json')
        if sbom.exists():
            sbom.unlink()
        case_seed = int(hashlib.sha256(f'{args.seed}|{name}|{mode}|{repeat}'.encode()).hexdigest()[:15], 16)
        info = make_case(src, case_path, mode, case_seed, name)
        print(f'[{i}/{len(case_specs)}] {case_id}: {info["source_files_after"]} source files', flush=True)
        status, components, error = 'OK', [], ''
        try:
            p = run_scanner(args.scanner, case_path, sbom, args.timeout)
            if p.returncode != 0:
                status, error = 'SCAN_FAILED', (p.stderr or p.stdout)[-1000:]
            elif not sbom.is_file():
                status, error = 'NO_OUTPUT', 'No JSON created at {out}'
            else:
                components = collect_components(json.loads(sbom.read_text(encoding='utf-8')))
        except (subprocess.TimeoutExpired, ValueError, json.JSONDecodeError, OSError) as e:
            status, error = 'SCAN_ERROR', str(e)[-1000:]
        for target in names:
            matches = [c for c in components if compare_names(c.get('name', ''), target, aliases)]
            kinds = [evidence_kind(c) for c in matches]
            detection = 'DETECTED' if 'DETECTED' in kinds else ('DECLARED' if 'DECLARED' in kinds else ('UNCONFIRMED' if matches else 'ABSENT'))
            # Cross-product negatives may actually contain a vendored copy of the
            # target. They are marked REVIEW, never silently used as true negatives.
            truth = 'PRESENT' if target == name and mode != 'cmake_only' else ('ABSENT' if target == name else 'REVIEW')
            rows.append(dict(case=case_id, source_product=name, target_product=target,
                mode=mode, repeat=repeat+1, ground_truth=truth, detection=detection,
                scanner_status=status, n_components=len(components), matched_components=len(matches),
                evidence_files=';'.join(dict.fromkeys(x for c in matches for x in props(c, 'evidence.file'))),
                identity_methods=';'.join(dict.fromkeys(x for c in matches for x in props(c, 'detection.identity_methods'))),
                **info, error=error.replace('\n',' ')))
        if not args.keep_cases:
            shutil.rmtree(case_path)
    if not rows:
        ap.error('No eligible cases generated')
    with (root / 'results.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)
    evaluated = [r for r in rows if r['ground_truth'] != 'REVIEW' and r['scanner_status'] == 'OK']
    tp = sum(r['ground_truth']=='PRESENT' and r['detection']=='DETECTED' for r in evaluated)
    fn = sum(r['ground_truth']=='PRESENT' and r['detection']!='DETECTED' for r in evaluated)
    fp = sum(r['ground_truth']=='ABSENT' and r['detection']=='DETECTED' for r in evaluated)
    tn = sum(r['ground_truth']=='ABSENT' and r['detection']!='DETECTED' for r in evaluated)
    def ratio(a, b):
        return round(a/b, 4) if b else None
    metrics = dict(tp=tp, fn=fn, fp=fp, tn=tn, recall=ratio(tp,tp+fn),
                   precision=ratio(tp,tp+fp), false_positive_rate=ratio(fp,fp+tn),
                   successful_scans=sum(r['scanner_status']=='OK' and r['target_product']==r['source_product'] for r in rows),
                   failed_scans=sum(r['scanner_status']!='OK' and r['target_product']==r['source_product'] for r in rows),
                   caveat='Precision/FPR use only explicit product-vs-CMake-only negatives. Cross-product detections require manual truth review.')
    by_mode = {}
    for mode in MODES:
        r = [x for x in evaluated if x['mode']==mode and x['ground_truth']=='PRESENT']
        by_mode[mode] = dict(n=len(r), detected=sum(x['detection']=='DETECTED' for x in r), detection_rate=ratio(sum(x['detection']=='DETECTED' for x in r),len(r)))
    metrics['by_mode'] = by_mode
    (root/'metrics.json').write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding='utf-8')
    (root/'README.txt').write_text('results.csv: all product/case predictions; REVIEW is cross-product ground truth not assumed absent.\n'
        'metrics.json: initial metrics; scanner failures excluded.\n'
        'A CMake-only case has no source and should not be DETECTED.\n'
        'code_10/30/50 inserts a disabled code block into selected files; this is byte-level robustness, not semantic rewriting.\n'
        'Partial cases randomly retain source files, but may leave metadata and headers that still mention the product.\n'
        'Use curated, independently checked negative projects for a credible false-positive benchmark.\n', encoding='utf-8')
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f'\nResults: {root / "results.csv"}')

if __name__ == '__main__':
    main()
