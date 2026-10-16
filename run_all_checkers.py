#!/usr/bin/env python3
"""Download sources for every checker, build fingerprint DB, validate product detection."""
from __future__ import annotations
import argparse,csv,json,random,shutil,sqlite3,subprocess,sys,hashlib
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SCANNER=ROOT/'cpluschecks'
EXCLUDE={'.git','.hg','.svn','build','node_modules','.venv','__pycache__'}
SRC_EXT={'.c','.cc','.cpp','.cxx','.h','.hh','.hpp','.hxx'}

def execute(cmd,log,cwd=None):
    log.parent.mkdir(parents=True,exist_ok=True)
    print('$',' '.join(map(str,cmd)),flush=True)
    with log.open('w',encoding='utf8') as f:
        p=subprocess.run(list(map(str,cmd)),cwd=cwd,stdout=f,stderr=subprocess.STDOUT)
    if p.returncode: print(f'ERROR exit={p.returncode}: {log}',file=sys.stderr)
    return p.returncode

def manifest(catalog):
    sys.path.insert(0,str(SCANNER/'tools'))
    from download_checker_sources import discover_sources,safe_dir_name
    specs,warnings=discover_sources(SCANNER/'checkers')
    records=[]
    for s in specs:
        path=catalog/safe_dir_name(s.product)/'reference'
        records.append({'product':s.product,'checker':s.checker_file,'url':s.url,'path':str(path),'available':(path/'.git').exists()})
    return records,warnings

def modify(original,target,ratio,seed):
    if target.exists():shutil.rmtree(target)
    shutil.copytree(original,target,ignore=shutil.ignore_patterns(*EXCLUDE),symlinks=True)
    files=sorted(p for p in target.rglob('*') if p.is_file() and not p.is_symlink() and p.suffix.lower() in SRC_EXT and p.stat().st_size < 2_000_000)
    rng=random.Random(seed);count=max(1,round(len(files)*ratio)) if files else 0
    for file in rng.sample(files,min(count,len(files))):
        with file.open('ab') as f:f.write(b'\n/* CPP_SCA_BENCHMARK_COMMENT */\n')
    return count,len(files)

def scan(source,db,out,log,threads):
    known=out.with_suffix('.known.json');unknown=out.with_suffix('.unknown.json')
    command=[sys.executable,str(SCANNER/'scanner.py'),str(source),'--fingerprint-db',str(db),'--fingerprint-policy','always','--sbom',str(known),'--unknown',str(unknown),'--threads',str(threads)]
    status=execute(command,log,cwd=SCANNER)
    if status:return None
    try:
        components=[]
        for fp in (known,unknown):components+=json.loads(fp.read_text(encoding='utf8')).get('components',[])
        out.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':components},ensure_ascii=False,indent=2),encoding='utf8')
        return components
    except Exception as e:
        print('Invalid SBOM:',e,file=sys.stderr);return None

def fingerprint_confirmed(component):
    props={}
    for p in component.get('properties',[]):props.setdefault(p.get('name'),[]).append(str(p.get('value','')))
    methods=' '.join(props.get('detection.identity_methods',[])).lower()
    return 'true' in [v.lower() for v in props.get('detection.identity_confirmed',[])] and 'hash:' in methods

def names(components):
    return {str(c.get('name','')).casefold().strip() for c in components if fingerprint_confirmed(c)}

def main():
    p=argparse.ArgumentParser(description='All checker product detection benchmark')
    p.add_argument('--workdir',default='all_checker_work');p.add_argument('--workers',type=int,default=2);p.add_argument('--threads',type=int,default=2)
    p.add_argument('--skip-download',action='store_true');p.add_argument('--skip-build',action='store_true');p.add_argument('--update',action='store_true')
    p.add_argument('--dry-run',action='store_true');p.add_argument('--limit',type=int,default=0,help='Test only first N downloaded products; download/build still all')
    p.add_argument('--modify',type=float,default=.30,help='Fraction of files to append comments to')
    p.add_argument('--db',default='',help='Existing database; required with --skip-build if default DB missing')
    a=p.parse_args(); work=Path(a.workdir).expanduser().resolve();work.mkdir(parents=True,exist_ok=True)
    catalog=work/'catalog';reports=work/'reports';reports.mkdir(exist_ok=True)
    records,warnings=manifest(catalog)
    (reports/'checker_manifest.json').write_text(json.dumps({'checkers':records,'warnings':warnings},ensure_ascii=False,indent=2),encoding='utf8')
    print(f'Checker repositories: {len(records)}; warnings: {len(warnings)}')
    if a.dry_run:
        for item in records:print(item['product'],item['url'])
        return 0
    if not a.skip_download:
        cmd=[sys.executable,str(SCANNER/'tools/download_checker_sources.py'),'--checkers',str(SCANNER/'checkers'),'--out',str(catalog),'--workers',str(a.workers),'--report',str(reports/'downloads.json')]
        if a.update:cmd+=['--update']
        execute(cmd,reports/'download.log',cwd=SCANNER)
    records,warnings=manifest(catalog)
    (reports/'checker_manifest.json').write_text(json.dumps({'checkers':records,'warnings':warnings},ensure_ascii=False,indent=2),encoding='utf8')
    available=[r for r in records if r['available']]
    unavailable=[r for r in records if not r['available']]
    print(f'Downloaded/available: {len(available)}; missing: {len(unavailable)}')
    (reports/'missing_sources.json').write_text(json.dumps(unavailable,indent=2,ensure_ascii=False),encoding='utf8')
    if not available:print('No sources available. See download.log',file=sys.stderr);return 2
    db=Path(a.db).expanduser().resolve() if a.db else (work/'fingerprints.sqlite')
    if not a.skip_build:
        if execute([sys.executable,str(SCANNER/'build_fingerprint_index.py'),str(catalog),'--db',str(db)],reports/'build.log',cwd=SCANNER):return 3
    if not db.is_file():print('Database missing:',db,file=sys.stderr);return 3
    try:
        with sqlite3.connect(db) as connection:
            ok=connection.execute('PRAGMA integrity_check').fetchone()[0]
            schema=[r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if ok!='ok' or not schema:raise ValueError(f'integrity={ok}, tables={schema}')
    except Exception as e:print('Invalid database:',e,file=sys.stderr);return 3
    (reports/'db_validation.json').write_text(json.dumps({'integrity':ok,'tables':schema,'bytes':db.stat().st_size},indent=2),encoding='utf8')
    chosen=available[:a.limit] if a.limit else available
    # Cross-target false positives: every matched foreign product is flagged for review, not blindly labeled false.
    rows=[]
    for ix,r in enumerate(chosen,1):
        product=r['product'];src=Path(r['path']);print(f'[{ix}/{len(chosen)}] VERIFY {product}',flush=True)
        cases=[('original',src)]
        negative=work/'negative'/f'{ix:03d}_{product}'
        negative.mkdir(parents=True,exist_ok=True)
        # Build-only reference, not actual vendored source. It must not constitute fingerprint identity.
        (negative/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.16)\nproject(negative_control)\n# Declared name only: '+product+'\n',encoding='utf8')
        (negative/'dummy.cpp').write_text('int unrelated_benchmark_dummy() { return 42; }\n',encoding='utf8')
        cases.append(('negative_no_source',negative))
        modified=work/'mutated'/f'{ix:03d}_{product}'
        try:
            num,total=modify(src,modified,a.modify,seed=42+ix)
            cases.append(('comment_modified',modified))
        except Exception as e:
            rows.append({'product':product,'scenario':'comment_modified','status':'ERROR','error':str(e)})
        for scenario,source in cases:
            slug=f'{ix:03d}_{scenario}';out=reports/'sboms'/f'{slug}.json';out.parent.mkdir(exist_ok=True)
            components=scan(source,db,out,reports/'logs'/f'{slug}.log',a.threads)
            if components is None:
                rows.append({'product':product,'scenario':scenario,'status':'SCAN_ERROR','detected':'','other_products':'','sbom':str(out)})
                continue
            detected=names(components);is_found=product.casefold() in detected
            passed=not is_found if scenario=='negative_no_source' else is_found
            rows.append({'product':product,'scenario':scenario,'status':'PASS' if passed else ('FALSE_POSITIVE' if scenario=='negative_no_source' else 'MISS'),'detected':str(is_found),'other_products':';'.join(sorted(detected-{product.casefold()})),'sbom':str(out),'error':''})
    with (reports/'product_detection.csv').open('w',newline='',encoding='utf8') as f:
        fields=['product','scenario','status','detected','other_products','sbom','error'];wr=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');wr.writeheader();wr.writerows(rows)
    summary={'checkers_discovered':len(records),'sources_available':len(available),'sources_missing':len(unavailable),'tested_products':len(chosen),'database_integrity':ok,'by_scenario':{}}
    for scenario in ('original','comment_modified','negative_no_source'):
        rr=[x for x in rows if x.get('scenario')==scenario];valid=[x for x in rr if x.get('status') in ('PASS','MISS','FALSE_POSITIVE')]
        summary['by_scenario'][scenario]={'passed':sum(x['status']=='PASS' for x in valid),'missed_or_false_positives':sum(x['status'] in ('MISS','FALSE_POSITIVE') for x in valid),'scan_errors':sum(x['status']=='SCAN_ERROR' for x in rr),'detection_rate':round(sum(x['status']=='PASS' for x in valid)/len(valid),4) if valid else None}
    summary['interpretation']='Rates are positive-control recall only. Other_products may be real nested dependencies and need ground-truth review. Current HEAD clones are in-sample; not independent holdout.'
    (reports/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps(summary,ensure_ascii=False,indent=2));return 0 if all(x.get('status')=='PASS' for x in rows) and not unavailable else 1

if __name__=='__main__':raise SystemExit(main())
