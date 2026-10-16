#!/usr/bin/env python3
"""Adapter: scan with the real CXX SCA CLI, merge known and unknown SBOMs."""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--src',required=True);p.add_argument('--out',required=True)
p.add_argument('--db',required=True);p.add_argument('--threads',type=int,default=4)
a=p.parse_args()
project=Path(__file__).resolve().parent/'cpluschecks'
db=Path(a.db).expanduser().resolve()
if not db.is_file():p.error(f'Fingerprint database missing: {db}. Build it first; see README_RU.md')
with tempfile.TemporaryDirectory() as td:
    k=Path(td)/'known.json';u=Path(td)/'unknown.json'
    cmd=[sys.executable,str(project/'scanner.py'),str(Path(a.src).resolve()),'--sbom',str(k),'--unknown',str(u),'--fingerprint-db',str(db),'--fingerprint-policy','always','--threads',str(a.threads)]
    r=subprocess.run(cmd,cwd=str(project),capture_output=True,text=True)
    if r.returncode:
        print(r.stdout,file=sys.stderr);print(r.stderr,file=sys.stderr);sys.exit(r.returncode)
    sources=[json.loads(x.read_text()) for x in (k,u)]
    output={'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':[]}
    for source in sources:output['components'].extend(source.get('components',[]))
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf8')
