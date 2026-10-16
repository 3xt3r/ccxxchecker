#!/usr/bin/env python3
"""Read-only checks for compact CXX SCA v8 database."""
import argparse
import sqlite3
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('db', type=Path)
    args = p.parse_args()
    if not args.db.is_file():
        p.error(f'No database: {args.db}')
    conn = sqlite3.connect(f'file:{args.db.resolve()}?mode=ro', uri=True)
    try:
        meta = dict(conn.execute('SELECT key,value FROM meta'))
        print('Schema:', meta.get('schema_version'))
        if meta.get('schema_version') != 'identity-compact-v8':
            raise SystemExit('ERROR: database is not compact v8')
        print('Components:', meta.get('component_count'))
        print('Source labels:', meta.get('source_label_count'))
        print('SQLite size MiB:', round(args.db.stat().st_size/1048576, 1))
        for name in ('segments','snippets','hash_stats','snippet_hash_stats'):
            n=conn.execute(f'SELECT COUNT(*) FROM {name}').fetchone()[0]
            print(f'{name}: {n:,} rows')
        print('Integrity (quick_check):', conn.execute('PRAGMA quick_check').fetchone()[0])
        print('Components example:', [x[0] for x in conn.execute('SELECT DISTINCT component FROM snippets LIMIT 10')])
    finally:
        conn.close()


if __name__ == '__main__':
    main()
