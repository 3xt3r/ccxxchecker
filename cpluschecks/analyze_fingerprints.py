#!/usr/bin/env python3
"""Read-only disk footprint audit for a large CXX SCA SQLite fingerprint database.

Usage: python analyze_fingerprints.py fingerprints.sqlite --output db_audit.json
No third-party modules. Does not modify the source DB.
"""
import argparse
import collections
import json
import os
import sqlite3
import sys
from pathlib import Path


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def human(n):
    if n is None:
        return 'n/a'
    return f'{n / (1024 ** 2):,.1f} MiB'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('database', nargs='?', default='fingerprints.sqlite')
    ap.add_argument('--output', default='fingerprint_db_audit.json')
    ap.add_argument('--top', type=int, default=25)
    ap.add_argument('--sample', type=int, default=20000, help='row sample per hash column, 0 to disable')
    args = ap.parse_args()
    db = Path(args.database).expanduser().resolve()
    if not db.is_file():
        ap.error(f'not found: {db}')
    if args.sample < 0:
        ap.error('--sample must be nonnegative')
    # SQLite read-only URI; any WAL is opened read-only as well.
    from urllib.parse import quote
    uri = 'file:' + quote(str(db), safe='/') + '?mode=ro'
    con = sqlite3.connect(uri, uri=True, timeout=5)
    con.execute('PRAGMA query_only=ON')
    con.execute('PRAGMA temp_store=MEMORY')
    con.execute('PRAGMA busy_timeout=5000')
    try:
        page_size = con.execute('PRAGMA page_size').fetchone()[0]
        page_count = con.execute('PRAGMA page_count').fetchone()[0]
        freelist = con.execute('PRAGMA freelist_count').fetchone()[0]
        objects = con.execute("SELECT name,type,tbl_name,sql FROM sqlite_master WHERE type IN ('table','index') ORDER BY name").fetchall()
        tables = [n for n, typ, *_ in objects if typ == 'table' and not n.startswith('sqlite_')]
        indexes = {name: {'table': parent, 'sql': sql} for name, typ, parent, sql in objects if typ == 'index'}
        by_object = {}
        dbstat_error = None
        try:
            rows = con.execute('SELECT name, SUM(pgsize) AS bytes FROM dbstat GROUP BY name ORDER BY bytes DESC').fetchall()
            by_object = dict(rows)
        except sqlite3.Error as exc:
            dbstat_error = str(exc)
        estimated = {}
        try:
            for tbl, stat in con.execute('SELECT tbl,stat FROM sqlite_stat1'):
                if stat and stat.split()[0].isdigit():
                    estimated.setdefault(tbl, int(stat.split()[0]))
        except sqlite3.Error:
            pass
        table_info = {}
        for table in tables:
            cols = [dict(cid=c[0], name=c[1], type=c[2], pk=c[5]) for c in con.execute('PRAGMA table_info(' + quoted(table) + ')')]
            idx = [dict(name=r[1], unique=bool(r[2]), origin=r[3], columns=[x[2] for x in con.execute('PRAGMA index_info(' + quoted(r[1]) + ')')]) for r in con.execute('PRAGMA index_list(' + quoted(table) + ')')]
            samples = []
            if args.sample:
                for col in cols:
                    name = col['name']
                    if not any(k in name.lower() for k in ('hash', 'digest', 'fingerprint', 'snippet')):
                        continue
                    # Only sample one column at a time, no GROUP BY or DB-wide COUNT(*).
                    vals = con.execute('SELECT ' + quoted(name) + ' FROM ' + quoted(table) + ' WHERE ' + quoted(name) + ' IS NOT NULL LIMIT ?', (args.sample,)).fetchall()
                    if not vals:
                        continue
                    counts = collections.Counter(x[0] for x in vals)
                    samples.append({'column': name, 'sample_rows': len(vals), 'distinct_in_sample': len(counts), 'duplicate_fraction_in_sample': round(1-len(counts)/len(vals), 4), 'note': 'First N non-null rows only; not a DB-wide duplicate rate'})
            table_info[table] = {'estimated_rows_from_sqlite_stat1': estimated.get(table), 'columns': cols, 'indexes': idx, 'hash_column_samples': samples, 'object_size_bytes': by_object.get(table)}
        index_bytes = sum(by_object.get(i, 0) for i in indexes)
        table_bytes = sum(by_object.get(t, 0) for t in tables)
        result = {
            'database': str(db),
            'file_size_bytes': db.stat().st_size,
            'wal_bytes': (Path(str(db)+'-wal').stat().st_size if Path(str(db)+'-wal').exists() else 0),
            'shm_bytes': (Path(str(db)+'-shm').stat().st_size if Path(str(db)+'-shm').exists() else 0),
            'page_size': page_size, 'page_count': page_count,
            'free_pages': freelist, 'estimated_free_bytes': freelist*page_size,
            'dbstat_error': dbstat_error,
            'table_bytes_dbstat': table_bytes if by_object else None,
            'index_bytes_dbstat': index_bytes if by_object else None,
            'largest_objects': [{'name': name, 'kind': 'index' if name in indexes else 'table', 'size_bytes': size} for name, size in sorted(by_object.items(), key=lambda x: -x[1])],
            'tables': table_info,
        }
        out = Path(args.output).expanduser().resolve()
        if out == db:
            ap.error('--output may not overwrite the database')
        out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'Database: {db} ({human(result["file_size_bytes"])})')
        print(f'WAL: {human(result["wal_bytes"])}; free pages: {human(result["estimated_free_bytes"])}')
        if dbstat_error:
            print('dbstat unavailable:', dbstat_error)
        else:
            print(f'DB pages allocated to tables: {human(table_bytes)}; indexes: {human(index_bytes)}')
            print('\nLargest SQLite objects:')
            for item in result['largest_objects'][:args.top]:
                print(f'  {human(item["size_bytes"]):>12}  {item["kind"]:5}  {item["name"]}')
        print('\nTables and potential fingerprint columns:')
        for name, info in table_info.items():
            print(f'  {name}: approx rows={info["estimated_rows_from_sqlite_stat1"] or "unknown"}; indexes={len(info["indexes"])}')
            for s in info['hash_column_samples']:
                print(f'    {s["column"]}: {s["distinct_in_sample"]}/{s["sample_rows"]} unique within sample (NOT global rate)')
        print('\nDetailed JSON:', out)
    finally:
        con.close()


if __name__ == '__main__':
    try:
        main()
    except sqlite3.Error as ex:
        print(f'SQLite error: {ex}', file=sys.stderr)
        sys.exit(2)
