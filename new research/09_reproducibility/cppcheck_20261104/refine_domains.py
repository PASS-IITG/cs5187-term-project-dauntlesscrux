#!/usr/bin/env python3
from pathlib import Path
import csv
out=Path(__file__).resolve().parent
src=Path('/mnt/d/CVE-Typestate-Project-clang-analysis')
with (out/'cppcheck_inventory_deduplicated.csv').open(newline='') as f: rows=list(csv.DictReader(f))
for r in rows:
    p=r['Source File']
    if p.startswith('test/'): d='test'
    elif p.startswith('fuzz/'): d='fuzz'
    elif p.startswith('doc/'): d='documentation/example'
    elif p.startswith('demos/'): d='optional demo'
    elif p.startswith('apps/'): d='application'
    else: d='production library/provider'
    r['Source Domain']=d
fields=list(rows[0])
with (out/'cppcheck_inventory_deduplicated_refined.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
print('rows',len(rows))
