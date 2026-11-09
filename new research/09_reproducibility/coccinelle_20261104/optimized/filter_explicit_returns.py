#!/usr/bin/env python3
"""Separate explicit source return events from synthetic/nonliteral positions, then rebuild Rule 04 candidates."""
from pathlib import Path
import csv
import re
ROOT = Path('/mnt/d/CVE-Typestate-Project-clang-analysis')
OPT = Path(__file__).resolve().parent

def read_csv(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))

def write_csv(path, rows, fields):
    with path.open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

raw = read_csv(OPT / 'raw_events_04b.csv')
explicit, nonliteral = [], []
source_lines = {}
for event in raw:
    source = ROOT / event['Source File']
    if event['Source File'] not in source_lines:
        source_lines[event['Source File']] = source.read_text(errors='replace').splitlines()
    lines = source_lines[event['Source File']]
    line = int(event['Line'])
    text = lines[line - 1] if 0 < line <= len(lines) else ''
    start, end = (int(x) for x in event['Column'].split('-', 1))
    reported_token = text[start:end]
    (explicit if re.search(r'\breturn\b', reported_token) else nonliteral).append(event)
fields = list(raw[0]) if raw else ['Rule ID','Source File','Absolute File','Function','Event','Line','Column','Callee','Pointer','Mapping Status']
write_csv(OPT / 'raw_events_04b_explicit.csv', explicit, fields)
write_csv(OPT / 'raw_events_04b_nonliteral_position.csv', nonliteral, fields)

allocs = read_csv(OPT / 'raw_events_04a.csv')
by_function = {}
for event in explicit:
    if event['Function']:
        by_function.setdefault((event['Source File'], event['Function']), []).append(int(event['Line']))
candidates = []
for event in allocs:
    if not event['Function']:
        continue
    later = sorted(set(n for n in by_function.get((event['Source File'], event['Function']), []) if n > int(event['Line'])))
    if later:
        candidates.append({
            'Candidate ID': '',
            'Rule ID': '04_acquire_early_return',
            'Source File': event['Source File'],
            'Function': event['Function'],
            'Pointer': event['Pointer'],
            'Allocation Line': event['Line'],
            'Later Return Lines': ';'.join(map(str, later)),
            'Later Return Count': str(len(later)),
            'Review Status': 'pending initial review',
        })
candidates.sort(key=lambda r: (r['Source File'], r['Function'], int(r['Allocation Line'])))
for i, row in enumerate(candidates, 1):
    row['Candidate ID'] = f'R04X-{i:06d}'
write_csv(OPT / 'candidate_inventory_04_explicit.csv', candidates,
          ['Candidate ID','Rule ID','Source File','Function','Pointer','Allocation Line','Later Return Lines','Later Return Count','Review Status'])
print(f'raw={len(raw)} explicit={len(explicit)} nonliteral={len(nonliteral)} candidates={len(candidates)}')
