#!/usr/bin/env python3
"""Run a SmPL event extractor over every path in an explicit source manifest.
Timed-out/failed batches are recursively subdivided; every result has its own
raw stdout/stderr and command/status record.
"""
import csv, datetime, pathlib, subprocess, sys
out = pathlib.Path(sys.argv[1])
rule_id, rule_file, source_list = sys.argv[2:5]
source_list = pathlib.Path(source_list)
files = [x.strip() for x in source_list.read_text().splitlines() if x.strip()]
phase = out / 'optimized'
logs = phase / 'logs' / rule_id
mans = phase / 'manifests' / rule_id
logs.mkdir(parents=True, exist_ok=True); mans.mkdir(parents=True, exist_ok=True)
tmp = out / 'tmp'
rows=[]; ok=[]; failed=[]; sequence=0

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def scan(group, name):
    global sequence
    sequence += 1
    listfile = mans / f'{name}.list'
    listfile.write_text('\n'.join(group)+'\n')
    stdout=logs/f'{name}.stdout'; stderr=logs/f'{name}.stderr'
    command=['spatch','--jobs','8','--tmp-dir',str(tmp),'--very-quiet','--sp-file',str(pathlib.Path(rule_file)),'--file-groups',str(listfile)]
    start=now()
    try:
        p=subprocess.run(['timeout','120',*command],capture_output=True,text=True)
        rc=p.returncode; stdout.write_text(p.stdout); stderr.write_text(p.stderr)
    except Exception as e:
        rc=125; stdout.write_text(''); stderr.write_text(f'{type(e).__name__}: {e}\n')
    end=now()
    rows.append({'Rule ID':rule_id,'Batch':name,'File Count':len(group),'Start UTC':start,'End UTC':end,'Exit Code':rc,'Status':'completed' if rc==0 else 'failed or timed out','Command':' '.join(['timeout','120',*command]),'File Manifest':str(listfile),'Stdout':str(stdout),'Stderr':str(stderr)})
    print(f'{rule_id} {name}: files={len(group)} exit={rc} bytes={stdout.stat().st_size} elapsed_start={start}', flush=True)
    if rc==0:
        ok.extend(group)
    elif len(group)>1:
        mid=len(group)//2
        scan(group[:mid],name+'a'); scan(group[mid:],name+'b')
    else:
        failed.extend(group)

for i in range(0,len(files),100): scan(files[i:i+100],f'batch_{i//100:03d}')
for row in rows: row['Exit Code']=int(row['Exit Code'])
with (phase/f'{rule_id}_batch_status.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['Rule ID']);w.writeheader();w.writerows(rows)
with (phase/f'{rule_id}_file_status.csv').open('w',newline='') as f:
    fields=['Source File','Status','Completed Batch'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    success_batches={p:r['Batch'] for r in rows if r['Exit Code']==0 for p in pathlib.Path(r['File Manifest']).read_text().splitlines() if p}
    for p in files: w.writerow({'Source File':p,'Status':'scanned' if p in success_batches else 'not_scanned','Completed Batch':success_batches.get(p,'')})
with (phase/f'{rule_id}_failed_files.txt').open('w') as f: f.write(''.join(p+'\n' for p in failed))
print(f'{rule_id} FINAL files={len(files)} scanned={len(ok)} failed={len(failed)} batches={len(rows)}',flush=True)
