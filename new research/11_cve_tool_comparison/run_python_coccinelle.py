#!/usr/bin/env python3
"""Run frozen Python checker and pre-existing Coccinelle rules on six sources."""
from pathlib import Path
import csv, datetime, json, subprocess, time

ROOT=Path('/mnt/d/cve-typestate-project')
OUT=ROOT/'research/11_cve_tool_comparison'
RULES=OUT/'frozen/coccinelle_rules'
CASES=[
('CVE-2022-4450','Vulnerable','openssl-CVE-2022-4450-vulnerable','crypto/pem/pem_lib.c'),
('CVE-2022-4450','Fixed','openssl-CVE-2022-4450-fixed','crypto/pem/pem_lib.c'),
('CVE-2023-0215','Vulnerable','openssl-CVE-2023-0215-vulnerable','crypto/asn1/bio_ndef.c'),
('CVE-2023-0215','Fixed','openssl-CVE-2023-0215-fixed','crypto/asn1/bio_ndef.c'),
('CVE-2024-4741','Vulnerable','openssl-CVE-2024-4741-vulnerable','ssl/record/ssl3_buffer.c'),
('CVE-2024-4741','Fixed','openssl-CVE-2024-4741-fixed','ssl/record/ssl3_buffer.c'),
]
RULES_LIST=['01_use_after_release.cocci','02_repeated_release_events.cocci',
            '03_release_after_transfer.cocci','04a_alloc_events.cocci',
            '04b_return_events.cocci']

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def call(cmd,cwd=None,timeout=300):
    try:
        p=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        return p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as e:
        return 124,e.stdout.decode('utf-8','replace') if isinstance(e.stdout,bytes) else (e.stdout or ''),e.stderr.decode('utf-8','replace') if isinstance(e.stderr,bytes) else (e.stderr or '')

def main():
    pyrows=[]; corows=[]
    for cve,side,folder,rel in CASES:
        path=ROOT/folder/rel; tag=f'{cve}_{side.lower()}'
        logdir=OUT/'runs/python'/tag;logdir.mkdir(parents=True,exist_ok=True)
        cmd=['python3',str(OUT/'frozen/typestate_check.py'),str(path)]
        start=time.monotonic();startutc=utc();rc,stdout,stderr=call(cmd,cwd=ROOT,timeout=120)
        (logdir/'stdout.log').write_text(stdout,encoding='utf-8');(logdir/'stderr.log').write_text(stderr,encoding='utf-8')
        pyrows.append({'CVE':cve,'Side':side,'Source':str(path),'Command JSON':json.dumps(cmd),
                       'Start UTC':startutc,'End UTC':utc(),'Duration Seconds':round(time.monotonic()-start,3),
                       'Exit Code':rc,'Status':'COMPLETED' if rc in (0,1,2) else 'NOT_EVALUABLE'})
        for rulename in RULES_LIST:
            rule=RULES/rulename; name=rulename.removesuffix('.cocci')
            rd=OUT/'runs/coccinelle'/tag/name;rd.mkdir(parents=True,exist_ok=True)
            cmd=['spatch','--jobs','2','--very-quiet','--sp-file',str(rule),str(path)]
            start=time.monotonic();startutc=utc();rc,stdout,stderr=call(cmd,cwd=ROOT,timeout=300)
            (rd/'stdout.log').write_text(stdout,encoding='utf-8');(rd/'stderr.log').write_text(stderr,encoding='utf-8')
            corows.append({'CVE':cve,'Side':side,'Source':str(path),'Rule ID':name,
                           'Rule SHA256':__import__('hashlib').sha256(rule.read_bytes()).hexdigest(),
                           'Command JSON':json.dumps(cmd),'Start UTC':startutc,'End UTC':utc(),
                           'Duration Seconds':round(time.monotonic()-start,3),'Exit Code':rc,
                           'Status':'COMPLETED' if rc==0 else ('TIMEOUT' if rc==124 else 'NOT_EVALUABLE'),
                           'Stdout Log':str((rd/'stdout.log').relative_to(OUT)),
                           'Stderr Log':str((rd/'stderr.log').relative_to(OUT))})
    for filename,rows in [('python_run_status.csv',pyrows),('coccinelle_run_status.csv',corows)]:
        with (OUT/filename).open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    print('Python checks:',len(pyrows),'Coccinelle runs:',len(corows))
    for r in pyrows: print('PY',r['CVE'],r['Side'],'exit',r['Exit Code'])
    for r in corows:
        if r['Status']!='COMPLETED': print('COCCI ISSUE',r['CVE'],r['Side'],r['Rule ID'],r['Status'],r['Exit Code'])

if __name__=='__main__': main()
