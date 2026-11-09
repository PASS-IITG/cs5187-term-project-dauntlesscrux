#!/usr/bin/env python3
"""Run frozen Cppcheck options on each temporary configured source revision."""
from pathlib import Path
import csv, datetime, json, subprocess, time

ROOT=Path('/mnt/d/cve-typestate-project')
OUT=ROOT/'research/11_cve_tool_comparison'
TMP=Path('/tmp/openssl-cve-tool-comparison/clang')
CASES=[
('CVE-2022-4450','Vulnerable','CVE-2022-4450_vulnerable','crypto/pem/pem_lib.c'),
('CVE-2022-4450','Fixed','CVE-2022-4450_fixed','crypto/pem/pem_lib.c'),
('CVE-2023-0215','Vulnerable','CVE-2023-0215_vulnerable','crypto/asn1/bio_ndef.c'),
('CVE-2023-0215','Fixed','CVE-2023-0215_fixed','crypto/asn1/bio_ndef.c'),
('CVE-2024-4741','Vulnerable','CVE-2024-4741_vulnerable','ssl/record/ssl3_buffer.c'),
('CVE-2024-4741','Fixed','CVE-2024-4741_fixed','ssl/record/ssl3_buffer.c'),
]

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def main():
    rows=[]
    for cve,side,tag,rel in CASES:
        src=TMP/tag; file=src/rel
        base=['cppcheck','-j','4','--quiet','--enable=warning,style,performance,portability',
              '--inconclusive','--inline-suppr','--platform=unix64','--std=c11','-DNDEBUG']
        for path in ['include','crypto','ssl','providers/common/include',
                     'providers/implementations/include','apps','test']:
            base.append('-I'+str(src/path))
        base += ['--template=gcc',str(file)]
        for fmt in ['text','xml']:
            command=base+(['--xml'] if fmt=='xml' else [])
            ld=OUT/'runs/cppcheck'/f'{cve}_{side.lower()}'/fmt;ld.mkdir(parents=True,exist_ok=True)
            start=time.monotonic();started=utc()
            try:
                p=subprocess.run(command,cwd=src,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 text=True,encoding='utf-8',errors='replace',timeout=900,check=False)
                rc=p.returncode; stdout=p.stdout;stderr=p.stderr; status='COMPLETED' if rc==0 else 'NONZERO_EXIT'
            except subprocess.TimeoutExpired as e:
                rc=124; stdout=e.stdout.decode('utf-8','replace') if isinstance(e.stdout,bytes) else (e.stdout or '')
                stderr=e.stderr.decode('utf-8','replace') if isinstance(e.stderr,bytes) else (e.stderr or '')
                status='TIMEOUT'
            suffix='xml' if fmt=='xml' else 'txt'
            (ld/f'raw.{suffix}').write_text(stderr if fmt=='xml' else stdout,encoding='utf-8')
            (ld/'stdout.log').write_text(stdout,encoding='utf-8')
            (ld/'stderr.log').write_text(stderr,encoding='utf-8')
            rows.append({'CVE':cve,'Side':side,'Format':fmt,'Source':str(file),'Command JSON':json.dumps(command),
                         'Start UTC':started,'End UTC':utc(),'Duration Seconds':round(time.monotonic()-start,3),
                         'Exit Code':rc,'Status':status,'Raw Log':str((ld/f'raw.{suffix}').relative_to(OUT))})
    with (OUT/'cppcheck_run_status.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    for r in rows: print(r['CVE'],r['Side'],r['Format'],r['Status'],r['Exit Code'],r['Duration Seconds'])

if __name__=='__main__': main()
