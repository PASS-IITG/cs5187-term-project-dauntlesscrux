#!/usr/bin/env python3
"""Analyze one affected OpenSSL TU from each pinned commit in /tmp copies.

The compilation command comes from `make -n V=1 <object>` after configuring
the exact revision. The original six worktrees are never configured or built.
"""
from pathlib import Path
import concurrent.futures, csv, datetime, json, os, shlex, subprocess, time

ROOT = Path('/mnt/d/cve-typestate-project')
OUT = ROOT / 'research/11_cve_tool_comparison'
TMP = Path('/tmp/openssl-cve-tool-comparison/clang')
PAIRS = [
    ('CVE-2022-4450','Vulnerable','openssl-CVE-2022-4450-vulnerable','crypto/pem/pem_lib.c','crypto/pem/libcrypto-lib-pem_lib.o'),
    ('CVE-2022-4450','Fixed','openssl-CVE-2022-4450-fixed','crypto/pem/pem_lib.c','crypto/pem/libcrypto-lib-pem_lib.o'),
    ('CVE-2023-0215','Vulnerable','openssl-CVE-2023-0215-vulnerable','crypto/asn1/bio_ndef.c','crypto/asn1/libcrypto-lib-bio_ndef.o'),
    ('CVE-2023-0215','Fixed','openssl-CVE-2023-0215-fixed','crypto/asn1/bio_ndef.c','crypto/asn1/libcrypto-lib-bio_ndef.o'),
    ('CVE-2024-4741','Vulnerable','openssl-CVE-2024-4741-vulnerable','ssl/record/ssl3_buffer.c','ssl/record/libssl-lib-ssl3_buffer.o'),
    ('CVE-2024-4741','Fixed','openssl-CVE-2024-4741-fixed','ssl/record/ssl3_buffer.c','ssl/record/libssl-lib-ssl3_buffer.o'),
]

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
def run(cmd, cwd=None, timeout=1800, env=None):
    return subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding='utf-8', errors='replace',
                          timeout=timeout, check=False, env=env)

def one(item):
    cve, side, folder, source, target = item
    tag = f'{cve}_{side.lower()}'
    source_repo = ROOT / folder
    copy = TMP / tag
    logdir = OUT / 'runs/clang/attempt2' / tag
    logdir.mkdir(parents=True, exist_ok=True)
    TMP.mkdir(parents=True, exist_ok=True)
    row = {'CVE':cve,'Side':side,'Worktree':str(source_repo),'Temporary Copy':str(copy),
           'Target Source':source,'Object Target':target,'Configure Command':'CC=clang-18 ./Configure linux-x86_64',
           'Analysis Command JSON':'','Start UTC':utc(),'End UTC':'','Duration Seconds':'',
           'Configure Exit':'','Dry Run Exit':'','Analyzer Exit':'','Status':'NOT_EVALUABLE','Error':''}
    start = time.monotonic()
    try:
        if not copy.exists():
            archive = subprocess.run(['git','-C',str(source_repo),'archive','--format=tar','HEAD'],
                                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1800,check=False)
            if archive.returncode:
                raise RuntimeError(f'git archive exit {archive.returncode}: {archive.stderr[-3000:].decode("utf-8", "replace")}')
            import tarfile, io
            with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode='r:') as tf:
                tf.extractall(copy)
        configure_env = os.environ.copy()
        configure_env['CC'] = 'clang-18'
        cfg = run(['./Configure','linux-x86_64'],cwd=copy,timeout=1800,env=configure_env)
        (logdir/'configure.stdout').write_text(cfg.stdout,encoding='utf-8')
        (logdir/'configure.stderr').write_text(cfg.stderr,encoding='utf-8')
        row['Configure Exit']=cfg.returncode
        if cfg.returncode:
            raise RuntimeError(f'Configure failed ({cfg.returncode})')
        generated = run(['make','-j8','build_generated'],cwd=copy,timeout=1800)
        (logdir/'generated_headers.stdout').write_text(generated.stdout,encoding='utf-8')
        (logdir/'generated_headers.stderr').write_text(generated.stderr,encoding='utf-8')
        if generated.returncode:
            raise RuntimeError(f'generated header target failed ({generated.returncode})')
        (logdir/'configdata.dump.txt').write_text(
            run(['perl','configdata.pm','--dump'],cwd=copy,timeout=60).stdout,encoding='utf-8')
        dry = run(['make','-n','V=1',target],cwd=copy,timeout=1800)
        (logdir/'make_dryrun.stdout').write_text(dry.stdout,encoding='utf-8')
        (logdir/'make_dryrun.stderr').write_text(dry.stderr,encoding='utf-8')
        row['Dry Run Exit']=dry.returncode
        if dry.returncode:
            raise RuntimeError(f'make dry run failed ({dry.returncode})')
        candidates=[line for line in dry.stdout.splitlines()
                    if source in line and ' -c ' in f' {line} ' and ('clang' in line)]
        if len(candidates)!=1:
            raise RuntimeError(f'expected one compiler line for {source}, found {len(candidates)}')
        argv=shlex.split(candidates[0])
        clean=[]; i=0
        while i<len(argv):
            if argv[i] in ('-MMD','-MD','-MP','-c'):
                i+=1; continue
            if argv[i] in ('-MF','-MT','-o'):
                i+=2; continue
            clean.append(argv[i]); i+=1
        clean += ['--analyze','-Xanalyzer','-analyzer-output=text','-fno-color-diagnostics']
        row['Analysis Command JSON']=json.dumps(clean)
        (logdir/'analyzer_command.json').write_text(row['Analysis Command JSON']+'\n',encoding='utf-8')
        res=run(clean,cwd=copy,timeout=1800)
        (logdir/'analyzer.stdout').write_text(res.stdout,encoding='utf-8')
        (logdir/'analyzer.stderr').write_text(res.stderr,encoding='utf-8')
        row['Analyzer Exit']=res.returncode
        row['Status']='COMPLETED' if res.returncode==0 else 'NOT_EVALUABLE'
        if res.returncode: row['Error']=f'clang analysis exit {res.returncode}'
    except Exception as exc:
        row['Error']=str(exc)
        (logdir/'runner_error.txt').write_text(str(exc)+'\n',encoding='utf-8')
    row['End UTC']=utc(); row['Duration Seconds']=round(time.monotonic()-start,3)
    return row

if __name__=='__main__':
    rows=[one(item) for item in PAIRS]
    with (OUT/'clang_run_status_attempt2.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    for r in rows: print(r['CVE'],r['Side'],r['Status'],r['Analyzer Exit'],r['Error'])
