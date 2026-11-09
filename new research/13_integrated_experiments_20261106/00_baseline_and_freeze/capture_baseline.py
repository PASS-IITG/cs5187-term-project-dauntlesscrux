import concurrent.futures, hashlib, os, pathlib, subprocess, sys, time
root=pathlib.Path('/mnt/d/cve-typestate-project')
out=root/'research/13_integrated_experiments_20261106/00_baseline_and_freeze'
repos=[('main',root),('clang_analysis',pathlib.Path('/mnt/d/CVE-Typestate-Project-clang-analysis'))]
for name in ['openssl-cve-2022-4450-vulnerable','openssl-cve-2022-4450-fixed','openssl-cve-2023-0215-vulnerable','openssl-cve-2023-0215-fixed','openssl-cve-2024-4741-vulnerable','openssl-cve-2024-4741-fixed']:
    repos.append((name,root/name))
def run(repo, args, timeout=90):
    env=os.environ.copy(); env['GIT_OPTIONAL_LOCKS']='0'
    try:
        p=subprocess.run(['git','-C',str(repo),*args],capture_output=True,text=True,timeout=timeout,env=env)
        return p.returncode,p.stdout,p.stderr
    except subprocess.TimeoutExpired as e:
        return 124,(e.stdout or b'').decode(errors='replace') if isinstance(e.stdout,bytes) else (e.stdout or ''),'TIMEOUT after %ds'%timeout
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
    futs={ex.submit(run,path,['rev-parse','--show-toplevel']):(name,path,'root') for name,path in repos}
    futs.update({ex.submit(run,path,['rev-parse','HEAD']):(name,path,'head') for name,path in repos})
    futs.update({ex.submit(run,path,['symbolic-ref','--short','-q','HEAD']):(name,path,'branch') for name,path in repos})
    vals={}
    for f in concurrent.futures.as_completed(futs):
        name,path,kind=futs[f]; vals[(name,kind)]=f.result()
with (out/'REPOSITORY_REVISION_FREEZE.csv').open('w') as f:
    f.write('repository,path,git_root,branch,head,root_rc,branch_rc,head_rc\n')
    for name,path in repos:
        rootr=vals[(name,'root')]; br=vals[(name,'branch')]; hr=vals[(name,'head')]
        branch=br[1].strip() or ('DETACHED' if br[0]==1 else f'ERROR:{br[0]}')
        f.write(','.join([name,str(path),rootr[1].strip(),branch,hr[1].strip(),str(rootr[0]),str(br[0]),str(hr[0])])+'\n')
# Git status is isolated and time-bounded; full status is attempted, then untracked-disabled fallback if it stalls.
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
    futs={ex.submit(run,path,['status','--short','--branch'],60):(name,path) for name,path in repos}
    with (out/'GIT_STATUS_BASELINE.txt').open('w') as f:
        for future in concurrent.futures.as_completed(futs):
            name,path=futs[future]; rc,stdout,stderr=future.result()
            f.write(f'===== {name} {path} rc={rc} =====\n{stdout}')
            if stderr: f.write('STDERR: '+stderr+'\n')
# Hash analyzer and all tests; configs from existing experiments where relevant.
items=[root/'src/typestate_check.py']+list((root/'tests').glob('**/*'))
items += [root/'research/09_reproducibility/clang_scan_20261103',root/'research/09_reproducibility/coccinelle_20261104']
with (out/'FROZEN_FILE_HASHES.csv').open('w') as f:
    f.write('path,sha256,size_bytes\n')
    for item in sorted(items):
        if not item.is_file(): continue
        h=hashlib.sha256(item.read_bytes()).hexdigest()
        f.write(f'{item},{h},{item.stat().st_size}\n')
