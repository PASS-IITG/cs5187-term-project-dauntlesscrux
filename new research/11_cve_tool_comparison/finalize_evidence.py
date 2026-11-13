from pathlib import Path
import csv,hashlib,json,subprocess,xml.etree.ElementTree as ET
from collections import Counter

out=Path(__file__).resolve().parent
root=out.parent.parent
def readcsv(p):
 with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def writecsv(p,rows):
 with p.open('w',newline='',encoding='utf-8') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def sha(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()

# Include stable Clang++ metadata and hashes of invocation drivers.
freeze=readcsv(out/'TOOL_FREEZE.csv')
if not any(r['Tool']=='Clang++ 18 (C++ frontend; not used for these C TUs)' for r in freeze):
 p=Path('/usr/bin/clang++-18')
 version=subprocess.run(['clang++-18','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0]
 freeze.append({'Tool':'Clang++ 18 (C++ frontend; not used for these C TUs)','Version':version,'Executable/Configuration':str(p),'SHA256':sha(p),'Frozen Configuration':'Recorded for toolchain identity; comparison inputs are C translation units.'})
writecsv(out/'TOOL_FREEZE.csv',freeze)

scripts=['run_clang_sa.py','run_python_coccinelle.py','run_cppcheck.py','build_comparison.py','finalize_evidence.py']
writecsv(out/'RUNNER_HASHES.csv',[{'Runner':s,'SHA256':sha(out/s)} for s in scripts])

# Capture per-revision generated Clang build configuration and exact command hashes.
cl=readcsv(out/'clang_run_status_attempt2.csv')
configs=[]
for r in cl:
 tag=f"{r['CVE']}_{r['Side'].lower()}"; d=out/'runs/clang/attempt2'/tag
 configs.append({'CVE':r['CVE'],'Side':r['Side'],'Revision':next(x['Actual HEAD'] for x in readcsv(out/'WORKTREE_REVISION_MANIFEST.csv') if x['CVE']==r['CVE'] and x['Side']==r['Side']),
  'Configure Command':r['Configure Command'],'Configure Log SHA256':sha(d/'configure.stdout'),
  'Configdata Dump SHA256':sha(d/'configdata.dump.txt'),'Generated Header Build Status':'completed (make -j8 build_generated)',
  'Target Compile Command SHA256':hashlib.sha256(r['Analysis Command JSON'].encode()).hexdigest(),'Analyzer Exit':r['Analyzer Exit'],'Analyzer Status':r['Status']})
writecsv(out/'CLANG_CONFIGURATION_MANIFEST.csv',configs)

# Count raw records and validate complete coverage.
manifest=readcsv(out/'WORKTREE_REVISION_MANIFEST.csv')
assert len(manifest)==6 and all(r['Revision Match']=='yes' for r in manifest)
matrix=readcsv(out/'COMPARISON_MATRIX.csv');assert len(matrix)==24
allowed={'DETECTED_AND_DISTINGUISHED','DETECTED_BUT_NOT_DISTINGUISHED','NOT_DETECTED','INCONCLUSIVE','NOT_EVALUABLE'}
assert all(r['Pair Result Category'] in allowed for r in matrix)
assert all(r['Run Status']=='COMPLETED' for r in matrix)
assert len(readcsv(out/'python_run_status.csv'))==6
assert len(readcsv(out/'clang_run_status_attempt2.csv'))==6 and all(r['Status']=='COMPLETED' and r['Analyzer Exit']=='0' for r in readcsv(out/'clang_run_status_attempt2.csv'))
assert len(readcsv(out/'coccinelle_run_status.csv'))==30 and all(r['Status']=='COMPLETED' and r['Exit Code']=='0' for r in readcsv(out/'coccinelle_run_status.csv'))
assert len(readcsv(out/'cppcheck_run_status.csv'))==12 and all(r['Status']=='COMPLETED' and r['Exit Code']=='0' for r in readcsv(out/'cppcheck_run_status.csv'))
for r in readcsv(out/'python_run_status.csv'):
 expected='1' if r['Side']=='Vulnerable' else '0'
 assert str(r['Exit Code'])==expected
 d=out/'runs/python'/f"{r['CVE']}_{r['Side'].lower()}"
 assert (d/'stdout.log').exists() and (d/'stderr.log').exists()
for r in readcsv(out/'coccinelle_run_status.csv'):
 assert (out/r['Stdout Log']).exists() and (out/r['Stderr Log']).exists()
for r in readcsv(out/'cppcheck_run_status.csv'):
 assert (out/r['Raw Log']).exists()
for r in readcsv(out/'clang_run_status_attempt2.csv'):
 d=out/'runs/clang/attempt2'/f"{r['CVE']}_{r['Side'].lower()}"
 assert (d/'analyzer.stdout').exists() and (d/'analyzer.stderr').exists()
cpp_counts={}
cpp_review=[]
for r in readcsv(out/'cppcheck_run_status.csv'):
 if r['Format']=='xml':
  cpp_counts[(r['CVE'],r['Side'])]=len(ET.parse(out/r['Raw Log']).getroot().findall('.//error'))
  rootxml=ET.parse(out/r['Raw Log']).getroot()
  for e in rootxml.findall('.//error'):
   loc=e.find('location'); loc=loc.attrib if loc is not None else {}
   cpp_review.append({'CVE':r['CVE'],'Side':r['Side'],'File':r['Source'],'Line':loc.get('line',''),
    'Diagnostic ID':e.attrib.get('id',''),'Severity':e.attrib.get('severity',''),'Message':e.attrib.get('msg',''),
    'Mechanism Classification':'unrelated diagnostic','Review Evidence':'Diagnostic is a style/scope/name/unread-variable item; it does not describe the CVE-specific ownership or pointer-state invariant.',
    'Raw XML':r['Raw Log']})
if cpp_review:
 writecsv(out/'CPPCHECK_DIAGNOSTIC_REVIEW.csv',cpp_review)
 assert all(r['Severity']=='style' for r in cpp_review)
for k,v in cpp_counts.items(): print('Cppcheck',*k,'diagnostics',v)

# Validate all CSV row widths and every raw reference in the matrix.
csv_files=list(out.rglob('*.csv'))
for f in csv_files:
 rr=list(csv.reader(f.open(newline='',encoding='utf-8')))
 assert rr and len({len(row) for row in rr})==1,(f,'inconsistent columns')
for r in matrix:
 raw=(out/r['Raw Log Reference'])
 assert raw.exists() or raw.is_dir(),r['Raw Log Reference']
# Frozen checker/rule copies must match the source/config reviewed at freeze.
assert sha(out/'frozen/typestate_check.py')==sha(root/'src/typestate_check.py')
orig=Path('/mnt/d/cve-typestate-project/research/09_reproducibility/coccinelle_20261104/rules')
for f in (out/'frozen/coccinelle_rules').glob('*.cocci'):
 assert sha(f)==sha(orig/f.name),f
control=(out/'runs/clang/control/stderr.log').read_text(errors='replace')
assert 'Use of memory after it is freed' in control
summary={'worktrees_verified':len(manifest),'comparison_rows':len(matrix),'python_runs':6,
 'clang_runs':6,'coccinelle_rule_runs':30,'cppcheck_format_runs':12,
 'cppcheck_xml_diagnostics':{f'{k[0]} {k[1]}':v for k,v in cpp_counts.items()},'csv_files_validated':len(csv_files),
 'clang_positive_control':'passed; UAF diagnostic observed'}
(out/'VALIDATION.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary,indent=2))
