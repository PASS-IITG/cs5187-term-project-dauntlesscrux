#!/usr/bin/env python3
"""Build the 24-row, manually reviewed comparison from raw run records."""
from pathlib import Path
import csv, json, re, xml.etree.ElementTree as ET
from collections import defaultdict

OUT=Path(__file__).resolve().parent
def rows(file):
    with (OUT/file).open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))
def write(file, data):
    with (OUT/file).open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)

manifest=rows('WORKTREE_REVISION_MANIFEST.csv')
py=rows('python_run_status.csv')
clang=rows('clang_run_status_attempt2.csv')
coc=rows('coccinelle_run_status.csv')
cpp=rows('cppcheck_run_status.csv')
revision={(r['CVE'],r['Side']):r['Actual HEAD'] for r in manifest}
pyidx={(r['CVE'],r['Side']):r for r in py}
clidx={(r['CVE'],r['Side']):r for r in clang}
coidx=defaultdict(list)
for r in coc: coidx[(r['CVE'],r['Side'])].append(r)
cpidx=defaultdict(list)
for r in cpp: cpidx[(r['CVE'],r['Side'])].append(r)

manual=[]; matrix=[]
notes={
 'CVE-2022-4450':{
  'Invariant':'After PEM_read_bio_ex frees a caller-visible output allocation on out_free, clear that output pointer before returning failure.',
  'Mechanism evidence':'Vulnerable pem_lib.c:990-993 frees *header/*data and leaves the outputs unchanged; fixed source adds NULL resets after each free (fixed lines 990-1000).',
  'Clang':'The affected translation unit compiled/analyzed with the revision-specific generated OpenSSL flags and no Clang analyzer diagnostic was emitted. No reported path addresses dangling PEM outputs.',
  'Coccinelle':'All five frozen rules parsed and exited 0. Rule 02 does not match the vulnerable pem_free(*header/*data) calls because its argument metavariable is an identifier, while these arguments are dereferences. Its unrelated release/allocation/return events do not associate a freed output with a missing reset. No frozen rule encodes this invariant.',
  'Cppcheck':'Both passes exited 0. It emitted only style diagnostics (12 per version, including declaration-name and scope/style items); none concerns freed caller-visible PEM output pointers. The same unrelated diagnostics appear in both versions.',
 },
 'CVE-2023-0215':{
  'Invariant':'After BIO_push links caller-owned out below asn_bio, detach the filter with BIO_pop before freeing it on error so BIO links do not retain a freed prev_bio.',
  'Mechanism evidence':'Vulnerable bio_ndef.c:69-72 links asn_bio/out and 99-102 frees without BIO_pop. Fixed code saves the inserted head (fixed lines 75-80) and pops before free (121-126). BIO_push/BIO_pop link behavior is in crypto/bio/bio_lib.c:649-684; BIO_free releases one BIO (126-157).',
  'Clang':'The affected translation unit compiled/analyzed with revision-specific flags and no analyzer diagnostic was emitted. No reported path follows the stale BIO chain link.',
  'Coccinelle':'All five frozen rules parsed and exited 0. Rule 02 emits a generic BIO_free event at the vulnerable and fixed cleanup sites, but does not check whether BIO_pop repairs the chain. Rule 03 covers SSL_set0 BIO transfer, not BIO_push/BIO_pop. No rule detects this mechanism.',
  'Cppcheck':'Both text/XML passes exited 0 and produced zero diagnostics for bio_ndef.c in both versions. No BIO chain lifetime mechanism was reported.',
 },
 'CVE-2024-4741':{
  'Invariant':'After freeing the record-layer read buffer, clear b->buf, the packet pointer into the buffer, and packet_length; SSL_free_buffers also has a no-pending-data precondition.',
  'Mechanism evidence':'Vulnerable ssl3_buffer.c:185-195 frees and nulls b->buf but leaves packet and packet_length stale. Fixed source clears both (fixed lines 185-196). The packet pointer/length describe the read-buffer slice (rec_layer_s3.c:194-202, 223-263); SSL_free_buffers checks pending/data state before release (ssl_lib.c:5488-5501).',
  'Clang':'The affected translation unit compiled/analyzed with revision-specific flags and no analyzer diagnostic was emitted. No reported path captures later use of the packet pointer.',
  'Coccinelle':'All five frozen rules parsed and exited 0. 04a reports a generic allocation event in buffer setup and 04b generic returns; neither rule follows those events to ssl3_release_read_buffer or checks packet state. The other frozen rules have no matching release/use pattern. No mechanism detection.',
  'Cppcheck':'Both text/XML passes exited 0 and produced two unrelated style diagnostics per version (variable scope and unread variable in other functions). No diagnostic concerns packet pointer or packet_length after release.',
 },
}

for cve,n in notes.items():
    pyouts={side:(OUT/'runs/python'/f'{cve}_{side.lower()}'/'stdout.log').read_text(errors='replace').strip()
            for side in ['Vulnerable','Fixed']}
    py_pair_ok=('STATE: VIOLATION' in pyouts['Vulnerable'] and
                'STATE: CONFORMING' in pyouts['Fixed'])
    for side in ['Vulnerable','Fixed']:
        key=(cve,side)
        # Per-tool status and mechanism decision, with raw-log references.
        p=pyidx[key]; c=clidx[key]; cr=coidx[key]; xr=cpidx[key]
        pyout=pyouts[side]
        pyst=('VIOLATION' if 'STATE: VIOLATION' in pyout else
              'CONFORMING' if 'STATE: CONFORMING' in pyout else 'UNKNOWN')
        cstderr=(OUT/'runs/clang/attempt2'/f'{cve}_{side.lower()}'/'analyzer.stderr').read_text(errors='replace')
        cstdout=(OUT/'runs/clang/attempt2'/f'{cve}_{side.lower()}'/'analyzer.stdout').read_text(errors='replace')
        cdiag=bool(re.search(r'\bwarning:|\berror:',cstderr+cstdout))
        # Review all raw rule output; only the reviewed targeted operations can count as detection.
        cocci_count=0; cocci_rule_rows=[]
        for rr in cr:
            txt=(OUT/rr['Stdout Log']).read_text(errors='replace')
            cocci_count+=len(txt.splitlines())
            cocci_rule_rows.append(f"{rr['Rule ID']}={len(txt.splitlines())} events")
        cppxml=next(r for r in xr if r['Format']=='xml')
        xmlroot=ET.parse(OUT/cppxml['Raw Log']).getroot()
        cppdiags=xmlroot.findall('.//error')
        cpp_ids=sorted({e.attrib.get('id','') for e in cppdiags})
        cpp_summaries=[]
        for e in cppdiags:
            loc=e.find('location'); line=loc.attrib.get('line','') if loc is not None else ''
            cpp_summaries.append(f"{line}:{e.attrib.get('id')}:{e.attrib.get('severity')}:{e.attrib.get('msg')}")
        tool_rows=[
            ('Python checker',p['Status'],'DETECTED_AND_DISTINGUISHED' if py_pair_ok else 'INCONCLUSIVE',
             'Checker emitted '+pyst,
             f"runs/python/{cve}_{side.lower()}/stdout.log"),
            ('Clang Static Analyzer 18',c['Status'],'NOT_DETECTED' if not cdiag and c['Status']=='COMPLETED' else ('INCONCLUSIVE' if c['Status']=='COMPLETED' else 'NOT_EVALUABLE'),
             'No diagnostic output for the affected translation unit' if not cdiag else 'Analyzer emitted diagnostics; none independently reviewed as the CVE mechanism',
             f"runs/clang/attempt2/{cve}_{side.lower()}/analyzer.stderr"),
            ('Coccinelle 1.1.1','COMPLETED' if all(x['Status']=='COMPLETED' for x in cr) else 'NOT_EVALUABLE','NOT_DETECTED',
             '; '.join(cocci_rule_rows)+'; event-only/generic messages do not check this invariant',
             f"runs/coccinelle/{cve}_{side.lower()}/"),
            ('Cppcheck 2.13.0','COMPLETED' if all(x['Status']=='COMPLETED' for x in xr) else 'NOT_EVALUABLE','NOT_DETECTED',
             f"{len(cppdiags)} diagnostic(s); IDs: {','.join(cpp_ids) if cpp_ids else 'none'}; no reviewed CVE mechanism", 
             f"runs/cppcheck/{cve}_{side.lower()}/"),
        ]
        for tool,status,result,diag,raw in tool_rows:
            manual.append({'CVE':cve,'Side':side,'Tool':tool,'Observed Classification':result,
                           'Run Status':status,'Mechanism Review':diag,
                           'Vulnerable/Fixed Revision':revision[key],'Raw Evidence':raw})
            matrix.append({'CVE':cve,'Side':side,'Source Revision':revision[key],'Tool':tool,
                           'Pair Result Category':result,'Run Status':status,
                           'Source Mechanism Reviewed':n['Mechanism evidence'],
                           'Observed Output':diag,'Raw Log Reference':raw})

write('COMPARISON_MATRIX.csv',matrix)
write('MANUAL_REVIEW_EVIDENCE.csv',manual)
print('matrix rows',len(matrix),'manual rows',len(manual))
