#!/usr/bin/env python3
"""Extract Cppcheck XML diagnostics and deduplicate repeated TU/header reports."""
from pathlib import Path
import csv, collections, re, xml.etree.ElementTree as ET
OUT=Path(__file__).resolve().parent
SRC=Path('/mnt/d/CVE-Typestate-Project-clang-analysis')

def mask_c(s):
    a=list(s); i=0; state='code'; n=len(s)
    while i<n:
        c=s[i]; d=s[i+1] if i+1<n else ''
        if state=='code':
            if c=='/' and d=='*': a[i]=a[i+1]=' '; i+=2; state='block'; continue
            if c=='/' and d=='/': a[i]=a[i+1]=' '; i+=2; state='line'; continue
            if c in ('"', "'"): state='string' if c=='"' else 'char'; a[i]=' '; i+=1; continue
        elif state=='block':
            if c=='*' and d=='/': a[i]=a[i+1]=' '; i+=2; state='code'; continue
            if c!='\n': a[i]=' '
        elif state=='line':
            if c=='\n': state='code'
            else: a[i]=' '
        else:
            if c=='\\':
                a[i]=' '
                if i+1<n and s[i+1]!='\n': a[i+1]=' '
                i+=2; continue
            if (state=='string' and c=='"') or (state=='char' and c=="'"): state='code'
            if c!='\n': a[i]=' '
        i+=1
    return ''.join(a)

def ranges_for(path):
    try: text=path.read_text(errors='replace')
    except OSError: return [],{}
    m=mask_c(text); ranges=[]; depth=0; top_start=0; stack=[]
    for i,ch in enumerate(m):
        if ch=='{' and depth==0:
            prefix=m[top_start:i].rstrip(); name=None
            if prefix.endswith(')'):
                close=len(prefix)-1; d=0; op=None
                for j in range(close,-1,-1):
                    if prefix[j]==')': d+=1
                    elif prefix[j]=='(':
                        d-=1
                        if d==0: op=j; break
                if op is not None:
                    before=prefix[:op].rstrip(); mat=re.search(r'([A-Za-z_]\w*)\s*$',before)
                    if mat and mat.group(1) not in {'if','while','for','switch','sizeof','_Alignof','return','__attribute__','__declspec'} and not re.search(r'(?:=|,|\breturn|\bif|\bwhile|\bfor)\s*$',before):
                        name=mat.group(1)
            stack.append((i,name)); depth=1
        elif ch=='{' and depth: depth+=1
        elif ch=='}' and depth:
            depth-=1
            if depth==0 and stack:
                start,name=stack.pop()
                if name: ranges.append((start,i+1,name))
                top_start=i+1
        elif ch==';' and depth==0: top_start=i+1
    line_offsets=[0]
    for idx,ch in enumerate(text):
        if ch=='\n': line_offsets.append(idx+1)
    return ranges,line_offsets

cache={}
def source_location(file_attr, line):
    p=Path(file_attr)
    if p.is_absolute():
        try: rel=p.relative_to(SRC).as_posix()
        except ValueError: return p.as_posix(),p
        path=p
    else:
        rel=Path(file_attr).as_posix()
        path=SRC/rel
    if path not in cache: cache[path]=ranges_for(path)
    ranges,offsets=cache[path]
    fn=''
    if line and line<=len(offsets):
        off=offsets[line-1]
        for a,b,n in ranges:
            if a<=off<b: fn=n; break
    return rel,path,fn

xml_path=OUT/'cppcheck_raw_xml_first.xml'
root=ET.parse(xml_path).getroot()
raw=[]
for node in root.iter('error'):
    attrs=node.attrib
    locs=[x.attrib for x in node.findall('location')]
    if not locs:
        locs=[{'file':attrs.get('file0',''),'line':'','column':''}]
    primary=locs[0]
    try: line=int(primary.get('line','0') or 0)
    except ValueError: line=0
    try: col=int(primary.get('column','0') or 0)
    except ValueError: col=0
    srcfile,path,fn=source_location(primary.get('file',''),line)
    tu=attrs.get('file0','')
    try: tu=Path(tu).relative_to(SRC).as_posix() if Path(tu).is_absolute() else Path(tu).as_posix()
    except ValueError: pass
    raw.append({'Source File':srcfile,'Line':str(line),'Column':str(col),'Function':fn,
        'Diagnostic ID':attrs.get('id',''),'Severity':attrs.get('severity',''),'Message':attrs.get('msg',''),
        'Verbose':attrs.get('verbose',''),'CWE':attrs.get('cwe',''),'Inconclusive':attrs.get('inconclusive','false'),
        'Primary Translation Unit':tu,'Other Locations':';'.join(f"{x.get('file','')}:{x.get('line','')}:{x.get('column','')}" for x in locs[1:])})
raw_fields=list(raw[0]) if raw else ['Source File','Line','Column','Function','Diagnostic ID','Severity','Message','Verbose','CWE','Inconclusive','Primary Translation Unit','Other Locations']
with (OUT/'cppcheck_diagnostics_raw.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=raw_fields); w.writeheader(); w.writerows(raw)

groups={}
for r in raw:
    key=tuple(r[k] for k in ['Source File','Line','Column','Diagnostic ID','Severity','Message','Inconclusive'])
    if key not in groups: groups[key]=dict(r, **{'Raw Occurrences':0,'Translation Units':set()})
    groups[key]['Raw Occurrences']+=1
    if r['Primary Translation Unit']: groups[key]['Translation Units'].add(r['Primary Translation Unit'])
rows=[]
for i,key in enumerate(sorted(groups),1):
    r=groups[key]; r['Finding ID']=f'CPK-{i:06d}'; r['Translation Unit Count']=len(r['Translation Units'])
    r['Translation Units']=';'.join(sorted(r['Translation Units']))
    rel=r['Source File']
    r['Source Domain']='test' if rel.startswith('test/') else 'fuzz' if rel.startswith('fuzz/') else 'documentation/example' if rel.startswith('doc/') else 'production/application'
    r['Review Status']='pending initial review'
    rows.append(r)
fields=['Finding ID','Source Domain','Source File','Function','Line','Column','Diagnostic ID','Severity','Message','Inconclusive','CWE','Raw Occurrences','Translation Unit Count','Translation Units','Other Locations','Review Status']
with (OUT/'cppcheck_inventory_deduplicated.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader();
    for r in rows:w.writerow({k:r.get(k,'') for k in fields})
print('raw_xml_diagnostics',len(raw),'deduplicated',len(rows))
print('severity',dict(collections.Counter(r['Severity'] for r in rows)))
print('domain',dict(collections.Counter(r['Source Domain'] for r in rows)))
print('IDs',len(set(r['Diagnostic ID'] for r in rows)))
