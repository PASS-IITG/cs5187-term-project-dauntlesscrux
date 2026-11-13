#!/usr/bin/env python3
"""Map Coccinelle event lines to C function ranges and group original predicates."""
from pathlib import Path
import csv, re, sys
out=Path(sys.argv[1]); src=Path('/mnt/d/CVE-Typestate-Project-clang-analysis'); opt=out/'optimized'

def mask_c(s):
    # Replace comments and literals with spaces while preserving offsets/newlines.
    a=list(s); n=len(a); i=0; state='code'
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
        elif state in ('string','char'):
            if c=='\\':
                a[i]=' '
                if i+1<n and s[i+1]!='\n': a[i+1]=' '
                i+=2; continue
            if (state=='string' and c=='"') or (state=='char' and c=="'"): state='code'
            if c!='\n': a[i]=' '
        i+=1
    # Directives and continued macro lines do not represent ordinary function bodies.
    lines=''.join(a).splitlines(True); result=[]; skip=False
    for line in lines:
        if skip:
            result.append(''.join('\n' if c=='\n' else ' ' for c in line)); skip=line.rstrip('\n').endswith('\\'); continue
        if re.match(r'^\s*#',line):
            result.append(''.join('\n' if c=='\n' else ' ' for c in line)); skip=line.rstrip('\n').endswith('\\')
        else: result.append(line)
    return ''.join(result)

def function_ranges(path):
    text=path.read_text(errors='replace'); m=mask_c(text); n=len(m); ranges=[]; depth=0; top_start=0; stack=[]
    for i,c in enumerate(m):
        if c=='{' and depth==0:
            prefix=m[top_start:i].rstrip()
            name=None
            if prefix.endswith(')'):
                close=len(prefix)-1; d=0; op=None
                for j in range(close,-1,-1):
                    if prefix[j]==')': d+=1
                    elif prefix[j]=='(':
                        d-=1
                        if d==0: op=j; break
                if op is not None:
                    before=prefix[:op].rstrip(); mat=re.search(r'([A-Za-z_][A-Za-z_0-9]*)\s*$',before)
                    if mat:
                        nm=mat.group(1)
                        if nm not in {'if','while','for','switch','sizeof','_Alignof','return','__attribute__','__declspec'}:
                            # Avoid a function-like expression used to initialize a block.
                            if not re.search(r'(?:=|,|\breturn|\bif|\bwhile|\bfor)\s*$',before): name=nm
            stack.append((i,0,name))
            depth=1
        elif c=='{' and depth>0: depth+=1
        elif c=='}' and depth>0:
            depth-=1
            if depth==0 and stack:
                start,_,name=stack.pop()
                if name: ranges.append((start,i+1,name))
                top_start=i+1
        elif c==';' and depth==0: top_start=i+1
    # Attribute declarations after a function body can leave top_start exact at the closing brace;
    # candidate sites are mapped by half-open body offsets.
    starts=[]; pos=0
    for ln,line in enumerate(text.splitlines(True),1): starts.append((pos,ln));pos+=len(line)
    def lineoff(line): return starts[line-1][0] if 0<line<=len(starts) else -1
    return ranges,lineoff

# Parse Coccinelle output, retaining all event rows even if mapping fails.
event_specs=[('02','02_events','release_event'),('04a','04a_alloc_events','alloc_event'),('04b','04b_return_events','return_event')]
all_events={}; unmapped=[]; range_cache={}
rx=re.compile(r'^(.*):(\d+):(\d+-\d+): (release_event\|[^\r\n]+|alloc_event\|[^\r\n]+|return_event)\s*$')
for tag,rule,event_kind in event_specs:
    events=[]
    for log in sorted((opt/'logs'/rule).glob('*.stdout')):
        for line in log.read_text(errors='replace').splitlines():
            m=rx.match(line)
            if not m: continue
            file,ln,col,payload=m.groups(); path=Path(file); line_no=int(ln)
            try: relpath=str(path.relative_to(src))
            except ValueError: relpath=file
            if file not in range_cache:
                if path.exists(): range_cache[file]=function_ranges(path)
                else: range_cache[file]=( [], lambda _: -1 )
            ranges,lineoff=range_cache[file]; off=lineoff(line_no)
            fn='';
            for a,b,name in ranges:
                if a < off < b: fn=name; break
            kind=payload.split('|',1)[0]
            rest=payload.split('|')[1:] if '|' in payload else []
            if kind=='release_event': rel,p=rest; desc=''
            elif kind=='alloc_event': p=rest[0]; rel=''; desc=''
            else: rel=p=''; desc=''
            status='mapped' if fn else 'unmapped'
            ev={'Rule ID':rule,'Source File':relpath,'Absolute File':file,'Function':fn,'Event':kind,'Line':line_no,'Column':col,'Callee':rel,'Pointer':p,'Mapping Status':status}
            events.append(ev)
            if not fn: unmapped.append(ev)
    all_events[tag]=events
    with (opt/f'raw_events_{tag}.csv').open('w',newline='') as f:
        fields=list(events[0]) if events else ['Rule ID','Source File','Absolute File','Function','Event','Line','Column','Callee','Pointer','Mapping Status']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(events)
# Group repeated releases by same filename, function, callee and identifier.
e02={}
for e in all_events['02']:
    if e['Function']:
        e02.setdefault((e['Source File'],e['Function'],e['Callee'],e['Pointer']),[]).append(e['Line'])
with (opt/'candidate_inventory_02.csv').open('w',newline='') as f:
    fields=['Candidate ID','Rule ID','Source File','Function','Callee','Pointer','Release Lines','Occurrence Count','Review Status']; w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    i=0
    for (file,fn,rel,p),lines in sorted(e02.items()):
        if len(lines)<2: continue
        i+=1; w.writerow({'Candidate ID':f'R02-{i:05d}','Rule ID':'02_repeated_release','Source File':file,'Function':fn,'Callee':rel,'Pointer':p,'Release Lines':';'.join(map(str,sorted(set(lines)))),'Occurrence Count':len(set(lines)),'Review Status':'pending initial review'})
# Rule 04: each allocated identifier with a later return in the same function.
allocs={}; returns={}
for e in all_events['04a']:
    if e['Function']: allocs.setdefault((e['Source File'],e['Function']),[]).append(e)
for e in all_events['04b']:
    if e['Function']: returns.setdefault((e['Source File'],e['Function']),[]).append(e['Line'])
with (opt/'candidate_inventory_04.csv').open('w',newline='') as f:
    fields=['Candidate ID','Rule ID','Source File','Function','Pointer','Allocation Line','Later Return Lines','Later Return Count','Review Status'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
    i=0
    for key,aa in sorted(allocs.items()):
        rr=sorted(set(x for x in returns.get(key,[]) if x>0))
        for a in aa:
            later=[x for x in rr if x>a['Line']]
            if not later: continue
            i+=1;w.writerow({'Candidate ID':f'R04-{i:06d}','Rule ID':'04_acquire_early_return','Source File':a['Source File'],'Function':a['Function'],'Pointer':a['Pointer'],'Allocation Line':a['Line'],'Later Return Lines':';'.join(map(str,later)),'Later Return Count':len(later),'Review Status':'pending initial review'})
with (opt/'unmapped_events.csv').open('w',newline='') as f:
    fields=['Rule ID','Source File','Line','Event','Callee','Pointer','Mapping Status'];w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows([{k:e[k] for k in fields} for e in unmapped])
print('events', {k:len(v) for k,v in all_events.items()}, 'unmapped',len(unmapped))
print('rule02_candidates',sum(1 for x in csv.DictReader((opt/'candidate_inventory_02.csv').open())))
print('rule04_candidates',sum(1 for x in csv.DictReader((opt/'candidate_inventory_04.csv').open())))
