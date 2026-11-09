#!/usr/bin/env python3
"""Run Cppcheck over the pinned tracked-C manifest in bounded batches."""
from pathlib import Path
from datetime import datetime, timezone
import argparse, csv, json, subprocess, time, xml.etree.ElementTree as ET

OUT = Path(__file__).resolve().parent
SRC = Path('/mnt/d/CVE-Typestate-Project-clang-analysis')
CPP = 'cppcheck'

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['text', 'xml'], required=True)
    ap.add_argument('--attempt', default='initial')
    ap.add_argument('--batch-size', type=int, default=100)
    ap.add_argument('--jobs', type=int, default=8)
    ap.add_argument('--timeout', type=int, default=1800)
    args = ap.parse_args()
    source_files = [x.strip() for x in (OUT/'tracked_c_files.txt').read_text().splitlines() if x.strip()]
    label = f'{args.mode}_{args.attempt}'
    manifest_dir = OUT/'manifests'/label
    log_dir = OUT/'logs'/label
    manifest_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    batch_rows, file_rows, combined_xml = [], [], []
    for start in range(0, len(source_files), args.batch_size):
        idx = start // args.batch_size + 1
        group = source_files[start:start+args.batch_size]
        bid = f'batch_{idx:03d}'
        list_path = manifest_dir/f'{bid}.list'
        list_path.write_text('\n'.join(group)+'\n')
        cmd = [CPP, '-j', str(args.jobs), '--quiet',
               '--enable=warning,style,performance,portability', '--inconclusive',
               '--inline-suppr', '--platform=unix64', '--std=c11',
               '-DNDEBUG',
               '-I'+str(SRC/'include'), '-I'+str(SRC/'crypto'),
               '-I'+str(SRC/'ssl'), '-I'+str(SRC/'providers/common/include'),
               '-I'+str(SRC/'providers/implementations/include'),
               '-I'+str(SRC/'apps'), '-I'+str(SRC/'test'),
               '--file-list='+str(list_path)]
        if args.mode == 'xml':
            cmd.append('--xml')
        stdout_path = log_dir/f'{bid}.stdout'
        stderr_path = log_dir/(f'{bid}.xml' if args.mode == 'xml' else f'{bid}.stderr')
        t0 = time.monotonic(); started = now(); rc = None; status = 'running'
        try:
            p = subprocess.run(cmd, cwd=SRC, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=args.timeout, check=False)
            rc = p.returncode; status = 'completed' if rc == 0 else 'nonzero_exit'
            stdout_path.write_bytes(p.stdout); stderr_path.write_bytes(p.stderr)
        except subprocess.TimeoutExpired as exc:
            status = 'timeout'; rc = 124
            stdout_path.write_bytes(exc.stdout or b''); stderr_path.write_bytes(exc.stderr or b'')
        duration = round(time.monotonic()-t0, 3); ended = now()
        batch_rows.append({'Mode':args.mode,'Batch ID':bid,'Input Files':len(group),'Start UTC':started,
                           'End UTC':ended,'Duration Seconds':duration,'Exit Code':rc,'Status':status,
                           'Command JSON':json.dumps(cmd),'Manifest':str(list_path.relative_to(OUT)),
                           'Stdout':str(stdout_path.relative_to(OUT)),'Stderr or XML':str(stderr_path.relative_to(OUT))})
        file_status = 'scanned' if status == 'completed' else 'incomplete_batch'
        file_rows.extend({'Mode':args.mode,'Batch ID':bid,'Source File':f,'Status':file_status} for f in group)
        if args.mode == 'xml' and status == 'completed' and stderr_path.stat().st_size:
            try:
                tree = ET.parse(stderr_path)
                root = tree.getroot()
                combined_xml.extend(list(root))
            except ET.ParseError as exc:
                batch_rows[-1]['Status'] = 'invalid_xml'
                batch_rows[-1]['XML Parse Error'] = str(exc)
                for row in file_rows[-len(group):]: row['Status']='invalid_xml_batch'
        write_status(OUT, label, batch_rows, file_rows)
        print(f"{args.mode} {bid}: {status} rc={rc} files={len(group)} duration={duration:.3f}s", flush=True)
    if args.mode == 'xml':
        root = ET.Element('results', {'version':'2'})
        for node in combined_xml: root.append(node)
        ET.ElementTree(root).write(OUT/f'cppcheck_raw_{label}.xml', encoding='utf-8', xml_declaration=True)
    else:
        with (OUT/f'cppcheck_raw_{label}.txt').open('w') as dest:
            for row in batch_rows:
                for field in ['Stdout','Stderr or XML']:
                    p=OUT/row[field]
                    if p.exists() and p.stat().st_size:
                        dest.write(f"===== {row['Batch ID']} {field} =====\n")
                        dest.write(p.read_text(errors='replace'))
                        if not p.read_text(errors='replace').endswith('\n'): dest.write('\n')
    failed=[r for r in batch_rows if r['Status']!='completed']
    print(f"FINAL {label}: files={len(file_rows)} scanned={sum(r['Status']=='scanned' for r in file_rows)} batches={len(batch_rows)} failed={len(failed)}", flush=True)

def write_status(out, mode, batches, files):
    for name, rows in [(f'{mode}_batch_status.csv',batches),(f'{mode}_file_status.csv',files)]:
        p=out/f"{mode}_{name}"
        fields=list(rows[0]) if rows else []
        with p.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

if __name__ == '__main__': main()
