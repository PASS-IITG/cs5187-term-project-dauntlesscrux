#!/usr/bin/env python3
"""check_triage.py - cross-check triage.csv against results/*.json and print the numbers the report cites.

Fails (exit 1) if a flagged site has no label or a label matches no flagged site, so the report
cannot silently drift away from the logs.
"""
import collections
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "results")
SNAPS = ["cve4450_pre", "cve4450_post", "kdf_pre", "kdf_post", "v3_0_0", "master_2026_10_30"]


def rel(path):
    # results hold paths like snap_<name>/<crypto|ssl|providers>/...
    for top in ("crypto/", "ssl/", "providers/"):
        i = path.find("/" + top)
        if i != -1:
            return path[i + 1:]
    return path


labels = {}
for r in csv.DictReader(open(os.path.join(HERE, "triage.csv"))):
    labels[(r["file"], r["function"], r["param"])] = r["label"]

per_snap, seen = {}, set()
for n in SNAPS:
    d = json.load(open(os.path.join(R, n + ".json")))
    keys = {}
    for s in d["sites"]:
        if s["status"] != "conforming":
            keys[(rel(s["file"]), s["function"], s["param"])] = s["status"]
    per_snap[n] = (d["counts"], keys)
    seen |= set(keys)

missing = sorted(seen - set(labels))
unused = sorted(set(labels) - seen)
for m in missing:
    print("NO LABEL for flagged site", m)
for u in unused:
    print("LABEL matches no flagged site", u)

print("unique flagged sites over all 6 snapshots: %d (labelled: %d)" % (len(seen), len(labels)))
print()
print("%-20s %6s %6s %6s | triage of the %s tool-flagged violations" % ("snapshot", "sites", "viol", "supp", "N"))
order = ["TP-upstream-fixed", "Candidate-latent", "Benign-deviation", "Unclear", "False-positive"]
for n in SNAPS:
    counts, keys = per_snap[n]
    c = collections.Counter(labels.get(k, "?") for k, st in keys.items() if st == "violation")
    tot = sum(counts.values())
    print("%-20s %6d %6d %6d | %s" % (n, tot, counts["violation"], counts["suppressed"],
          ", ".join("%s=%d" % (l, c[l]) for l in order if c[l])))
print()
allv = collections.Counter(labels[k] for k in seen if k in labels and labels[k] != "Suppressed-correct")
n = sum(allv.values())
print("all unique tool-flagged violations: %d  %s" % (n, dict(allv)))
sure = allv["TP-upstream-fixed"] + allv["Candidate-latent"] + allv["Benign-deviation"]
print("invariant really broken on some path (TP + candidate + benign): %d/%d = %.0f%% ; unclear %d ; false positive %d"
      % (sure, n, 100.0 * sure / n, allv["Unclear"], allv["False-positive"]))
sys.exit(1 if (missing or unused) else 0)
