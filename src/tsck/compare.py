#!/usr/bin/env python3
"""compare.py - what does a fix change?  Diff the violation sets of two outparam.py JSON runs.

Sites are identified by (relative file, function, parameter), not by line number, so that
unrelated edits above a site do not look like a change.
usage: compare.py PRE.json POST.json [--prefix-pre DIR --prefix-post DIR]
"""
import json
import os
import sys


def key(s, prefix):
    f = s["file"]
    return (os.path.relpath(f, prefix) if prefix else f, s["function"], s["param"])


def load(path, prefix):
    d = json.load(open(path))
    flagged = {key(s, prefix): s for s in d["sites"] if s["status"] == "violation"}
    return d, flagged


def main():
    a = sys.argv[1:]
    pre, post = a[0], a[1]
    pp = a[a.index("--prefix-pre") + 1] if "--prefix-pre" in a else ""
    pq = a[a.index("--prefix-post") + 1] if "--prefix-post" in a else ""
    dpre, fpre = load(pre, pp)
    dpost, fpost = load(post, pq)
    removed = sorted(set(fpre) - set(fpost))
    added = sorted(set(fpost) - set(fpre))
    print("pre : release-sites=%d violations=%d" % (sum(dpre["counts"].values()), len(fpre)))
    print("post: release-sites=%d violations=%d" % (sum(dpost["counts"].values()), len(fpost)))
    print("violations removed by the change: %d" % len(removed))
    for k in removed:
        print("   - %s %s *%s" % k)
    print("violations added by the change:   %d" % len(added))
    for k in added:
        print("   + %s %s *%s" % k)


if __name__ == "__main__":
    main()
