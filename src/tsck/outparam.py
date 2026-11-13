#!/usr/bin/env python3
"""outparam.py - Protocol B checker: output-pointer reset after release.

The rule is read from a JSON spec (specs/outparam_reset.json).  For every
function parameter of type T** (pointer to pointer) named P, every call that
releases *P is a "release site".  A release site is

  conforming   - every path from the release to function exit assigns to *P
  violation    - some path reaches exit with *P still in state Released
  suppressed   - flagged by the path rule but *P is read again after the release
                 (partial release / reuse), or the callee is listed in the spec as
                 a partial-release function.  Reported separately, never hidden.

Usage:
  outparam.py [--spec FILE] [--func NAME] [--json OUT] PATH [PATH ...]
Exit status: 0 if no violations, 1 if at least one, 2 on usage error.
"""
import argparse
import json
import os
import re
import sys
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cfg import (build_cfg, function_name_and_params, functions, line, parse,
                 text, walk)

HERE = os.path.dirname(os.path.abspath(__file__))


def strip_parens(n):
    while n is not None and n.type == "parenthesized_expression" and n.named_children:
        n = n.named_children[0]
    return n


def is_star_of(n, p):
    """True if n is the expression `*p` (optionally parenthesised)."""
    n = strip_parens(n)
    if n is None or n.type != "pointer_expression":
        return False
    op = n.child_by_field_name("operator")
    arg = strip_parens(n.child_by_field_name("argument"))
    return (op is not None and text(op) == "*" and arg is not None
            and arg.type == "identifier" and text(arg) == p)


def guard_kind(cond, p):
    """'nonnull' if `cond` true means p != NULL, 'null' if it means p == NULL, else None."""
    e = strip_parens(cond)
    if e is None:
        return None
    if e.type == "identifier" and text(e) == p:
        return "nonnull"
    if e.type == "unary_expression":
        op, arg = e.child_by_field_name("operator"), strip_parens(e.child_by_field_name("argument"))
        if op is not None and text(op) == "!" and arg is not None \
                and arg.type == "identifier" and text(arg) == p:
            return "null"
    if e.type == "binary_expression":
        op = e.child_by_field_name("operator")
        l, r = strip_parens(e.child_by_field_name("left")), strip_parens(e.child_by_field_name("right"))
        if op is not None and text(op) in ("!=", "==") and l is not None and r is not None:
            names = {text(l), text(r)}
            if p in names and (names - {p}) <= {"NULL", "0"} and len(names) == 2:
                return "nonnull" if text(op) == "!=" else "null"
    return None


def node_events(ast, p, rel_re, passing_resets):
    """Events for parameter p inside one CFG node's AST."""
    releases, reset, uses = [], False, []
    reserved = set()                       # ids of `*p` nodes that are not plain uses
    nodes = list(walk(ast))
    for n in nodes:
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            name = text(fn) if fn is not None and fn.type == "identifier" else None
            if args is None:
                continue
            for a in args.named_children:
                if name and rel_re.search(name) and is_star_of(a, p):
                    releases.append((name, line(n)))
                    reserved.add(strip_parens(a).id)
                elif passing_resets and a.type == "identifier" and text(a) == p:
                    reset = True
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            op = n.child_by_field_name("operator")
            if is_star_of(left, p) and op is not None and text(op) == "=":
                reset = True
                reserved.add(strip_parens(left).id)
    for n in nodes:
        if n.type == "pointer_expression" and n.id not in reserved and is_star_of(n, p):
            uses.append(line(n))
    return releases, reset, uses


def analyse_function(fn, fname, params, spec, rel_re, path):
    cfg = build_cfg(fn.child_by_field_name("body"))
    depth_min = spec["tracked"]["min_pointer_depth"]
    passing = spec["reset"].get("passing_P_to_a_call_counts_as_reset", False)
    partial = set(spec["suppress"].get("partial_release_functions", []))
    use_supp = spec["suppress"].get("deref_after_release", False)
    sites = []
    fn_err = fn.has_error
    for depth, p, _ in params:
        if depth < depth_min:
            continue
        ev = {}
        for n in cfg.nodes:
            if n.ast is not None:
                ev[n.id] = node_events(n.ast, p, rel_re, passing)
        for n in cfg.nodes:
            if n.id not in ev or not ev[n.id][0]:
                continue
            for callee, ln in ev[n.id][0]:
                site = {"file": path, "function": fname, "param": p,
                        "callee": callee, "line": ln, "function_has_parse_error": fn_err}
                if ev[n.id][1]:                       # reset in the same statement
                    site["status"] = "conforming"
                    sites.append(site)
                    continue
                parent, seen, dq = {}, {n.id}, deque()
                for s in n.succ:
                    parent[s] = n.id
                    seen.add(s)
                    dq.append(s)
                reaches_exit, use_lines = False, []
                while dq:
                    cur = dq.popleft()
                    if cur == cfg.exit:
                        reaches_exit = True
                        continue
                    e = ev.get(cur)
                    if e is not None:
                        if e[1]:
                            continue                  # Reset: stop exploring this path
                        use_lines += e[2] + [l for _, l in e[0]]
                    # Sound pruning: *P was dereferenced by the release, so P is non-NULL
                    # on every later path; the branch where a guard says P == NULL is dead.
                    dead = None
                    if cur in cfg.branch:
                        gk = guard_kind(cfg.nodes[cur].ast, p)
                        if gk is not None:
                            dead = cfg.branch[cur][1 if gk == "nonnull" else 0]
                    for s in cfg.nodes[cur].succ:
                        if s != dead and s not in seen:
                            seen.add(s)
                            parent[s] = cur
                            dq.append(s)
                if not reaches_exit:
                    site["status"] = "conforming"
                else:
                    path_lines, c = [], cfg.exit
                    while c != n.id:
                        c = parent[c]
                        if c != n.id and cfg.nodes[c].ast is not None:
                            path_lines.append(cfg.nodes[c].line)
                    path_lines = [ln] + path_lines[::-1]
                    site["witness"] = path_lines
                    if use_supp and use_lines:
                        site["status"] = "suppressed"
                        site["reason"] = "deref-after-release at lines %s" % sorted(set(use_lines))
                    elif callee in partial:
                        site["status"] = "suppressed"
                        site["reason"] = "partial-release function listed in spec"
                    else:
                        site["status"] = "violation"
                sites.append(site)
    return sites


def collect_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in sorted(files):
                    if f.endswith(".c"):
                        yield os.path.join(root, f)
        else:
            yield p


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--spec", default=os.path.join(HERE, "specs", "outparam_reset.json"))
    ap.add_argument("--func", help="only analyse this function name")
    ap.add_argument("--json", help="write all sites to this JSON file")
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    spec = json.load(open(a.spec))
    rel_re = re.compile(spec["release"]["call_name_regex"])

    sites, nfiles, errors, parse_err = [], 0, 0, 0
    for path in collect_files(a.paths):
        try:
            data = open(path, "rb").read()
            tree = parse(data)
        except Exception as ex:                       # unreadable file
            errors += 1
            print("ERROR %s: %s" % (path, ex), file=sys.stderr)
            continue
        nfiles += 1
        if tree.root_node.has_error:
            parse_err += 1
        for fn in functions(tree.root_node):
            fname, params = function_name_and_params(fn)
            if not fname or (a.func and fname != a.func):
                continue
            if not any(d >= spec["tracked"]["min_pointer_depth"] for d, _, _ in params):
                continue
            try:
                sites += analyse_function(fn, fname, params, spec, rel_re, path)
            except Exception as ex:
                errors += 1
                print("ERROR %s:%s: %r" % (path, fname, ex), file=sys.stderr)

    sites.sort(key=lambda s: (s["file"], s["line"], s["param"]))
    count = {k: sum(1 for s in sites if s["status"] == k)
             for k in ("conforming", "violation", "suppressed")}
    if not a.quiet:
        for s in sites:
            if s["status"] == "violation":
                print("VIOLATION %s:%d %s() releases *%s via %s; exit reachable without reset (path lines %s)"
                      % (s["file"], s["line"], s["function"], s["param"], s["callee"], s["witness"]))
        for s in sites:
            if s["status"] == "suppressed":
                print("SUPPRESSED %s:%d %s() releases *%s via %s; %s"
                      % (s["file"], s["line"], s["function"], s["param"], s["callee"], s["reason"]))
    in_err = sum(1 for s in sites if s["function_has_parse_error"])
    print("files=%d release-sites: conforming=%d violation=%d suppressed=%d errors=%d "
          "parse_error_files=%d sites_in_functions_with_parse_errors=%d"
          % (nfiles, count["conforming"], count["violation"], count["suppressed"], errors,
             parse_err, in_err))
    if a.json:
        json.dump({"spec": spec["name"], "files": nfiles, "counts": count,
                   "errors": errors, "parse_error_files": parse_err, "sites": sites},
                  open(a.json, "w"), indent=1)
    return 1 if count["violation"] else 0


if __name__ == "__main__":
    sys.exit(main())
