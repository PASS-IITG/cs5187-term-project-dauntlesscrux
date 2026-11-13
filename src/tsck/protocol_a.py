#!/usr/bin/env python3
"""protocol_a.py - Protocol A checker: BIO-chain detach-before-release.

This is a second rule-as-data checker, alongside Protocol B (outparam.py),
reusing the same tree-sitter parser and the same per-function control-flow
graph builder (cfg.py).  It implements the manual rule derived in
BIO-2023-0215-rule-notes.md for CVE-2023-0215: a local BIO variable V that is
linked into a chain by `BIO_push(V, other)` must be detached by `BIO_pop()`
on EVERY path from that call to any call that releases V (or a variable V was
directly assigned into, e.g. `pop_bio = asn_bio;`).

Unlike Protocol B, the tracked object here is not a function parameter but a
local variable, and the obligation runs forward from an "establish" call
(BIO_push) to a "release" call (BIO_free/BIO_free_all), with a "detach" call
(BIO_pop) as the thing that must happen in between. Concretely, for each
occurrence of BIO_push(V, ...):
  1. Collect V's whole-function syntactic alias set (see specs/bio_chain_pop.json
     for the exact, deliberately limited, alias rule).
  2. Walk the CFG forward from the BIO_push call. A BIO_pop() on V or an alias
     absorbs that path (nothing further to check along it). A BIO_free()/
     BIO_free_all() on V or an alias that is reached without first passing a
     BIO_pop() is a violation. A release reached only via paths that already
     passed a BIO_pop() first is conforming.

A release call textually present in the function but never reachable from any
BIO_push(V, ...) (for example, a release on an entirely unrelated variable
that happens to share this scan, or a release on V's error path that never
executed the push at all) is not reported at all: it is not an obligation
this rule creates.

Usage:
  protocol_a.py [--spec FILE] [--func NAME] [--json OUT] PATH [PATH ...]
Exit status: 0 if no violations, 1 if at least one, 2 on usage error.
"""
import argparse
import json
import os
import re
import sys
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cfg import build_cfg, function_name_and_params, functions, line, parse, text, walk

HERE = os.path.dirname(os.path.abspath(__file__))


def strip_parens(n):
    while n is not None and n.type == "parenthesized_expression" and n.named_children:
        n = n.named_children[0]
    return n


def call_arg_identifier(call_node, idx):
    """If call_node is `name(arg0, arg1, ...)` and arg[idx] is a plain
    identifier, return (callee_name, arg_identifier_text); else None."""
    fn = call_node.child_by_field_name("function")
    if fn is None or fn.type != "identifier":
        return None
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return None
    named = args.named_children
    if idx >= len(named):
        return None
    a = strip_parens(named[idx])
    if a is None or a.type != "identifier":
        return None
    return text(fn), text(a)


def scan_function_statically(fn_body, spec):
    """One whole-function pass (not CFG/path-sensitive): find every
    BIO_push(V, ...) target var, and every simple `W = X;` assignment, to
    build a syntactic alias closure per establish variable.

    Also treats `W = BIO_push(V, ...);` as aliasing W to V. BIO_push(b, a)
    is documented to return its first argument, so after that statement W
    and V are the same pointer; this codebase's own idiom (see
    B64_write_ASN1/b64_read_asn1 in asn_mime.c) is to push through one
    variable and then pop/free through the one the return value was
    assigned to, not the original. Treating only bare `W = V;` as an alias
    (and not this call-return form) was confirmed to misclassify both of
    those real, correct functions as violations.

    Returns: push_vars (set of names), alias_of (name -> set of group names)."""
    est_re = re.compile(spec["establish"]["call_name_regex"])
    est_idx = spec["establish"]["arg_index"]
    push_vars = set()
    assigns = []  # (W, X)
    for n in walk(fn_body):
        if n.type == "call_expression":
            hit = call_arg_identifier(n, est_idx)
            if hit is not None:
                name, var = hit
                if est_re.search(name):
                    push_vars.add(var)
        elif n.type == "assignment_expression":
            left = strip_parens(n.child_by_field_name("left"))
            op = n.child_by_field_name("operator")
            right = strip_parens(n.child_by_field_name("right"))
            if left is None or left.type != "identifier" or op is None or text(op) != "=":
                continue
            if right is not None and right.type == "identifier":
                assigns.append((text(left), text(right)))
            elif right is not None and right.type == "call_expression":
                fn = right.child_by_field_name("function")
                if fn is not None and fn.type == "identifier" and est_re.search(text(fn)):
                    hit = call_arg_identifier(right, est_idx)
                    if hit is not None:
                        assigns.append((text(left), hit[1]))

    groups = {v: {v} for v in push_vars}
    for _ in range(spec["alias"]["max_passes"]):
        changed = False
        for v, g in groups.items():
            for (w, x) in assigns:
                if x in g and w not in g:
                    g.add(w)
                    changed = True
        if not changed:
            break
    return push_vars, groups


def node_call_hits(ast, name_re, idx, group):
    """List of (callee_name, line) for calls in ast matching name_re whose
    arg[idx] is an identifier in group."""
    hits = []
    for n in walk(ast):
        if n.type != "call_expression":
            continue
        fn = n.child_by_field_name("function")
        if fn is None or fn.type != "identifier" or not name_re.search(text(fn)):
            continue
        hit = call_arg_identifier(n, idx)
        if hit is not None and hit[1] in group:
            hits.append((hit[0], line(n)))
    return hits


def find_establish_nodes(cfg, var, est_re, est_idx):
    """CFG node ids whose ast directly contains BIO_push(var, ...)."""
    out = []
    for n in cfg.nodes:
        if n.ast is None:
            continue
        for c in walk(n.ast):
            if c.type == "call_expression":
                hit = call_arg_identifier(c, est_idx)
                if hit is not None and hit[1] == var and est_re.search(hit[0]):
                    out.append(n.id)
                    break
    return out


def analyse_function(fn, fname, spec, path):
    est_re = re.compile(spec["establish"]["call_name_regex"])
    det_re = re.compile(spec["detach"]["call_name_regex"])
    rel_re = re.compile(spec["release"]["call_name_regex"])
    est_idx = spec["establish"]["arg_index"]
    det_idx = spec["detach"]["arg_index"]
    rel_idx = spec["release"]["arg_index"]

    push_vars, groups = scan_function_statically(fn.child_by_field_name("body"), spec)
    if not push_vars:
        return []

    cfg = build_cfg(fn.child_by_field_name("body"))
    fn_err = fn.has_error
    sites = []

    for var in sorted(push_vars):
        group = groups[var]
        est_nodes = find_establish_nodes(cfg, var, est_re, est_idx)
        if not est_nodes:
            continue

        # unsafe[node_id] = witness path lines reaching this node from an
        # establish node without a detach call in between (seen once, same
        # approximation as Protocol B's reset-forward search: a node's
        # detach/release content is intrinsic to that statement, not
        # path-dependent, so marking a node visited once is sound here).
        parent, seen, dq = {}, set(est_nodes), deque()
        for e in est_nodes:
            for s in cfg.nodes[e].succ:
                if s not in seen:
                    seen.add(s)
                    parent[s] = e
                    dq.append(s)

        unsafe_releases = []   # (node_id, callee, line)
        while dq:
            cur = dq.popleft()
            if cur == cfg.exit:
                continue
            node = cfg.nodes[cur]
            if node.ast is not None:
                rel_hits = node_call_hits(node.ast, rel_re, rel_idx, group)
                if rel_hits:
                    for callee, ln in rel_hits:
                        unsafe_releases.append((cur, callee, ln))
                    continue  # absorbing: this var is freed, obligation ends here
                det_hits = node_call_hits(node.ast, det_re, det_idx, group)
                if det_hits:
                    continue  # absorbing: detached safely, nothing further to check
            for s in node.succ:
                if s not in seen:
                    seen.add(s)
                    parent[s] = cur
                    dq.append(s)

        # Every release call of a group member anywhere in the function is a
        # candidate site; classify each by whether it showed up as unsafe above.
        unsafe_ids = {nid for nid, _, _ in unsafe_releases}
        for n in cfg.nodes:
            if n.ast is None:
                continue
            for callee, ln in node_call_hits(n.ast, rel_re, rel_idx, group):
                site = {"file": path, "function": fname, "var": var,
                        "callee": callee, "line": ln,
                        "function_has_parse_error": fn_err}
                if n.id in unsafe_ids:
                    path_lines, c = [], n.id
                    seen_path = {n.id}
                    while c in parent and parent[c] not in seen_path:
                        c = parent[c]
                        seen_path.add(c)
                        if cfg.nodes[c].ast is not None:
                            path_lines.append(cfg.nodes[c].line)
                    path_lines.reverse()
                    path_lines.append(ln)
                    site["status"] = "violation"
                    site["witness"] = path_lines
                else:
                    site["status"] = "conforming"
                sites.append(site)

    # de-duplicate: the same physical release call can be reached as an
    # unsafe target from more than one establish occurrence of the same var;
    # keep one entry per (file, function, var, line, callee).
    dedup = {}
    for s in sites:
        key = (s["file"], s["function"], s["var"], s["line"], s["callee"])
        if key not in dedup or s["status"] == "violation":
            dedup[key] = s
    return list(dedup.values())


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
    ap.add_argument("--spec", default=os.path.join(HERE, "specs", "bio_chain_pop.json"))
    ap.add_argument("--func", help="only analyse this function name")
    ap.add_argument("--json", help="write all sites to this JSON file")
    ap.add_argument("--quiet", action="store_true", help="print only the summary line")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    spec = json.load(open(a.spec))

    sites, nfiles, errors, parse_err = [], 0, 0, 0
    for path in collect_files(a.paths):
        try:
            data = open(path, "rb").read()
            tree = parse(data)
        except Exception as ex:
            errors += 1
            print("ERROR %s: %s" % (path, ex), file=sys.stderr)
            continue
        nfiles += 1
        if tree.root_node.has_error:
            parse_err += 1
        for fn in functions(tree.root_node):
            fname, _ = function_name_and_params(fn)
            if not fname or (a.func and fname != a.func):
                continue
            try:
                sites += analyse_function(fn, fname, spec, path)
            except Exception as ex:
                errors += 1
                print("ERROR %s:%s: %r" % (path, fname, ex), file=sys.stderr)

    sites.sort(key=lambda s: (s["file"], s["line"], s["var"]))
    count = {k: sum(1 for s in sites if s["status"] == k) for k in ("conforming", "violation")}
    if not a.quiet:
        for s in sites:
            if s["status"] == "violation":
                print("VIOLATION %s:%d %s() releases %s via %s without a prior BIO_pop "
                      "on this path (path lines %s)"
                      % (s["file"], s["line"], s["function"], s["var"], s["callee"], s["witness"]))
    in_err = sum(1 for s in sites if s["function_has_parse_error"])
    print("files=%d release-sites: conforming=%d violation=%d errors=%d "
          "parse_error_files=%d sites_in_functions_with_parse_errors=%d"
          % (nfiles, count["conforming"], count["violation"], errors, parse_err, in_err))
    if a.json:
        json.dump({"spec": spec["name"], "files": nfiles, "counts": count,
                   "errors": errors, "parse_error_files": parse_err, "sites": sites},
                  open(a.json, "w"), indent=1)
    return 1 if count["violation"] else 0


if __name__ == "__main__":
    sys.exit(main())
