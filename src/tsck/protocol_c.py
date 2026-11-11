#!/usr/bin/env python3
"""protocol_c.py - exploratory Protocol C: struct-field release/reset.

Generalizes Protocol B's rule from "*P for P a T** parameter" to
"OBJ->FIELD for OBJ a pointer-typed parameter of the function": if a
function releases the object a struct field points to, it must reset
that field on every path to function exit, exactly as Protocol B
requires for a T** out-parameter.

This directly targets the gap documented in threats.tex ("Scope of what
is tracked: an out-parameter hidden behind a struct member ... is
invisible"), and is motivated by 10 real, independently-authored OpenSSL
fixes of exactly this shape found by a historical commit search
(results/historical_recurrence_search.md) -- none of which Protocol B or
Protocol A's existing rules can see.

Built and validated this session (Claude). Exploratory: a third rule
added under deadline pressure, tested against real historical
vulnerable/fixed pairs (not yet unit-tested as thoroughly as Protocol
A/B's existing engine tests), and NOT claimed as a replacement for either
protocol. Run it, read its output, and triage every hit against real
source before trusting any count from it -- same discipline as the rest
of this project, applied to a rule that has had much less time to mature.

Usage:
  protocol_c.py [--spec FILE] [--func NAME] [--json OUT] PATH [PATH ...]
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


def field_target_text(n):
    """If n is `base->field` (or `base.field`) where base is a plain identifier,
    return its canonical text 'base->field'/'base.field'; else None.
    Deliberately conservative: only a direct one-level field access off a bare
    identifier counts as a tracked target (no base->mid->field chains, no
    array-indexed bases) -- keeps the rule simple and auditable, same spirit
    as Protocol A's syntactic alias rule."""
    n = strip_parens(n)
    if n is None or n.type != "field_expression":
        return None
    base = strip_parens(n.child_by_field_name("argument"))
    op = n.child_by_field_name("operator")
    field = n.child_by_field_name("field")
    if base is None or base.type != "identifier" or op is None or field is None:
        return None
    return text(base) + text(op) + text(field)


def node_events(ast, target, base_name, rel_re):
    """Events for one tracked target ('base->field') inside one CFG node's AST."""
    releases, reset, uses = [], False, []
    reserved = set()
    nodes = list(walk(ast))
    for n in nodes:
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            name = text(fn) if fn is not None and fn.type == "identifier" else None
            if args is None:
                continue
            for a in args.named_children:
                if name and rel_re.search(name) and field_target_text(a) == target:
                    releases.append((name, line(n)))
                    reserved.add(strip_parens(a).id)
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            op = n.child_by_field_name("operator")
            if field_target_text(left) == target and op is not None and text(op) == "=":
                reset = True
                reserved.add(strip_parens(left).id)
    for n in nodes:
        if n.id not in reserved and field_target_text(n) == target:
            uses.append(line(n))
    return releases, reset, uses


def _pointer_identifier_from_declarator(decl):
    """Unwrap a declarator node; return its identifier name if it is pointer
    typed (passed through at least one pointer_declarator), else None."""
    is_ptr = False
    d = decl
    while d is not None:
        if d.type == "pointer_declarator":
            is_ptr = True
            d = d.child_by_field_name("declarator")
        elif d.type == "init_declarator":
            d = d.child_by_field_name("declarator")
        elif d.type == "identifier":
            return text(d) if is_ptr else None
        else:
            return None
    return None


def pointer_identifiers(fn, params):
    """Identifiers in this function that are pointer-typed: parameters with
    at least one '*' (depth >= 1 in `params`, from function_name_and_params),
    and local declarations whose declarator is a pointer_declarator.
    Deliberately excludes stack-allocated struct/union locals
    (`struct Foo s;`) -- a field of a value, not a pointer, dies with the
    function's own stack frame, so "unreset on exit" is not a meaningful
    hazard for it the way it is for a pointer whose pointee can outlive the
    function. Found by validation: two real false positives
    (x509_name_ex_d2i's `intname`, ossl_sm2_encrypt's `ctext_struct`) were
    exactly this -- stack-local structs, not pointers."""
    ptrs = {p for depth, p, _ in params if depth >= 1}
    for n in walk(fn):
        if n.type != "declaration":
            continue
        for child in n.named_children:
            name = _pointer_identifier_from_declarator(child)
            if name is not None:
                ptrs.add(name)
    return ptrs


def find_targets(fn, rel_re, ptr_idents):
    """Every distinct 'base->field' target used as a release-call argument
    anywhere in this function, where `base` is pointer-typed (see
    pointer_identifiers). `base` may be a parameter or a local pointer (the
    common `void *vctx` -> `TYPE *ctx = vctx;` idiom means the tracked
    struct is very often reached through a local alias, not the parameter
    itself) -- so this is not restricted to the function's own parameters,
    only to pointer-typed identifiers, which excludes plain `base.field` on
    a stack-allocated struct/union local (not a pointer) while still
    catching the aliased-parameter idiom."""
    targets = set()
    for n in walk(fn):
        if n.type != "call_expression":
            continue
        fnode = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        name = text(fnode) if fnode is not None and fnode.type == "identifier" else None
        if args is None or not (name and rel_re.search(name)):
            continue
        for a in args.named_children:
            tgt = field_target_text(a)
            if tgt is not None:
                base = tgt.split("->")[0]
                if "->" in tgt and base in ptr_idents:
                    targets.add(tgt)
    return sorted(targets)


_MEMSET_RE = re.compile(r"^(memset|OPENSSL_cleanse|OPENSSL_clear_free)$")


def whole_object_teardown(fn, base, rel_re):
    """True if, anywhere in this function, `base` itself (the bare struct
    pointer, not a field of it) is either (a) passed to a release call, or
    (b) bulk-cleared with memset/OPENSSL_cleanse. Both mean the whole
    struct's lifetime is ending in this function, so a stale field left
    over from an earlier release is not reachable afterward -- the
    dominant real-world false-positive class found in validation (`_free`
    destructors that release a field then free the struct itself;
    `_reset`-style functions that release fields then `memset` the whole
    struct back to zero). Suppressing these trades a small chance of
    missing a real bug between the two calls for not drowning every real
    hit in redundant "the object is being destroyed anyway" noise."""
    for n in walk(fn):
        if n.type != "call_expression":
            continue
        fnode = n.child_by_field_name("function")
        args = n.child_by_field_name("arguments")
        name = text(fnode) if fnode is not None and fnode.type == "identifier" else None
        if args is None or name is None:
            continue
        first = args.named_children[0] if args.named_children else None
        first = strip_parens(first) if first is not None else None
        if first is None or first.type != "identifier" or text(first) != base:
            continue
        if rel_re.search(name) or _MEMSET_RE.match(name):
            return True
    return False


def analyse_function(fn, fname, path, rel_re, use_supp=True):
    _, params = function_name_and_params(fn)
    ptr_idents = pointer_identifiers(fn, params)
    targets = find_targets(fn, rel_re, ptr_idents)
    if not targets:
        return []
    cfg = build_cfg(fn.child_by_field_name("body"))
    fn_err = fn.has_error
    sites = []
    teardown_cache = {}
    for target in targets:
        base = target.split("->")[0].split(".")[0]
        if base not in teardown_cache:
            teardown_cache[base] = whole_object_teardown(fn, base, rel_re)
        teardown = teardown_cache[base]
        ev = {}
        for n in cfg.nodes:
            if n.ast is not None:
                ev[n.id] = node_events(n.ast, target, base, rel_re)
        for n in cfg.nodes:
            if n.id not in ev or not ev[n.id][0]:
                continue
            for callee, ln in ev[n.id][0]:
                site = {"file": path, "function": fname, "target": target,
                        "callee": callee, "line": ln, "function_has_parse_error": fn_err}
                if ev[n.id][1]:
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
                            continue
                        use_lines += e[2] + [l for _, l in e[0]]
                    for s in cfg.nodes[cur].succ:
                        if s not in seen:
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
                    site["witness"] = [ln] + path_lines[::-1]
                    if teardown:
                        site["status"] = "suppressed"
                        site["reason"] = ("whole-object teardown: %s itself is freed or "
                                          "memset to zero elsewhere in this function" % base)
                    elif use_supp and use_lines:
                        site["status"] = "suppressed"
                        site["reason"] = "deref-after-release at lines %s" % sorted(set(use_lines))
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
    ap.add_argument("--spec", default=os.path.join(HERE, "specs", "structfield_reset.json"))
    ap.add_argument("--func")
    ap.add_argument("--json")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    spec = json.load(open(a.spec))
    rel_re = re.compile(spec["release"]["call_name_regex"])

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
                sites += analyse_function(fn, fname, path, rel_re)
            except Exception as ex:
                errors += 1
                print("ERROR %s:%s: %r" % (path, fname, ex), file=sys.stderr)

    sites.sort(key=lambda s: (s["file"], s["line"], s["target"]))
    count = {k: sum(1 for s in sites if s["status"] == k)
             for k in ("conforming", "violation", "suppressed")}
    if not a.quiet:
        for s in sites:
            if s["status"] == "violation":
                print("VIOLATION %s:%d %s() releases %s via %s; exit reachable without reset (path lines %s)"
                      % (s["file"], s["line"], s["function"], s["target"], s["callee"], s["witness"]))
        for s in sites:
            if s["status"] == "suppressed":
                print("SUPPRESSED %s:%d %s() releases %s via %s; %s"
                      % (s["file"], s["line"], s["function"], s["target"], s["callee"], s["reason"]))
    print("files=%d release-sites: conforming=%d violation=%d suppressed=%d errors=%d parse_error_files=%d"
          % (nfiles, count["conforming"], count["violation"], count["suppressed"], errors, parse_err))
    if a.json:
        json.dump({"spec": spec["name"], "files": nfiles, "counts": count,
                   "errors": errors, "parse_error_files": parse_err, "sites": sites},
                  open(a.json, "w"), indent=1)
    return 1 if count["violation"] else 0


if __name__ == "__main__":
    sys.exit(main())
