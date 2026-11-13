"""Logic-only test of protocol_a.py's classification, bypassing tree-sitter
(not installed in this sandbox). Builds a synthetic AST/CFG shaped exactly
like BIO_new_NDEF's vulnerable and fixed control flow, and checks that
analyse_function reports violation / conforming respectively.
"""
import itertools
import os
import sys
import types

# tree-sitter / tree-sitter-c are not installable in this sandbox (no network
# access to pypi). cfg.py only needs them at import time to build a module-
# level parser this test never calls (it builds CFGs by hand), so stub both
# packages out just enough to satisfy `import tree_sitter_c as tsc` and
# `from tree_sitter import Language, Parser`.
_tsc_stub = types.ModuleType("tree_sitter_c")
_tsc_stub.language = lambda: None
_ts_stub = types.ModuleType("tree_sitter")


class _StubLanguage:
    def __init__(self, *a, **k):
        pass


class _StubParser:
    def __init__(self, *a, **k):
        pass


_ts_stub.Language = _StubLanguage
_ts_stub.Parser = _StubParser
sys.modules["tree_sitter_c"] = _tsc_stub
sys.modules["tree_sitter"] = _ts_stub

# Resolve paths relative to this file's own location (src/tsck/tests/ once
# moved there for `make check` discovery), not a hardcoded absolute path --
# the previous version only worked on the machine it was written on.
_HERE = os.path.dirname(os.path.abspath(__file__))
_TSCK_DIR = os.path.dirname(_HERE)
sys.path.insert(0, _TSCK_DIR)
import cfg as cfgmod
import protocol_a as pa

_ids = itertools.count()


class FakeNode:
    def __init__(self, type_, children=None, fields=None, text_val="", ln=1):
        self.type = type_
        self.children = children or []
        self.named_children = list(self.children)
        self._fields = fields or {}
        self.text = text_val.encode()
        self.start_point = (ln - 1, 0)
        self.id = next(_ids)
        self.has_error = False

    def child_by_field_name(self, name):
        return self._fields.get(name)


def ident(name, ln=1):
    return FakeNode("identifier", text_val=name, ln=ln)


def call(name, args, ln=1):
    fn = ident(name, ln)
    arg_nodes = [ident(a, ln) for a in args]
    args_node = FakeNode("argument_list", children=arg_nodes, ln=ln)
    args_node.named_children = arg_nodes
    return FakeNode("call_expression", children=[fn, args_node],
                     fields={"function": fn, "arguments": args_node}, ln=ln)


def assign(left, right, ln=1):
    l, r = ident(left, ln), ident(right, ln)
    op = FakeNode("op", text_val="=", ln=ln)
    return FakeNode("assignment_expression", children=[l, op, r],
                     fields={"left": l, "operator": op, "right": r}, ln=ln)


def build_graph(with_pop):
    """Shape of BIO_new_NDEF: push -> cond(out==NULL) -[true]-> err,
    -[false]-> pop_bio=asn_bio -> cond(cb fails) -[true]-> err, -[false]-> ok exit.
    err label -> (pop if with_pop) -> free -> exit."""
    g = cfgmod.CFG()
    push = g.new("stmt", call("BIO_push", ["asn_bio", "out"], 70))
    g.edge(g.entry, push)
    cond1 = g.new("cond", ident("dummy_cond1"))
    g.edge(push, cond1)
    pop_bio_assign = g.new("stmt", assign("pop_bio", "asn_bio", 71))
    err = g.new("label", None)
    g.edge(cond1, err)          # true: out == NULL -> goto err (before pop_bio assigned)
    g.edge(cond1, pop_bio_assign)  # false: push succeeded
    cond2 = g.new("cond", ident("dummy_cond2"))
    g.edge(pop_bio_assign, cond2)
    ok = g.new("stmt", ident("ok_return", 90))
    g.edge(cond2, err)          # true: callback failed -> goto err
    g.edge(cond2, ok)           # false: success path
    g.edge(ok, g.exit)

    if with_pop:
        pop = g.new("stmt", call("BIO_pop", ["pop_bio"], 121))
        free = g.new("stmt", call("BIO_free", ["asn_bio"], 122))
        g.edge(err, pop)
        g.edge(pop, free)
    else:
        free = g.new("stmt", call("BIO_free", ["asn_bio"], 99))
        g.edge(err, free)
    g.edge(free, g.exit)
    return g


def fn_body_ast(with_pop):
    """Whole-function AST for the static alias/push scan: must contain the
    same BIO_push call and (if with_pop) the pop_bio=asn_bio assignment."""
    kids = [call("BIO_push", ["asn_bio", "out"], 70)]
    if with_pop:
        kids.append(assign("pop_bio", "asn_bio", 71))
        kids.append(call("BIO_pop", ["pop_bio"], 121))
        kids.append(call("BIO_free", ["asn_bio"], 122))
    else:
        kids.append(call("BIO_free", ["asn_bio"], 99))
    return FakeNode("compound_statement", children=kids)


def run_case(name, with_pop, expect_status):
    spec = __import__("json").load(open(
        os.path.join(_TSCK_DIR, "specs", "bio_chain_pop.json")))
    body = fn_body_ast(with_pop)
    graph = build_graph(with_pop)
    fake_fn = FakeNode("function_definition", fields={"body": body})

    orig_build_cfg = pa.build_cfg
    pa.build_cfg = lambda b: graph
    try:
        sites = pa.analyse_function(fake_fn, "BIO_new_NDEF", spec, "bio_ndef.c")
    finally:
        pa.build_cfg = orig_build_cfg

    statuses = {s["status"] for s in sites}
    print(f"{name}: sites={sites}")
    assert sites, f"{name}: expected at least one site, got none"
    assert expect_status in statuses, f"{name}: expected {expect_status} in {statuses}"
    assert len(statuses) == 1, f"{name}: mixed statuses {statuses}, expected only {expect_status}"
    print(f"{name}: OK ({expect_status})")


run_case("vulnerable (no BIO_pop)", with_pop=False, expect_status="violation")
run_case("fixed (BIO_pop before BIO_free)", with_pop=True, expect_status="conforming")


def build_b64_write_asn1_graph():
    """Shape of the real B64_write_ASN1 in asn_mime.c:
    b64 = BIO_new(...); out = BIO_push(b64, out); ...; BIO_pop(out); BIO_free(b64);
    out aliases b64 only through the push's return value, not a bare copy."""
    g = cfgmod.CFG()
    new_stmt = g.new("stmt", assign("b64", "BIO_new_result", 108))
    push_stmt = g.new("stmt", assign("out", "BIO_push(b64, out)", 112))
    # the assignment's right side must itself be the call node for the real
    # scan to see it; wire it directly below instead of through `assign()`.
    push_call = call("BIO_push", ["b64", "out"], 112)
    push_assign = FakeNode("assignment_expression",
                            children=[ident("out", 112), FakeNode("op", text_val="=", ln=112), push_call],
                            fields={"left": ident("out", 112),
                                    "operator": FakeNode("op", text_val="=", ln=112),
                                    "right": push_call}, ln=112)
    push_stmt = g.new("stmt", push_assign)
    g.edge(g.entry, new_stmt)
    g.edge(new_stmt, push_stmt)
    pop_stmt = g.new("stmt", call("BIO_pop", ["out"], 117))
    free_stmt = g.new("stmt", call("BIO_free", ["b64"], 118))
    g.edge(push_stmt, pop_stmt)
    g.edge(pop_stmt, free_stmt)
    g.edge(free_stmt, g.exit)
    return g, push_assign


def run_b64_case():
    import json as _json
    spec = _json.load(open(
        os.path.join(_TSCK_DIR, "specs", "bio_chain_pop.json")))
    graph, push_assign = build_b64_write_asn1_graph()
    body = FakeNode("compound_statement",
                     children=[push_assign, call("BIO_pop", ["out"], 117), call("BIO_free", ["b64"], 118)])
    fake_fn = FakeNode("function_definition", fields={"body": body})

    orig_build_cfg = pa.build_cfg
    pa.build_cfg = lambda b: graph
    try:
        sites = pa.analyse_function(fake_fn, "B64_write_ASN1", spec, "asn_mime.c")
    finally:
        pa.build_cfg = orig_build_cfg

    print(f"B64_write_ASN1 shape (alias via push return value): sites={sites}")
    assert sites, "expected a site"
    assert all(s["status"] == "conforming" for s in sites), \
        f"regression: expected conforming, got {[s['status'] for s in sites]}"
    print("B64_write_ASN1 shape: OK (conforming, false-positive fixed)")


run_b64_case()
print("ALL LOGIC TESTS PASSED")
