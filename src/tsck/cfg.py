"""cfg.py - parse C with tree-sitter and build an intraprocedural CFG per function.

Each CFG node corresponds to one simple statement, one branch/loop condition,
a label, or a join point.  Error paths such as `goto err;` become real edges.

Approximations (listed under threats to validity in the paper):
  * `&&` / `||` inside one condition is a single node (no short-circuit edges).
  * `#if` / `#ifdef` blocks are treated as "branch or skip" (both variants kept).
  * `switch`: every `case` label is reachable from the switch head; fallthrough is kept.
  * Macro bodies are not expanded; a macro call is an ordinary call expression.
"""
import sys
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

sys.setrecursionlimit(20000)
_LANG = Language(tsc.language())
_PARSER = Parser(_LANG)


def parse(data: bytes):
    return _PARSER.parse(data)


def text(node) -> str:
    return node.text.decode("utf8", "replace") if node is not None else ""


def line(node) -> int:
    return node.start_point[0] + 1


def walk(node):
    """Yield node and all descendants (pre-order, iterative)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


class CNode:
    __slots__ = ("id", "kind", "ast", "line", "succ")

    def __init__(self, nid, kind, ast, ln=None):
        # `ast` holds only the code executed AT this node (a simple statement or a
        # condition expression).  Labels, joins and loop heads without a condition
        # have ast=None so statements nested below them are never counted twice.
        self.id, self.kind, self.ast = nid, kind, ast
        self.line = ln if ln is not None else (line(ast) if ast is not None else 0)
        self.succ = []


class CFG:
    def __init__(self):
        self.nodes = []
        self.entry = self.new("entry", None)
        self.exit = self.new("exit", None)
        self.branch = {}          # cond node id -> (true-branch node id, false-branch node id)

    def new(self, kind, ast, ln=None):
        n = CNode(len(self.nodes), kind, ast, ln)
        self.nodes.append(n)
        return n.id

    def edge(self, a, b):
        if b not in self.nodes[a].succ:
            self.nodes[a].succ.append(b)

    def link(self, preds, b):
        for p in preds:
            self.edge(p, b)


_SIMPLE = {"expression_statement", "declaration", "ERROR"}
_IGNORE = {"comment", "preproc_include", "preproc_def", "preproc_function_def",
           "preproc_call", "preproc_params"}


class Builder:
    def __init__(self):
        self.g = CFG()
        self.labels = {}
        self.gotos = []
        self.breaks = []
        self.continues = []
        self.switches = []

    # ---- helpers -------------------------------------------------------
    def _simple(self, node, preds):
        n = self.g.new("stmt", node)
        self.g.link(preds, n)
        return [n]

    @staticmethod
    def _body_children(node, skip):
        skip_ids = {s.id for s in skip if s is not None}
        return [c for c in node.named_children
                if c.id not in skip_ids and c.type != "comment"]

    def seq(self, nodes, preds):
        for c in nodes:
            preds = self.stmt(c, preds)
        return preds

    # ---- statements ----------------------------------------------------
    def stmt(self, node, preds):
        t = node.type
        if t in _IGNORE:
            return preds
        if t == "compound_statement":
            return self.seq(node.named_children, preds)
        if t in _SIMPLE:
            return self._simple(node, preds)
        if t == "return_statement":
            n = self._simple(node, preds)[0]
            self.g.edge(n, self.g.exit)
            return []
        if t == "goto_statement":
            n = self._simple(node, preds)[0]
            self.gotos.append((n, text(node.child_by_field_name("label"))))
            return []
        if t == "break_statement":
            n = self._simple(node, preds)[0]
            if self.breaks:
                self.g.edge(n, self.breaks[-1])
            return []
        if t == "continue_statement":
            n = self._simple(node, preds)[0]
            if self.continues:
                self.g.edge(n, self.continues[-1])
            return []
        if t == "labeled_statement":
            name = text(node.child_by_field_name("label"))
            lab = self.labels.get(name)
            if lab is None:
                lab = self.labels[name] = self.g.new("label", None, line(node))
            self.g.link(preds, lab)
            body = self._body_children(node, [node.child_by_field_name("label")])
            return self.seq(body, [lab])
        if t == "attributed_statement":
            return self.seq(self._body_children(node, []), preds)
        if t == "if_statement":
            return self._if(node, preds)
        if t in ("while_statement", "for_statement", "do_statement"):
            return self._loop(node, preds)
        if t == "switch_statement":
            return self._switch(node, preds)
        if t == "case_statement":
            return self._case(node, preds)
        if t in ("preproc_if", "preproc_ifdef", "preproc_elif", "preproc_elifdef"):
            return self._preproc(node, preds)
        if t == "preproc_else":
            return self.seq(self._body_children(node, []), preds)
        if t.endswith("_statement"):          # unknown statement kind: keep as simple
            return self._simple(node, preds)
        return preds                           # bare expressions, types, ... ignored

    def _if(self, node, preds):
        g = self.g
        cond = g.new("cond", node.child_by_field_name("condition"))
        g.link(preds, cond)
        t, f = g.new("join", None), g.new("join", None)
        g.edge(cond, t)
        g.edge(cond, f)
        g.branch[cond] = (t, f)
        exits = self.stmt(node.child_by_field_name("consequence"), [t])
        alt = node.child_by_field_name("alternative")
        if alt is None:
            return exits + [f]
        if alt.type == "else_clause":
            return exits + self.seq(self._body_children(alt, []), [f])
        return exits + self.stmt(alt, [f])

    def _loop(self, node, preds):
        g, t = self.g, node.type
        after = g.new("join", None)
        if t == "do_statement":
            top = g.new("join", None)
            g.link(preds, top)
            cond_ast = node.child_by_field_name("condition")
            cond = g.new("cond", cond_ast)
            self.breaks.append(after); self.continues.append(cond)
            ex = self.stmt(node.child_by_field_name("body"), [top])
            self.breaks.pop(); self.continues.pop()
            g.link(ex, cond)
            if text(cond_ast).replace(" ", "") != "(0)":
                g.edge(cond, top)
            g.edge(cond, after)
            return [after]
        if t == "for_statement":
            init = node.child_by_field_name("initializer")
            if init is not None:
                preds = self._simple(init, preds)
            cond_ast = node.child_by_field_name("condition")
            head = g.new("cond", cond_ast, line(node))
            g.link(preds, head)
            upd_ast = node.child_by_field_name("update")
            upd = g.new("stmt", upd_ast) if upd_ast is not None else g.new("join", None)
            self.breaks.append(after); self.continues.append(upd)
            ex = self.stmt(node.child_by_field_name("body"), [head])
            self.breaks.pop(); self.continues.pop()
            g.link(ex, upd)
            g.edge(upd, head)
            if cond_ast is not None and text(cond_ast).replace(" ", "") not in ("1", "true"):
                g.edge(head, after)
            return [after]
        # while
        cond_ast = node.child_by_field_name("condition")
        head = g.new("cond", cond_ast)
        g.link(preds, head)
        self.breaks.append(after); self.continues.append(head)
        ex = self.stmt(node.child_by_field_name("body"), [head])
        self.breaks.pop(); self.continues.pop()
        g.link(ex, head)
        if text(cond_ast).replace(" ", "") not in ("(1)", "(true)"):
            g.edge(head, after)
        return [after]

    def _switch(self, node, preds):
        g = self.g
        cond = g.new("cond", node.child_by_field_name("condition"))
        g.link(preds, cond)
        after = g.new("join", None)
        info = {"cond": cond, "default": False}
        self.switches.append(info); self.breaks.append(after)
        ex = self.stmt(node.child_by_field_name("body"), [])
        self.switches.pop(); self.breaks.pop()
        g.link(ex, after)
        if not info["default"]:
            g.edge(cond, after)
        return [after]

    def _case(self, node, preds):
        g = self.g
        c = g.new("label", None, line(node))
        g.link(preds, c)                       # fallthrough from previous case
        if self.switches:
            g.edge(self.switches[-1]["cond"], c)
            if node.children and node.children[0].type == "default":
                self.switches[-1]["default"] = True
        body = self._body_children(node, [node.child_by_field_name("value")])
        return self.seq(body, [c])

    def _preproc(self, node, preds):
        skip = [node.child_by_field_name("condition"), node.child_by_field_name("name")]
        alt = node.child_by_field_name("alternative")
        skip.append(alt)
        then = self._body_children(node, skip)
        a = self.seq(then, preds)
        b = self.stmt(alt, preds) if alt is not None else preds
        return a + [x for x in b if x not in a]


def build_cfg(body):
    """Build the CFG for a function body (compound_statement)."""
    b = Builder()
    ex = b.stmt(body, [b.g.entry])
    b.g.link(ex, b.g.exit)
    for gnode, name in b.gotos:
        b.g.edge(gnode, b.labels.get(name, b.g.exit))
    return b.g


def function_name_and_params(fn):
    """Return (name, [(depth, param_name, decl_text)]) for a function_definition."""
    d = fn.child_by_field_name("declarator")
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    if d is None:
        return None, []
    name = text(d.child_by_field_name("declarator"))
    params = []
    plist = d.child_by_field_name("parameters")
    for p in (plist.named_children if plist is not None else []):
        if p.type != "parameter_declaration":
            continue
        decl, depth = p.child_by_field_name("declarator"), 0
        while decl is not None and decl.type == "pointer_declarator":
            depth += 1
            decl = decl.child_by_field_name("declarator")
        if decl is not None and decl.type == "identifier":
            params.append((depth, text(decl), text(p)))
    return name, params


def functions(root):
    for n in walk(root):
        if n.type == "function_definition" and n.child_by_field_name("body") is not None:
            yield n
