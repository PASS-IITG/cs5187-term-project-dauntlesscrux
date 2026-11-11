#!/usr/bin/env python3
"""
Protocol A: check that a BIO inserted by BIO_push is detached by BIO_pop
before that same BIO is freed by BIO_free on a reachable path.

Scope:
- Intraprocedural CFG analysis.
- Direct BIO_push/BIO_pop/BIO_free calls.
- Direct local aliases such as pop_bio = asn_bio.
- Recognizes the common result guard: if (out == NULL).
This is not general interprocedural pointer or ownership analysis.
"""
import argparse
import os
import sys
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cfg import build_cfg, functions, line, parse, text, walk


def strip_parens(node):
    while node is not None and node.type == "parenthesized_expression":
        if not node.named_children:
            break
        node = node.named_children[0]
    return node


def identifier(node):
    node = strip_parens(node)
    if node is not None and node.type == "identifier":
        return text(node)
    return None


def call_info(node):
    fn = node.child_by_field_name("function")
    args = node.child_by_field_name("arguments")
    if fn is None or fn.type != "identifier" or args is None:
        return None, []
    return text(fn), list(args.named_children)


def assigned_result_name(call):
    """Return the identifier assigned the result of this BIO_push call."""
    parent = call.parent
    while parent is not None:
        if parent.type == "assignment_expression":
            right = parent.child_by_field_name("right")
            left = parent.child_by_field_name("left")
            if (right is not None and
                    right.start_byte <= call.start_byte <= right.end_byte):
                return identifier(left)
        parent = parent.parent
    return None


def node_events(ast):
    """Extract direct assignments and relevant BIO calls in source order."""
    events = []

    for node in walk(ast):
        if node.type == "assignment_expression":
            left = identifier(node.child_by_field_name("left"))
            right = identifier(node.child_by_field_name("right"))
            if left:
                events.append((node.start_byte, 0, "assign", left, right))

        elif node.type == "init_declarator":
            left_node = node.child_by_field_name("declarator")
            while left_node is not None and left_node.type == "pointer_declarator":
                left_node = left_node.child_by_field_name("declarator")
            left = identifier(left_node)
            right = identifier(node.child_by_field_name("value"))
            if left:
                events.append((node.start_byte, 0, "assign", left, right))

        elif node.type == "call_expression":
            name, args = call_info(node)
            if name in ("BIO_push", "BIO_pop", "BIO_free"):
                arg_names = [identifier(arg) for arg in args]
                events.append((node.start_byte, 1, "call",
                               name, arg_names, node, assigned_result_name(node)))

    return sorted(events, key=lambda event: (event[0], event[1]))


def null_comparison(condition, variable):
    """
    Return == or != when condition compares variable with NULL/0.
    Otherwise return None.
    """
    expr = strip_parens(condition)
    if expr is None or expr.type != "binary_expression":
        return None

    op_node = expr.child_by_field_name("operator")
    left = strip_parens(expr.child_by_field_name("left"))
    right = strip_parens(expr.child_by_field_name("right"))
    if op_node is None or left is None or right is None:
        return None

    op = text(op_node)
    if op not in ("==", "!="):
        return None

    left_text, right_text = text(left).strip(), text(right).strip()
    is_null = lambda value: value in ("NULL", "0")

    if left_text == variable and is_null(right_text):
        return op
    if right_text == variable and is_null(left_text):
        return op
    return None


def transfer(ast, state):
    """
    State:
      root       - variable passed as first argument to BIO_push
      aliases    - local identifiers currently known to refer to root
      pushed     - True/False/None (None means no successful push established)
      popped     - whether BIO_pop was called through a tracked alias
      pending    - result variable whose NULL guard can refine push success
    """
    root, aliases, pushed, popped, pending = state
    aliases = set(aliases)
    violations = []

    for event in node_events(ast):
        if event[2] == "assign":
            _, _, _, lhs, rhs = event
            if root and lhs in aliases:
                if rhs in aliases:
                    aliases.add(lhs)
                else:
                    aliases.discard(lhs)
            elif root and rhs in aliases:
                aliases.add(lhs)
            continue

        _, _, _, name, args, call_node, result_name = event

        if name == "BIO_push" and args and args[0]:
            root = args[0]
            aliases = {root}
            pushed = True
            popped = False
            pending = result_name

        elif name == "BIO_pop" and args and args[0] in aliases:
            popped = True

        elif name == "BIO_free" and args and args[0] in aliases:
            if pushed is True and not popped:
                violations.append({
                    "line": line(call_node),
                    "object": root,
                    "callee": name,
                })

    return (root, frozenset(aliases), pushed, popped, pending), violations


def analyse_function(fn, filename, function_name):
    cfg = build_cfg(fn.child_by_field_name("body"))
    initial = (None, frozenset(), None, False, None)

    # Each queue item carries a CFG node, abstract state, and witness lines.
    queue = deque([(cfg.entry, initial, ())])
    seen = set()
    findings = []

    while queue:
        current, state, path = queue.popleft()
        key = (current, state)
        if key in seen:
            continue
        seen.add(key)

        node = cfg.nodes[current]
        next_path = path
        if node.ast is not None:
            next_path = path + (line(node.ast),)

        new_state, violations = transfer(node.ast, state) if node.ast is not None else (state, [])
        for violation in violations:
            findings.append({
                "file": filename,
                "function": function_name,
                "line": violation["line"],
                "object": violation["object"],
                "witness": list(next_path),
            })

        # Refine the success/failure result of BIO_push using its NULL guard.
        pending = new_state[4]
        if current in cfg.branch and pending:
            op = null_comparison(node.ast, pending)
            if op:
                true_node, false_node = cfg.branch[current]
                root, aliases, pushed, popped, _ = new_state

                # out == NULL: true means push failed; false means it succeeded.
                if op == "==":
                    true_state = (root, aliases, False, popped, None)
                    false_state = (root, aliases, True, popped, None)
                else:
                    true_state = (root, aliases, True, popped, None)
                    false_state = (root, aliases, False, popped, None)

                queue.append((true_node, true_state, next_path))
                queue.append((false_node, false_state, next_path))
                continue

        for successor in node.succ:
            queue.append((successor, new_state, next_path))

    # Deduplicate repeated findings reached through equivalent CFG paths.
    unique = {}
    for finding in findings:
        key = (finding["file"], finding["function"], finding["line"])
        unique.setdefault(key, finding)
    return list(unique.values())


def collect_files(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                for name in sorted(names):
                    if name.endswith(".c"):
                        yield os.path.join(root, name)
        else:
            yield path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)

    total_files = 0
    total_functions = 0
    findings = []

    for filename in collect_files(args.paths):
        try:
            with open(filename, "rb") as source:
                tree = parse(source.read())
        except Exception as exc:
            print(f"ERROR {filename}: {exc}", file=sys.stderr)
            continue

        total_files += 1
        if tree.root_node.has_error:
            print(f"WARNING parse errors in {filename}", file=sys.stderr)

        for fn in functions(tree.root_node):
            declarator = fn.child_by_field_name("declarator")
            while declarator is not None and declarator.type != "function_declarator":
                declarator = declarator.child_by_field_name("declarator")
            if declarator is None:
                continue

            function_name = text(declarator.child_by_field_name("declarator"))
            total_functions += 1
            findings.extend(analyse_function(fn, filename, function_name))

    for finding in findings:
        print(
            f"VIOLATION {finding['file']}:{finding['line']} "
            f"{finding['function']}(): {finding['object']} is freed "
            f"after BIO_push without a preceding BIO_pop on this path; "
            f"witness lines={finding['witness']}"
        )

    print(
        f"files={total_files} functions={total_functions} "
        f"BIO-chain violations={len(findings)}"
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
