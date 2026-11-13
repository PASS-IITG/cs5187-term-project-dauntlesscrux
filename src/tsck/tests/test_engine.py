"""Unit tests for the Protocol B engine on SYNTHETIC C snippets.

These check that cfg.py / outparam.py implement the rule as intended (gotos, branches, loops,
switch, guards, partial release).  They are NOT evidence about OpenSSL; real-source numbers live in
results/ and are kept separate on purpose.

Run:  python3 -m unittest discover -s tests -v      (from src/tsck)
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "outparam.py")


def run(code):
    """Analyse one C snippet; return the list of site statuses sorted by line."""
    with tempfile.TemporaryDirectory() as d:
        src, out = os.path.join(d, "t.c"), os.path.join(d, "o.json")
        with open(src, "w") as fh:
            fh.write(code)
        subprocess.run([sys.executable, TOOL, "--quiet", "--json", out, src],
                       capture_output=True, text=True)
        with open(out) as fh:
            sites = json.load(fh)["sites"]
    return [s["status"] for s in sorted(sites, key=lambda s: s["line"])]


class Protocol(unittest.TestCase):
    def test_free_without_reset_is_violation(self):
        self.assertEqual(run("void f(char **p){ free(*p); }"), ["violation"])

    def test_reset_after_free_conforms(self):
        self.assertEqual(run("void f(char **p){ free(*p); *p = NULL; }"), ["conforming"])

    def test_pointer_depth_one_is_ignored(self):
        self.assertEqual(run("void f(char *p){ free(p); }"), [])

    def test_goto_error_path_without_reset(self):          # the CVE-2022-4450 shape
        code = """int f(char **p, int x){ int ret = 0;
            if (x) goto out_free;
            ret = 1; goto end;
          out_free:
            free(*p);
          end:
            return ret; }"""
        self.assertEqual(run(code), ["violation"])

    def test_goto_error_path_with_reset(self):
        code = """int f(char **p, int x){ int ret = 0;
            if (x) goto out_free;
            ret = 1; goto end;
          out_free:
            free(*p); *p = NULL;
          end:
            return ret; }"""
        self.assertEqual(run(code), ["conforming"])

    def test_goto_skips_the_reset(self):
        self.assertEqual(run("void f(char **p){ free(*p); goto end; *p = NULL; end: return; }"), ["violation"])

    def test_goto_lands_on_the_reset(self):
        self.assertEqual(run("void f(char **p){ free(*p); goto fix; fix: *p = NULL; }"), ["conforming"])

    def test_reset_on_one_branch_only(self):
        self.assertEqual(run("void f(char **p,int c){ free(*p); if (c) { *p = NULL; } }"), ["violation"])

    def test_reset_on_both_branches(self):
        self.assertEqual(run("void f(char **p,int c){ free(*p); if (c) { *p = NULL; } else { *p = NULL; } }"), ["conforming"])

    def test_early_return_between_free_and_reset(self):
        self.assertEqual(run("int f(char **p,int c){ free(*p); if (c) return 0; *p = NULL; return 1; }"), ["violation"])

    def test_loop_with_break(self):
        code = "void f(char **p,int n){ for (int i=0;i<n;i++){ free(*p); if (i==2) break; *p = NULL; } }"
        self.assertEqual(run(code), ["violation"])          # break skips the reset

    def test_switch_cases(self):
        code = """void f(char **p,int k){ switch (k) {
            case 1: free(*p); *p = NULL; break;
            default: free(*p); break; } }"""
        self.assertEqual(run(code), ["conforming", "violation"])

    def test_switch_with_default_covering_all_paths(self):
        code = "void f(char **p,int k){ free(*p); switch (k) { case 1: *p = NULL; break; default: *p = NULL; break; } }"
        self.assertEqual(run(code), ["conforming"])

    def test_switch_without_default_has_a_skip_path(self):
        code = "void f(char **p,int k){ free(*p); switch (k) { case 1: *p = NULL; break; case 2: *p = NULL; break; } }"
        self.assertEqual(run(code), ["violation"])

    def test_deref_after_release_is_suppressed_not_hidden(self):
        code = "int f(char **p){ free_internals(*p); return (*p)->type; }"
        self.assertEqual(run(code), ["suppressed"])

    def test_null_guard_on_reset_is_pruned(self):
        # *p was dereferenced by free(*p), so p != NULL; the else path is infeasible.
        code = "void f(char **p){ free(*p); if (p != NULL) *p = NULL; }"
        self.assertEqual(run(code), ["conforming"])

    def test_passing_p_to_callee_counts_as_reset(self):
        self.assertEqual(run("void f(char **p){ free(*p); reinit(p); }"), ["conforming"])

    def test_double_release_still_flagged(self):
        code = "void f(char **p){ free(*p); free(*p); }"
        self.assertEqual(run(code), ["suppressed", "violation"])

    def test_non_release_call_is_not_a_release(self):
        self.assertEqual(run("void f(char **p){ use(*p); }"), [])


if __name__ == "__main__":
    unittest.main()
