"""Tests for Protocol A (BIO-chain detach-before-free)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CHECKER = ROOT / "src/tsck/biochain.py"


def run_source(source):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "sample.c"
        path.write_text(source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(path)],
            capture_output=True,
            text=True,
            check=False,
        )


class BioChainTests(unittest.TestCase):
    def test_missing_pop_is_violation(self):
        result = run_source("""
            void f(int fail) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                if (fail) goto err;
                return;
            err:
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("VIOLATION", result.stdout)

    def test_pop_through_direct_alias_conforms(self):
        result = run_source("""
            void f(int fail) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                BIO *pop_bio = NULL;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                pop_bio = asn_bio;
                if (fail) goto err;
                return;
            err:
                BIO_pop(pop_bio);
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_conditional_pop_leaves_bad_path(self):
        result = run_source("""
            void f(int fail) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                BIO *pop_bio = NULL;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                pop_bio = asn_bio;
                if (fail) BIO_pop(pop_bio);
                goto err;
            err:
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_reassigned_alias_is_not_a_pop(self):
        result = run_source("""
            void f(void) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                BIO *pop_bio = NULL;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                pop_bio = asn_bio;
                pop_bio = NULL;
                BIO_pop(pop_bio);
            err:
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_push_failure_does_not_require_pop(self):
        result = run_source("""
            void f(void) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                return;
            err:
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_error_before_push_does_not_require_pop(self):
        result = run_source("""
            void f(int fail) {
                BIO *asn_bio = make_bio();
                BIO *out = 0;
                if (fail) goto err;
                out = BIO_push(asn_bio, out);
                if (out == NULL) goto err;
                return;
            err:
                BIO_free(asn_bio);
            }
        """)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_cve_2023_pair(self):
        vulnerable = ROOT / "openssl-cve-2023-0215-vulnerable/crypto/asn1/bio_ndef.c"
        fixed = ROOT / "openssl-cve-2023-0215-fixed/crypto/asn1/bio_ndef.c"
        if not vulnerable.exists() or not fixed.exists():
            self.skipTest("CVE-2023-0215 source snapshots are not present")

        before = subprocess.run(
            [sys.executable, str(CHECKER), str(vulnerable)],
            capture_output=True, text=True,
        )
        after = subprocess.run(
            [sys.executable, str(CHECKER), str(fixed)],
            capture_output=True, text=True,
        )
        self.assertEqual(before.returncode, 1, before.stdout + before.stderr)
        self.assertEqual(after.returncode, 0, after.stdout + after.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
