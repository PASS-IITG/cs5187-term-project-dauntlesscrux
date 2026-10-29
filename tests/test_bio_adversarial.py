#!/usr/bin/env python3

"""Adversarial tests for the CVE-2023-0215 BIO cleanup rule."""

import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "typestate_check.py"

VULNERABLE = (
    ROOT
    / "openssl-cve-2023-0215-vulnerable"
    / "crypto/asn1/bio_ndef.c"
)

FIXED = (
    ROOT
    / "openssl-cve-2023-0215-fixed"
    / "crypto/asn1/bio_ndef.c"
)


def run_checker(source_path):
    return subprocess.run(
        [sys.executable, str(CHECKER), str(source_path)],
        capture_output=True,
        text=True,
        check=False,
    )


def check_case(name, source_path, expected_exit, expected_text):
    result = run_checker(source_path)
    passed = (
        result.returncode == expected_exit
        and expected_text in result.stdout
    )

    print(f"{'PASS' if passed else 'FAIL'}: {name}")
    print(f"  Expected exit code: {expected_exit}")
    print(f"  Actual exit code:   {result.returncode}")
    print(f"  Output: {result.stdout.strip()}")

    if result.stderr.strip():
        print(f"  Stderr: {result.stderr.strip()}")

    return passed


def main():
    vulnerable_source = VULNERABLE.read_text(encoding="utf-8")
    original_push = "out = BIO_push(asn_bio, out);"

    if vulnerable_source.count(original_push) != 1:
        raise SystemExit(
            "Could not uniquely identify BIO_push line; "
            "no adversarial fixtures were generated."
        )

    unreachable_pop = """err:
    if (0) {
        (void)BIO_pop(asn_bio);
    }
    BIO_free(asn_bio);
    OPENSSL_free(ndef_aux);
    return NULL;"""

    original_cleanup = """err:
    BIO_free(asn_bio);
    OPENSSL_free(ndef_aux);
    return NULL;"""

    if vulnerable_source.count(original_cleanup) != 1:
        raise SystemExit(
            "Could not uniquely identify vulnerable cleanup; "
            "no adversarial fixtures were generated."
        )

    unreachable_source = vulnerable_source.replace(
        original_cleanup, unreachable_pop, 1
    )

    commented_push_source = vulnerable_source.replace(
        original_push,
        "/* out = BIO_push(asn_bio, out); */",
        1,
    )

    with tempfile.TemporaryDirectory(prefix="bio_typestate_test_") as temp:
        temp_dir = Path(temp)

        unreachable_file = temp_dir / "unreachable_pop.c"
        unreachable_file.write_text(
            unreachable_source, encoding="utf-8"
        )

        commented_file = temp_dir / "commented_push.c"
        commented_file.write_text(
            commented_push_source, encoding="utf-8"
        )

        cases = [
            (
                "Real vulnerable OpenSSL source",
                VULNERABLE,
                1,
                "ALERT [CVE-2023-0215]",
            ),
            (
                "Real fixed OpenSSL source",
                FIXED,
                0,
                "NO ALERT [CVE-2023-0215]",
            ),
            (
                "BIO_pop inside unreachable if (0)",
                unreachable_file,
                1,
                "ALERT [CVE-2023-0215]",
            ),
            (
                "BIO_push appearing only in a comment",
                commented_file,
                0,
                "NO ALERT [CVE-2023-0215]",
            ),
        ]

        results = [
            check_case(name, path, code, expected)
            for name, path, code, expected in cases
        ]

    print()
    print(f"Result: {sum(results)}/{len(results)} tests passed.")

    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
