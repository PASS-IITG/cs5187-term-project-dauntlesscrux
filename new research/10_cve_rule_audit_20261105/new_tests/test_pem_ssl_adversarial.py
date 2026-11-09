#!/usr/bin/env python3
"""Source-pattern edge cases for PEM and SSL CVE rules."""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "src" / "typestate_check.py"
SOURCE_ROOT = ROOT

PAIRS = {
    "pem": (
        SOURCE_ROOT / "openssl-CVE-2022-4450-vulnerable/crypto/pem/pem_lib.c",
        SOURCE_ROOT / "openssl-CVE-2022-4450-fixed/crypto/pem/pem_lib.c",
    ),
    "ssl": (
        SOURCE_ROOT / "openssl-CVE-2024-4741-vulnerable/ssl/record/ssl3_buffer.c",
        SOURCE_ROOT / "openssl-CVE-2024-4741-fixed/ssl/record/ssl3_buffer.c",
    ),
    "bio": (
        SOURCE_ROOT / "openssl-CVE-2023-0215-vulnerable/crypto/asn1/bio_ndef.c",
        SOURCE_ROOT / "openssl-CVE-2023-0215-fixed/crypto/asn1/bio_ndef.c",
    ),
}


def invoke(path):
    return subprocess.run(
        [sys.executable, str(CHECKER), str(path)],
        capture_output=True, text=True, check=False,
    )


def record(name, path, expected, token):
    result = invoke(path)
    ok = result.returncode == expected and token in result.stdout
    print(f"{'PASS' if ok else 'FAIL'}: {name}")
    print(f"  expected exit={expected}; actual exit={result.returncode}")
    print(f"  {result.stdout.strip()}")
    if result.stderr:
        print(f"  stderr: {result.stderr.strip()}")
    return ok


def replace_once(text, old, new, name):
    if text.count(old) != 1:
        raise RuntimeError(f"{name}: expected one occurrence of {old!r}")
    return text.replace(old, new, 1)


def main():
    source = {key: (v.read_text(encoding="utf-8"), f.read_text(encoding="utf-8"))
              for key, (v, f) in PAIRS.items()}
    tests = []
    with tempfile.TemporaryDirectory(prefix="typestate_audit_") as tmp:
        tmp = Path(tmp)

        def fixture(name, text):
            path = tmp / f"{name}.c"
            path.write_text(text, encoding="utf-8")
            return path

        # Every CVE's real vulnerable/fixed pair is part of this standalone run.
        for key, (vpath, fpath) in PAIRS.items():
            tests.append((f"{key} real vulnerable", vpath, 1, "STATE: VIOLATION"))
            tests.append((f"{key} real fixed", fpath, 0, "STATE: CONFORMING"))

        pem_v, pem_f = source["pem"]
        pem_missing_data = replace_once(
            pem_f, "    *data = NULL;\nend:", "end:", "PEM missing data reset"
        )
        tests.append(("PEM one freed output not reset", fixture("pem_missing_data", pem_missing_data), 1,
                      "STATE: VIOLATION"))

        pem_conditional_clear = replace_once(
            pem_f, "    *header = NULL;\n", "    if (retry) {\n        *header = NULL;\n    }\n",
            "PEM conditional reset"
        )
        tests.append(("PEM conditional output reset", fixture("pem_conditional", pem_conditional_clear), 2,
                      "STATE: UNKNOWN"))

        cleanup = """out_free:
    pem_free(*header, flags, 0);
    *header = NULL;
    pem_free(*data, flags, 0);
    *data = NULL;
"""
        wrapped_cleanup = """out_free:
    if (0) {
        pem_free(*header, flags, 0);
        *header = NULL;
        pem_free(*data, flags, 0);
        *data = NULL;
    }
"""
        pem_dead_cleanup = replace_once(pem_f, cleanup, wrapped_cleanup, "PEM unreachable cleanup")
        tests.append(("PEM unreachable cleanup pair", fixture("pem_dead_cleanup", pem_dead_cleanup), 2,
                      "STATE: UNKNOWN"))

        pem_reordered = replace_once(
            pem_f,
            "    pem_free(*header, flags, 0);\n    *header = NULL;",
            "    *header = NULL;\n    pem_free(*header, flags, 0);",
            "PEM reset before free",
        )
        tests.append(("PEM output reset before free", fixture("pem_reordered", pem_reordered), 2,
                      "STATE: UNKNOWN"))

        pem_alias = replace_once(
            pem_f,
            "int PEM_read_bio_ex(BIO *bp, char **name_out, char **header,",
            "int PEM_read_bio_ex(BIO *bp, char **name_out, char **header,",
            "PEM alias fixture signature",
        )
        pem_alias = replace_once(
            pem_alias,
            "{\n    EVP_ENCODE_CTX *ctx = NULL;",
            "{\n    char **header_out = header;\n    EVP_ENCODE_CTX *ctx = NULL;",
            "PEM alias declaration",
        )
        pem_alias = replace_once(
            pem_alias, "pem_free(*header, flags, 0);",
            "pem_free(*header_out, flags, 0);", "PEM alias free",
        )
        tests.append(("PEM aliased output cleanup unsupported", fixture("pem_alias", pem_alias), 2,
                      "STATE: UNKNOWN"))

        ssl_v, ssl_f = source["ssl"]
        ssl_missing_length = replace_once(
            ssl_f, "    s->rlayer.packet_length = 0;\n", "",
            "SSL missing length reset",
        )
        tests.append(("SSL packet length not reset", fixture("ssl_missing_length", ssl_missing_length), 1,
                      "STATE: VIOLATION"))

        ssl_conditional = replace_once(
            ssl_f, "    s->rlayer.packet = NULL;\n",
            "    if (retry)\n        s->rlayer.packet = NULL;\n",
            "SSL conditional packet reset",
        )
        tests.append(("SSL conditional packet reset", fixture("ssl_conditional", ssl_conditional), 2,
                      "STATE: UNKNOWN"))

        ssl_dead_reset = replace_once(
            ssl_f, "    s->rlayer.packet_length = 0;\n",
            "    if (0) {\n        s->rlayer.packet_length = 0;\n    }\n",
            "SSL unreachable length reset",
        )
        tests.append(("SSL unreachable state reset", fixture("ssl_dead_reset", ssl_dead_reset), 2,
                      "STATE: UNKNOWN"))

        ssl_order = replace_once(
            ssl_f,
            "    OPENSSL_free(b->buf);\n    b->buf = NULL;\n    s->rlayer.packet = NULL;",
            "    s->rlayer.packet = NULL;\n    OPENSSL_free(b->buf);\n    b->buf = NULL;",
            "SSL reset before release",
        )
        tests.append(("SSL state reset before release unsupported", fixture("ssl_order", ssl_order), 2,
                      "STATE: UNKNOWN"))

        bio_v, bio_f = source["bio"]
        bio_push = "    out = BIO_push(asn_bio, out);\n"
        bio_nested_push = replace_once(
            bio_v, bio_push,
            "    if (0) {\n        out = BIO_push(asn_bio, out);\n    }\n",
            "BIO unreachable push",
        )
        tests.append(("BIO insertion only in unreachable branch", fixture("bio_dead_push", bio_nested_push), 2,
                      "STATE: UNKNOWN"))

        bio_alias_push = replace_once(
            bio_v,
            "    BIO *asn_bio = NULL;\n",
            "    BIO *asn_bio = NULL;\n    BIO *push_alias = asn_bio;\n",
            "BIO alias declaration",
        )
        bio_alias_push = replace_once(
            bio_alias_push,
            bio_push,
            "    out = BIO_push(push_alias, out);\n",
            "BIO alias push",
        )
        tests.append(("BIO push through unsupported alias", fixture("bio_alias_push", bio_alias_push), 2,
                      "STATE: UNKNOWN"))

        passed = sum(record(name, path, code, token) for name, path, code, token in tests)
        print(f"\nResult: {passed}/{len(tests)} tests passed.")
        return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    raise SystemExit(main())
