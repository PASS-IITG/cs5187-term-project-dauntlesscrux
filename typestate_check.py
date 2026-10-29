#!/usr/bin/env python3

import re
import sys
from pathlib import Path


def extract_function(source, signature):
    """Extract a C function using simple brace counting."""
    start = source.find(signature)
    if start == -1:
        return None

    opening = source.find("{", start)
    if opening == -1:
        return None

    depth = 0
    for i in range(opening, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]

    return None




def strip_c_comments(source):
    """Replace C comments with spaces, preserving literals and newlines."""
    result = []
    i = 0
    state = "code"

    while i < len(source):
        char = source[i]
        next_char = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char == "/" and next_char == "/":
                result.extend([" ", " "])
                i += 2
                state = "line"
            elif char == "/" and next_char == "*":
                result.extend([" ", " "])
                i += 2
                state = "block"
            elif char == '"':
                result.append(char)
                i += 1
                state = "string"
            elif char == "'":
                result.append(char)
                i += 1
                state = "char"
            else:
                result.append(char)
                i += 1

        elif state == "line":
            if char == "\n":
                result.append("\n")
                state = "code"
            else:
                result.append(" ")
            i += 1

        elif state == "block":
            if char == "*" and next_char == "/":
                result.extend([" ", " "])
                i += 2
                state = "code"
            elif char == "\n":
                result.append("\n")
                i += 1
            else:
                result.append(" ")
                i += 1

        else:  # Inside a string or character literal
            result.append(char)
            if char == "\\" and i + 1 < len(source):
                result.append(source[i + 1])
                i += 2
                continue
            if state == "string" and char == '"':
                state = "code"
            elif state == "char" and char == "'":
                state = "code"
            i += 1

    return "".join(result)



def has_unconditional_bio_pop(function, cleanup, free_pos):
    """
    Accept only an obvious top-level BIO_pop() of the tracked BIO
    before BIO_free(). This is a conservative source heuristic,
    not full C control-flow analysis.
    """
    err_pos = function.find("err:")
    before_cleanup = function[:err_pos] if err_pos >= 0 else function

    allowed_names = {"asn_bio"}
    if re.search(r"\bpop_bio\s*=\s*asn_bio\s*;", before_cleanup):
        allowed_names.add("pop_bio")

    before_free = cleanup[:free_pos]
    pattern = r"\bBIO_pop\s*\(\s*(asn_bio|pop_bio)\s*\)"

    for match in re.finditer(pattern, before_free):
        if match.group(1) not in allowed_names:
            continue

        call_pos = match.start()

        # Reject calls inside a braced block.
        depth = 0
        for char in cleanup[:call_pos]:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1

        if depth != 0:
            continue

        # Also reject obvious single-statement control constructs,
        # such as: if (condition) BIO_pop(asn_bio);
        boundary = max(
            cleanup.rfind(";", 0, call_pos),
            cleanup.rfind("{", 0, call_pos),
            cleanup.rfind("}", 0, call_pos),
        )
        statement_prefix = cleanup[boundary + 1:call_pos]

        if re.search(r"\b(if|else|for|while|switch)\b", statement_prefix):
            continue

        return True

    return False

def check_bio_ndef(path, source):
    """Check the CVE-2023-0215 BIO-chain cleanup pattern."""
    function = extract_function(source, "BIO *BIO_new_NDEF(")

    if function is None:
        return None

    push_found = "BIO_push(asn_bio, out)" in function
    err_pos = function.find("err:")

    if err_pos == -1:
        return None

    cleanup = function[err_pos:]
    free_pos = cleanup.find("BIO_free(asn_bio)")

    if free_pos == -1:
        return None

    pop_found = has_unconditional_bio_pop(function, cleanup, free_pos)

    if push_found and not pop_found:
        print(f"ALERT [CVE-2023-0215]: {path}")
        print("  BIO chain is pushed, then freed in error cleanup")
        print("  without an unconditional BIO_pop() of the tracked BIO")
        print("  before BIO_free().")
        return 1

    print(f"NO ALERT [CVE-2023-0215]: {path}")
    return 0


def check_pem_read(path, source):
    """Check the CVE-2022-4450 dangling-output-pointer pattern."""
    function = extract_function(
        source, "int PEM_read_bio_ex("
    )

    if function is None:
        return None

    cleanup_pos = function.find("out_free:")
    if cleanup_pos == -1:
        return None

    end_pos = function.find("\nend:", cleanup_pos)
    if end_pos == -1:
        return None

    cleanup = function[cleanup_pos:end_pos]

    frees_header = "pem_free(*header, flags, 0);" in cleanup
    frees_data = "pem_free(*data, flags, 0);" in cleanup
    clears_header = "*header = NULL;" in cleanup
    clears_data = "*data = NULL;" in cleanup

    if frees_header and frees_data and not (clears_header and clears_data):
        print(f"ALERT [CVE-2022-4450]: {path}")
        print("  Failure cleanup frees output buffers but does not")
        print("  clear both caller-visible output pointers.")
        return 1

    print(f"NO ALERT [CVE-2022-4450]: {path}")
    return 0



def check_ssl_read_buffer(path, source):
    """Check the CVE-2024-4741 packet-pointer reset pattern."""
    function = extract_function(
        source, "int ssl3_release_read_buffer("
    )

    if function is None:
        return None

    frees_buffer = "OPENSSL_free(b->buf);" in function
    clears_buffer = "b->buf = NULL;" in function
    clears_packet = "s->rlayer.packet = NULL;" in function
    resets_length = "s->rlayer.packet_length = 0;" in function

    if frees_buffer and clears_buffer and not (
        clears_packet and resets_length
    ):
        print(f"ALERT [CVE-2024-4741]: {path}")
        print("  Read buffer is released, but the packet pointer")
        print("  and packet length are not both reset.")
        return 1

    print(f"NO ALERT [CVE-2024-4741]: {path}")
    return 0

def check_file(path):
    try:
        source = Path(path).read_text(
            encoding="utf-8", errors="replace"
        )
        source = strip_c_comments(source)
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}")
        return 2

    results = []
    for checker in (check_bio_ndef, check_pem_read, check_ssl_read_buffer):
        result = checker(path, source)
        if result is not None:
            results.append(result)

    if not results:
        print(f"SKIP: no supported target function found in {path}")
        return 2

    return 1 if 1 in results else 0


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 typestate_check.py <source.c> "
            "[source.c ...]"
        )
        return 2

    results = [check_file(path) for path in sys.argv[1:]]
    if 2 in results:
        return 2
    return 1 if 1 in results else 0


if __name__ == "__main__":
    sys.exit(main())
