#!/usr/bin/env python3

import re
import sys
from enum import Enum
from pathlib import Path



class AnalysisStatus(Enum):
    VIOLATION = "VIOLATION"
    CONFORMING = "CONFORMING"
    UNKNOWN = "UNKNOWN"


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


def _brace_depth_at(source, position):
    """Return lexical brace depth, ignoring braces inside C literals."""
    depth = 0
    state = "code"
    i = 0
    while i < position:
        char = source[i]
        if state == "code":
            if char == '"':
                state = "string"
            elif char == "'":
                state = "char"
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
        elif char == "\\":
            i += 1
        elif state == "string" and char == '"':
            state = "code"
        elif state == "char" and char == "'":
            state = "code"
        i += 1
    return depth


def _top_level_unconditional_matches(source, pattern, target_depth=1):
    """Find direct function-body matches outside nested/conditional code.

    This is a bounded lexical check, not C control-flow analysis.
    """
    matches = list(re.finditer(pattern, source))
    accepted = []
    for match in matches:
        if _brace_depth_at(source, match.start()) != target_depth:
            continue
        boundary = max(source.rfind(";", 0, match.start()),
                       source.rfind("{", 0, match.start()),
                       source.rfind("}", 0, match.start()))
        prefix = source[boundary + 1:match.start()]
        if re.search(r"\b(if|else|for|while|switch)\b", prefix):
            continue
        accepted.append(match)
    return matches, accepted



def has_unconditional_bio_pop(function, cleanup, free_pos):
    """
    Accept an obvious top-level BIO_pop() of asn_bio or a
    directly assigned top-level alias before BIO_free().

    This remains a conservative source heuristic, not full
    C control-flow or points-to analysis.
    """
    err_pos = function.find("err:")
    before_cleanup = function[:err_pos] if err_pos >= 0 else function

    allowed_names = {"asn_bio"}

    alias_pattern = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*asn_bio\s*;"
    )

    for assignment in alias_pattern.finditer(before_cleanup):
        alias = assignment.group(1)

        if alias == "asn_bio":
            continue

        # Require the alias assignment at function-body top level.
        depth = 0
        for char in before_cleanup[:assignment.start()]:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1

        if depth != 1:
            continue

        # Do not trust an alias overwritten later before cleanup.
        remainder = before_cleanup[assignment.end():]
        reassignment = re.search(
            rf"\b{re.escape(alias)}\s*=(?!=)",
            remainder
        )
        if reassignment:
            continue

        allowed_names.add(alias)

    before_free = cleanup[:free_pos]
    pattern = r"\bBIO_pop\s*\(\s*([A-Za-z_]\w*)\s*\)"

    for match in re.finditer(pattern, before_free):
        alias = match.group(1)

        if alias not in allowed_names:
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

        # Reject obvious conditional single-statement calls.
        boundary = max(
            cleanup.rfind(";", 0, call_pos),
            cleanup.rfind("{", 0, call_pos),
            cleanup.rfind("}", 0, call_pos),
        )
        statement_prefix = cleanup[boundary + 1:call_pos]

        if re.search(r"\b(if|else|for|while|switch)\b", statement_prefix):
            continue

        # An alias must not be overwritten between the error label
        # and the BIO_pop() call.
        if alias != "asn_bio" and re.search(
            rf"\b{re.escape(alias)}\s*=(?!=)",
            cleanup[:call_pos]
        ):
            continue

        return True

    return False

def check_bio_ndef(path, source):
    """Check the CVE-2023-0215 BIO-chain cleanup invariant."""
    function = extract_function(source, "BIO *BIO_new_NDEF(")

    if function is None:
        return AnalysisStatus.UNKNOWN

    push_pattern = r"\bBIO_push\s*\(\s*asn_bio\s*,\s*out\s*\)"
    push_matches, push_top_level = _top_level_unconditional_matches(
        function, push_pattern
    )
    any_pushes = list(re.finditer(r"\bBIO_push\s*\(", function))
    err_pos = function.find("err:")

    if err_pos == -1:
        return AnalysisStatus.UNKNOWN

    cleanup = function[err_pos:]
    free_pattern = r"\bBIO_free\s*\(\s*asn_bio\s*\)"
    free_matches, free_top_level = _top_level_unconditional_matches(
        cleanup, free_pattern, target_depth=0
    )

    if len(free_top_level) != 1:
        print(f"SKIP: no supported target cleanup found in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    free_pos = free_top_level[0].start()
    if not free_matches:
        return AnalysisStatus.UNKNOWN

    if not push_matches:
        if any_pushes:
            print(f"SKIP: BIO_push() target or alias is unsupported in {path}")
            print("  STATE: UNKNOWN")
            return AnalysisStatus.UNKNOWN
        print(f"NO ALERT [CVE-2023-0215]: {path}")
        print("  No BIO_push() ownership transfer was found.")
        print("  STATE: CONFORMING")
        return AnalysisStatus.CONFORMING

    if len(push_top_level) != 1:
        print(f"SKIP: BIO_push() is conditional or nested in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    pop_found = has_unconditional_bio_pop(function, cleanup, free_pos)

    if not pop_found:
        print(f"ALERT [CVE-2023-0215]: {path}")
        print("  BIO chain is pushed, then freed in error cleanup")
        print("  without an unconditional BIO_pop() of the tracked BIO")
        print("  before BIO_free().")
        print("  STATE: VIOLATION")
        return AnalysisStatus.VIOLATION

    print(f"NO ALERT [CVE-2023-0215]: {path}")
    print("  STATE: CONFORMING")
    return AnalysisStatus.CONFORMING


def check_pem_read(path, source):
    """Check the CVE-2022-4450 dangling-output-pointer invariant."""
    function = extract_function(source, "int PEM_read_bio_ex(")

    if function is None:
        return AnalysisStatus.UNKNOWN

    cleanup_pos = function.find("out_free:")
    if cleanup_pos == -1:
        return AnalysisStatus.UNKNOWN

    end_pos = function.find("\nend:", cleanup_pos)
    if end_pos == -1:
        return AnalysisStatus.UNKNOWN

    cleanup = function[cleanup_pos:end_pos]

    header_free_pattern = r"\bpem_free\s*\(\s*\*\s*header\s*,\s*flags\s*,\s*0\s*\)\s*;"
    data_free_pattern = r"\bpem_free\s*\(\s*\*\s*data\s*,\s*flags\s*,\s*0\s*\)\s*;"
    header_clear_pattern = r"\*\s*header\s*=\s*NULL\s*;"
    data_clear_pattern = r"\*\s*data\s*=\s*NULL\s*;"
    hfree_all, hfree = _top_level_unconditional_matches(
        cleanup, header_free_pattern, target_depth=0
    )
    dfree_all, dfree = _top_level_unconditional_matches(
        cleanup, data_free_pattern, target_depth=0
    )
    hclear_all, hclear = _top_level_unconditional_matches(
        cleanup, header_clear_pattern, target_depth=0
    )
    dclear_all, dclear = _top_level_unconditional_matches(
        cleanup, data_clear_pattern, target_depth=0
    )

    if any(len(all_matches) != 1 or len(top_matches) != 1
           for all_matches, top_matches in ((hfree_all, hfree), (dfree_all, dfree))):
        return AnalysisStatus.UNKNOWN

    if any(all_matches and len(top_matches) != len(all_matches)
           for all_matches, top_matches in ((hclear_all, hclear),
                                            (dclear_all, dclear))):
        print(f"SKIP: conditional PEM output reset in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    frees_header = bool(hfree)
    frees_data = bool(dfree)
    clears_header = bool(hclear)
    clears_data = bool(dclear)
    ordered = (clears_header and clears_data
               and hclear[0].start() > hfree[0].end()
               and dclear[0].start() > dfree[0].end())

    if frees_header and frees_data and not (clears_header and clears_data):
        print(f"ALERT [CVE-2022-4450]: {path}")
        print("  Failure cleanup frees output buffers but does not")
        print("  clear both caller-visible output pointers.")
        print("  STATE: VIOLATION")
        return AnalysisStatus.VIOLATION

    if frees_header and frees_data and clears_header and clears_data and ordered:
        print(f"NO ALERT [CVE-2022-4450]: {path}")
        print("  STATE: CONFORMING")
        return AnalysisStatus.CONFORMING

    if clears_header and clears_data and not ordered:
        print(f"SKIP: PEM output cleanup ordering is unsupported in {path}")
        print("  STATE: UNKNOWN")
    return AnalysisStatus.UNKNOWN


def check_ssl_read_buffer(path, source):
    """Check the CVE-2024-4741 read-buffer pointer-reset invariant."""
    function = extract_function(source, "int ssl3_release_read_buffer(")

    if function is None:
        return AnalysisStatus.UNKNOWN

    free_pattern = r"\bOPENSSL_free\s*\(\s*b\s*->\s*buf\s*\)\s*;"
    free_matches, free_top_level = _top_level_unconditional_matches(
        function, free_pattern
    )

    if not free_matches:
        return AnalysisStatus.UNKNOWN

    if len(free_matches) != 1 or len(free_top_level) != 1:
        print(f"SKIP: SSL buffer release is conditional or nested in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    reset_patterns = (
        r"\bb\s*->\s*buf\s*=\s*NULL\s*;",
        r"\bs\s*->\s*rlayer\s*\.\s*packet\s*=\s*NULL\s*;",
        r"\bs\s*->\s*rlayer\s*\.\s*packet_length\s*=\s*0\s*;",
    )
    reset_results = [_top_level_unconditional_matches(function, pattern)
                     for pattern in reset_patterns]
    if any(all_matches and len(top_matches) != len(all_matches)
           for all_matches, top_matches in reset_results):
        print(f"SKIP: conditional SSL buffer-state reset in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN
    if any(len(all_matches) > 1 or len(top_matches) > 1
           for all_matches, top_matches in reset_results):
        print(f"SKIP: multiple SSL buffer-state resets in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN
    reset_matches = [top_matches[0] if top_matches else None
                     for _, top_matches in reset_results]
    clears_buffer, clears_packet, resets_length = [match is not None
                                                   for match in reset_matches]

    if not (clears_buffer and clears_packet and resets_length):
        print(f"ALERT [CVE-2024-4741]: {path}")
        print("  Read buffer is released, but one or more")
        print("  associated pointers or lengths are not reset.")
        print("  STATE: VIOLATION")
        return AnalysisStatus.VIOLATION

    if any(match.start() < free_top_level[0].end()
           for match in reset_matches):
        print(f"SKIP: SSL buffer reset ordering is unsupported in {path}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    print(f"NO ALERT [CVE-2024-4741]: {path}")
    print("  STATE: CONFORMING")
    return AnalysisStatus.CONFORMING


def check_file(path):
    try:
        source = Path(path).read_text(
            encoding="utf-8", errors="replace"
        )
        source = strip_c_comments(source)
    except OSError as exc:
        print(f"ERROR: cannot read {path}: {exc}")
        print("  STATE: UNKNOWN")
        return AnalysisStatus.UNKNOWN

    results = []
    for checker in (check_bio_ndef, check_pem_read, check_ssl_read_buffer):
        result = checker(path, source)
        if result != AnalysisStatus.UNKNOWN:
            results.append(result)

    if AnalysisStatus.VIOLATION in results:
        return AnalysisStatus.VIOLATION

    if AnalysisStatus.CONFORMING in results:
        return AnalysisStatus.CONFORMING

    print(f"SKIP: no supported target function found in {path}")
    print("  STATE: UNKNOWN")
    return AnalysisStatus.UNKNOWN


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: python3 typestate_check.py <source.c> "
            "[source.c ...]"
        )
        return 2

    results = [check_file(path) for path in sys.argv[1:]]

    if AnalysisStatus.VIOLATION in results:
        return 1

    if AnalysisStatus.UNKNOWN in results:
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
