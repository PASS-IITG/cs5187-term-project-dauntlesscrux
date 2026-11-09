# Optimized Rule 02 and Rule 04 event extraction

Pinned source: `ed57129cd43b77e077c68fd5f7ea951976766f38`; Coccinelle 1.1.1. Original rules remain in `../rules/02_repeated_release.cocci` and `../rules/04_acquire_early_return.cocci`; optimized rules are separate.

## Diagnosis

Both original rules relate two sites using unbounded `...` regions in one function. Rule 02 also ranges over a regex-constrained arbitrary `*free*` callee and reports possible call pairs. Rule 04 relates every `OPENSSL_malloc` assignment to later returns, multiplying allocation/return matches per function. Full scans on 430/332 filtered files did not complete, while single-file original checks exited before 30-second timeouts. This indicates aggregate match/parse volume and site-pair growth, rather than a single universally pathological input file. `spatch --help` confirms `--jobs`, `--timeout`, `--profile`, `--profile-per-file`, `--use-cache`, and `--cache-prefix`; full optimized scans use parallel batches rather than a broad two-site Coccinelle cross product.

## Optimized Rule 02

`02_repeated_release_events.cocci` enumerates each direct one-argument call to a function whose name contains `free`, with no before/after ellipses. A source function-range postprocessor groups by source file, containing function, callee and pointer identifier; a candidate requires at least two distinct call lines. The scan covers all 1,695 tracked C files, including files outside the first 430-file lexical prefilter. This preserves the intended same-function/same-callee/same-identifier coverage and also finds additional eligible files when the old prefilter's function inference missed them. The extractor itself is deliberately an event collector: branch exclusivity, pointer reassignment, reference counts and reacquisition remain review work.

## Optimized Rule 04

`04a_alloc_events.cocci` extracts each assignment `p = OPENSSL_malloc(...)`; `04b_return_events.cocci` extracts returns. The postprocessor joins by source file/function and keeps explicit source return lines later than the allocation. Both passes cover all 1,695 tracked C files. The raw return output contained 44,510 locations, of which 903 reported source positions did not contain a literal `return` token (e.g. implicit/end-position or macro-position events); those are retained in `raw_events_04b_nonliteral_position.csv` (also preserved under the earlier name `raw_events_04b_synthetic_or_unmapped.csv`) and excluded from explicit-return pairing. The sample `unreachable_alloc` control exposed this issue: a closing-brace position must not be treated as an explicit later return. Filtering it leaves the full 288 candidate set unchanged.

## Mapping and coverage checks

The lexical function mapper leaves some macro-expanded/conditional source positions unresolved. Raw events are preserved. Rule 02 had 43 unresolved release events across six files; the original repeated-release SmPL was run on those six files and exited 0 with no candidates. Rule 04 had 265 unresolved return events across 31 files; the function-context fallback was run on those files. Only three mapped allocation events were in those affected files, and all already had later explicit returns in their mapped functions; no allocation/function pair was found by the contextual cross-check that was absent from the final inventory. The original Rule 04 was also run on the two allocation-bearing files, and its two emitted matches are present in the optimized inventory. These checks address candidate-set completeness while keeping unresolved event rows visible.

## Sample tests

`optimized/samples/resource_events.c` covers sequential repeated release (positive), mutually exclusive releases (expected heuristic false positive), one release only (negative), free/reacquire/free (heuristic candidate), allocation then early return, returned ownership, and an allocation after the only return (negative after explicit-return filtering). Each rule passed Coccinelle parsing on the sample; stdout/stderr are in `optimized/logs/sample_validation/`. The old two-site rules remain sample-tested in the original `samples/` and logs.

## Limits

Neither optimized rule proves path feasibility. Rule 02 still intentionally overmatches mutually exclusive branches and pointer reuse. Function mapping depends on lexical C-body parsing plus targeted Coccinelle context checks; unresolved raw events are not discarded. Rule 04 is a coarse same-function/same-pointer-free-agnostic allocation-to-return heuristic and will flag allocation failure checks, cleanup paths, ownership transfer and valid return values. Coccinelle and postprocessing do not establish a security impact.
