# Evaluation Protocol and Interpretation

## Available benchmark

The Version 2 script `typestate_checker_eval_v2.py` includes 16 labelled hand-written code snippets:

- 3 vulnerable-case positive snippets (one for each selected CVE),
- 3 fixed-case negative snippets,
- 8 safe-control snippets,
- 2 non-typestate control snippets.

The recorded output has **TP=3, TN=13, FP=0, FN=0** for this suite. The corresponding in-suite metrics are precision 100%, recall 100%, specificity 100%, and F1 100%.

## What these numbers mean

They mean that the harness's current string-based logic matched the expected labels in this small set of designed snippets. They do not show general accuracy across a full OpenSSL checkout, other C code, or unknown recurring bugs.

## Why the suite is not independent evidence of generalization

1. Snippets are hand-written to express the intended patterns rather than mined as an independent blind test set.
2. The evaluation's matching implementation uses literal string-presence checks.
3. Some snippets simplify the actual OpenSSL source and omit aliases, branch conditions, macros, and interprocedural ownership transfers.
4. The `TS-PEM-02` helper in this harness checks whether at least one of `*header = NULL`, `*data = NULL`, or `*ptr = NULL` is present; that can miss a case where only one of the two required output pointers is reset. This is a known coverage gap in the benchmark helper and must be fixed before relying on the harness as a faithful implementation of the written rule.
5. The `TS-SSL-03` snippet check is an approximation focused on buffer free and packet reset; the official issue also depends on whether record-layer data still requires the buffer.

## Recommended evaluation improvements

- Fix the PEM benchmark predicate so both output pointers must be reset in the right cleanup path.
- Add adversarial cases: conditional reset, one pointer reset but not the other, a pop on a different BIO, safe standalone BIO free, comments containing pattern names, macros, helper calls, different variable names, and state-dependent SSL release guards.
- Test on source files read from exact pinned vulnerable/fixed worktrees rather than relying only on hand-written snippets.
- Build an independently labeled set of safe and vulnerable candidate locations.
- Report false positives and false negatives after manual ground-truth review.
- Keep runtime testing distinct from static source-pattern testing.

## Raw files

- `typestate_checker_eval_v2.py`: evaluation helper script.
- `eval_v2_stdout.log`: saved output from the recorded run.

Re-run the script in the final repository before presenting metrics and preserve the new stdout log.
