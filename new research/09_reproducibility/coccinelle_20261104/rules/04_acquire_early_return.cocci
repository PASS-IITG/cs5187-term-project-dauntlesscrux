// Heuristic: OPENSSL_malloc assigned to a pointer and a later return in the
// same function. This flags candidate returns for ownership/error-path review;
// it does not prove cleanup is missing. Null-return paths, cleanup elsewhere,
// ownership transfer, or caller-owned results are common false positives.
@acquire_return@
identifier fn, p;
position palloc, pret;
@@
fn(...) {
...
p = OPENSSL_malloc@palloc(...);
...
return@pret ...;
...
}

@script:python@
palloc << acquire_return.palloc;
pret << acquire_return.pret;
fn << acquire_return.fn;
p << acquire_return.p;
@@
for i in range(len(palloc)):
    coccilib.report.print_report(palloc[i], "allocation assigned to %s in %s precedes a return at line %s; review cleanup/ownership" % (p, fn, pret[i].line))
