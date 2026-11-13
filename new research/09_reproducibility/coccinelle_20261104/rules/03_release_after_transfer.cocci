// Heuristic: a BIO explicitly transferred to an SSL object is then freed by
// the same function. SSL_set0_* transfers ownership; direct BIO_free after it
// may invalidate the SSL-owned BIO. Reference counts and reassignment are not
// modeled.
@bio_transfer_then_free@
identifier fn, ssl, p;
position ptransfer, pfree;
@@
fn(...) {
...
(
SSL_set0_rbio@ptransfer(ssl, p);
...
BIO_free@pfree(p);
|
SSL_set0_wbio@ptransfer(ssl, p);
...
BIO_free@pfree(p);
)
...
}

@script:python@
ptransfer << bio_transfer_then_free.ptransfer;
pfree << bio_transfer_then_free.pfree;
fn << bio_transfer_then_free.fn;
p << bio_transfer_then_free.p;
@@
for i in range(len(ptransfer)):
    coccilib.report.print_report(ptransfer[i], "possible BIO free after SSL ownership transfer of %s in %s; free at line %s" % (p, fn, pfree[i].line))
