// Enumerate every assignment of OPENSSL_malloc to an identifier. Pair with
// 04b return events by parsed C function range and line order.
@alloc_event@
identifier p;
position site;
@@
p = OPENSSL_malloc@site(...);

@script:python@
p << alloc_event.p;
site << alloc_event.site;
@@
for i in range(len(site)):
    coccilib.report.print_report(site[i], "alloc_event|%s" % p)
