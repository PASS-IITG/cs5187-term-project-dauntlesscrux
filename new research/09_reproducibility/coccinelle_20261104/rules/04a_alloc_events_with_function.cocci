@mid@
identifier fn, p;
position site;
@@
fn(...) {
...
p = OPENSSL_malloc@site(...);
...
}
@script:python@
fn << mid.fn; p << mid.p; site << mid.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "alloc_event|%s|%s" % (fn, p))

@head@
identifier fn, p;
position site;
@@
fn(...) {
p = OPENSSL_malloc@site(...);
...
}
@script:python@
fn << head.fn; p << head.p; site << head.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "alloc_event|%s|%s" % (fn, p))

@tail@
identifier fn, p;
position site;
@@
fn(...) {
...
p = OPENSSL_malloc@site(...);
}
@script:python@
fn << tail.fn; p << tail.p; site << tail.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "alloc_event|%s|%s" % (fn, p))

@only@
identifier fn, p;
position site;
@@
fn(...) {
p = OPENSSL_malloc@site(...);
}
@script:python@
fn << only.fn; p << only.p; site << only.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "alloc_event|%s|%s" % (fn, p))
