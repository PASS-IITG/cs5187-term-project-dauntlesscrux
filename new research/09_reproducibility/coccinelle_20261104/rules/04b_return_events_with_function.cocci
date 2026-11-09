@mid@
identifier fn;
position site;
@@
fn(...) {
...
return@site ...;
...
}
@script:python@
fn << mid.fn; site << mid.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "return_event|%s" % fn)

@head@
identifier fn;
position site;
@@
fn(...) {
return@site ...;
...
}
@script:python@
fn << head.fn; site << head.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "return_event|%s" % fn)

@tail@
identifier fn;
position site;
@@
fn(...) {
...
return@site ...;
}
@script:python@
fn << tail.fn; site << tail.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "return_event|%s" % fn)

@only@
identifier fn;
position site;
@@
fn(...) {
return@site ...;
}
@script:python@
fn << only.fn; site << only.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "return_event|%s" % fn)
