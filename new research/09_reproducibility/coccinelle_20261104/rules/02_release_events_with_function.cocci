// Event context variant: bind the containing function. The inner form catches
// interior sites; head/tail/only forms cover sites at ellipsis boundaries.
@mid@
identifier fn, p;
identifier rel =~ ".*free.*";
position site;
@@
fn(...) {
...
rel@site(p);
...
}
@script:python@
fn << mid.fn; p << mid.p; rel << mid.rel; site << mid.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "release_event|%s|%s|%s" % (fn, rel, p))

@head@
identifier fn, p;
identifier rel =~ ".*free.*";
position site;
@@
fn(...) {
rel@site(p);
...
}
@script:python@
fn << head.fn; p << head.p; rel << head.rel; site << head.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "release_event|%s|%s|%s" % (fn, rel, p))

@tail@
identifier fn, p;
identifier rel =~ ".*free.*";
position site;
@@
fn(...) {
...
rel@site(p);
}
@script:python@
fn << tail.fn; p << tail.p; rel << tail.rel; site << tail.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "release_event|%s|%s|%s" % (fn, rel, p))

@only@
identifier fn, p;
identifier rel =~ ".*free.*";
position site;
@@
fn(...) {
rel@site(p);
}
@script:python@
fn << only.fn; p << only.p; rel << only.rel; site << only.site;
@@
for loc in site:
    coccilib.report.print_report(loc, "release_event|%s|%s|%s" % (fn, rel, p))
