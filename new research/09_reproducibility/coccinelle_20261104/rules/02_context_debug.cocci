@r@
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
fn << r.fn;
p << r.p;
rel << r.rel;
site << r.site;
@@
for i in range(len(site)):
 coccilib.report.print_report(site[i], "%s|%s|%s" % (fn,rel,p))
