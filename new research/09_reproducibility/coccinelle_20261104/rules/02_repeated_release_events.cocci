// Enumerate every direct one-argument call to a function whose name contains
// "free". Pairing is performed by a postprocessor using parsed C function
// ranges. This avoids the pair of unbounded SmPL ellipses in original Rule 02.
@release_event@
identifier p;
identifier rel =~ ".*free.*";
position site;
@@
rel@site(p);

@script:python@
p << release_event.p;
rel << release_event.rel;
site << release_event.site;
@@
for i in range(len(site)):
    coccilib.report.print_report(site[i], "release_event|%s|%s" % (rel, p))
