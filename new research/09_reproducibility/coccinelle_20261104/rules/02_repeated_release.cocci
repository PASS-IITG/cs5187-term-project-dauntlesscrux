// Heuristic: the same identifier is passed to two one-argument calls whose
// function name contains "free" in one function. The rule cannot determine
// whether calls are mutually exclusive or whether a reference was reacquired.
@double_release@
identifier fn, p;
identifier rel =~ ".*free.*";
position pfirst, psecond;
@@
fn(...) {
...
rel@pfirst(p);
...
rel@psecond(p);
...
}

@script:python@
pfirst << double_release.pfirst;
psecond << double_release.psecond;
fn << double_release.fn;
p << double_release.p;
rel << double_release.rel;
@@
for i in range(len(pfirst)):
    coccilib.report.print_report(pfirst[i], "possible repeated %s release of %s in %s; another call at line %s" % (rel, p, fn, psecond[i].line))
