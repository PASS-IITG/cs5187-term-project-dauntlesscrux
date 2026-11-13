// Heuristic: release followed by member dereference in one function.
// No path-sensitive alias, branch, or lifetime reasoning is performed.
@uaf@
identifier fn, p, fld;
position prelease, puse;
@@
fn(...) {
...
(
OPENSSL_free@prelease(p);
|
BN_free@prelease(p);
|
BIO_free@prelease(p);
|
BIO_free_all@prelease(p);
|
EVP_MD_CTX_free@prelease(p);
|
EVP_CIPHER_CTX_free@prelease(p);
|
X509_free@prelease(p);
)
...
p->fld@puse
...
}

@script:python@
prelease << uaf.prelease;
puse << uaf.puse;
fn << uaf.fn;
p << uaf.p;
@@
for i in range(len(prelease)):
    coccilib.report.print_report(prelease[i], "possible use-after-release of %s in %s; later member access at line %s" % (p, fn, puse[i].line))
