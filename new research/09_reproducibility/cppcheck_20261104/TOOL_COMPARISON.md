# Descriptive analyzer comparison

This table is an exact-location inventory comparison only; the tools use different rule sets, configurations, and source scopes. It is not an evaluation set and supports no precision/recall/accuracy or superiority conclusion.

| Relationship | Cppcheck deduplicated rows |
|---|---:|
| Exact source file + line also in Clang inventory | 233 |
| Exact source file + line also in Coccinelle inventory | 1 |
| Exact location in both Clang and Coccinelle | 0 |
| Exact location unique to Cppcheck among these three inventories | 6572 |
| Same file and function as a historical fix-register row | 6 |

The historical comparison is file+function (not line) and is a retrospective cross-reference, not evidence that Cppcheck independently discovered a defect. The three known-CVE regression targets are enumerated separately in `known_cve_scope_crosswalk.csv`; Cppcheck has no exact file+function match to those targets in this whole-tree inventory. This does not establish that the tool cannot detect those CVEs; the present pinned source is the reviewed revision, not the vulnerable/fixed revision-pair experiment, and no CVE-specific matching was used.

Cppcheck's refined source domains include production library/provider, application, optional demo, tests, fuzz, and documentation/examples. Clang and Coccinelle inventories have their own analysis scopes and candidate semantics. See their respective research directories before drawing any comparison.
