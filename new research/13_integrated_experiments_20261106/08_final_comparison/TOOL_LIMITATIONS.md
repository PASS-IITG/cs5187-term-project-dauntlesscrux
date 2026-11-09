# Tool comparison limitations

- The four-tool matrix uses the required result vocabulary and corrected source revisions. It is a descriptive comparison of three selected CVEs only.
- Python rules are source-pattern checks; they identify the first two mechanisms but the CVE-2024 rule fires on both the vulnerable parent and official fixed commit.
- Clang's default static analyzer and the annotation overlay operate on selected translation units. The overlay models allocator/deallocator ownership, not BIO chain membership or SSL record-layer state as a complete protocol.
- The five frozen Coccinelle rules are generic syntactic/event rules; event matches do not entail defect findings. They did not express the specific logic that prevents the selected failures.
- Cppcheck diagnostics are largely style/performance/portability findings. Corrected CVE-2024 scan covered `ssl/ssl_lib.c` on both sides; it did not cover the other related TUs for this corrected pair. Matrix result concerns the completed file only.
- CodeQL and Infer are NOT_EVALUABLE. Their absence is not a negative detection.
- ASan is runtime evidence for fixed harness inputs and configurations. Lack of report on one fixed input does not prove absence of other paths.
- No independent test population or statistical performance estimate exists.
