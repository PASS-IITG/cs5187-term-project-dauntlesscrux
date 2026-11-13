# Pre-submission checklist

Updated 2026-11-13 after the citation, CCS, disclosure, and LaTeX-source pass.
Run `make clean && make` followed by `make check` from this directory.

## Content and authorship
- [x] Author Contributions section is populated with named, task-level roles
      and joint work. Both authors must confirm that the allocation is true
      before submission.
- [x] The active `\todo{...}` and unmeasured `\num{...}` placeholders in
      the paper sources compiled by `main.tex` have been removed.
- [x] The optional, currently excluded pilot and implementation files no
      longer contain active TODO placeholders; their comments explain why
      they are not part of this paper build.
- [ ] Both authors must independently review the source-level classifications,
      reachability arguments, and historical commit examples initially
      generated with AI assistance. The disclosure intentionally does not
      claim that this human second review has already happened.
- [ ] Both authors must confirm that the AI-use disclosure accurately records
      the tools and assistance used during the project.

## Citations and ACM classification
- [x] Added the foundational typestate citation: Strom and Yemini (1986),
      DOI `10.1109/TSE.1986.6312929`.
- [x] Added NVD references for CVE-2022-4450, CVE-2023-0215, and
      CVE-2024-4741.
- [x] Added and checked the cited related-work records for VulPA, recurring
      vulnerability detection, similar-but-patched code, vulnerability-
      introducing commit identification, and Mystique.
- [x] Replaced the incorrect ACM CCS concept identifiers with the taxonomy
      paths for Automated static analysis and Software and application
      security. Confirm the chosen concepts still match the final paper scope.
- [x] The bibliography entries used by the paper are cited and the BibTeX
      build completes in the current build environment.

## Build and presentation
- [x] `pdflatex`/BibTeX build completes in the current environment.
- [x] Rendered PDF pages inspected for layout. The RQ2 comparison table was
      corrected after the first render exposed a clipped, over-wide header;
      long source paths in the AI disclosure were also made breakable.
- [ ] Page limit: `paper.conf` sets `PAGE_LIMIT=12`; the current build has
      15 pages and the references begin on page 15. The main text therefore
      exceeds the configured limit and needs an author-approved reduction.
- [x] No overfull horizontal boxes remain in the final LaTeX log.
- [x] `pdffonts` confirms that all fonts listed in the current PDF are embedded.
- [ ] Check grayscale legibility and confirm the final PDF after page reduction.
- [ ] Confirm the Overleaf project and final submission PDF are up to date.

## Scope and claims
- [x] The paper reports zero confirmed new vulnerabilities and does not
      present candidate findings as confirmed bugs.
- [x] Protocol A's whole-tree false-positive result and limitations are
      described rather than omitted.
- [ ] Before submission, confirm every contribution statement and every
      experiment/result description with the project records and both authors.
