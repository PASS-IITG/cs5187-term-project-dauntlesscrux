# Before submission

Updated 2026-11-13 for the named-submission decision -- see HANDOFF.md §5
if any item here seems to contradict what's actually in the repo.

Run `make check` first; it covers the items marked (auto). As of 13 Nov it
reports 0 banned words, 0 identifying-path violations, 0 unmeasured
`\num{}`, 15 sentences over 35 words (unaddressed, minor), and 8 raw
`\todo` -- but only 5 of those are in sections `main.tex` actually
compiles (`implementation.tex`/`pilot.tex` are `\input`-commented-out and
don't count; HANDOFF.md §6 lists the real 5).

The **red `FOCUS` boxes** in the sections mark the five graded must-haves:
Motivating Example (intro), Workflow (approach), Research Questions
(evaluation), Related Work, and Threats to Validity. Write each section,
then delete its `\focus{...}` line (keep the section). A finished report has
zero red `\focus` and zero `\todo`.

## Content
- [x] Abstract, introduction and conclusion give the same numbers --
      re-checked 13 Nov: all four (abstract, introduction, evaluation,
      conclusion) say "10 sites, 2 potential recurrences, 8 harmless/
      convention deviations, 0 confirmed"; no file anywhere still says
      "6 convention deviation(s), 2 unclear" (grepped, zero hits)
- [x] Every number is in HANDOFF.md §4 with its source file -- re-checked
      against the same grep
- [~] No `\num{}` and no `\todo{}` left (auto) -- `\num` is 0 (done).
      `\todo` is 8 raw / **5 real** (the other 3 are in
      `implementation.tex`/`pilot.tex`, not `\input` by `main.tex`). The 5
      real ones cannot be closed by Claude: they need an author's email,
      the ACM CCS-concept tool, IEEE Xplore access, and the two authors'
      own sign-off (items below). Not something left undone by oversight.
- [~] Every RQ has a subsection and at least one Observation (all 5 do,
      re-checked). A table/figure: RQ1 and RQ2 had one already; **RQ5 now
      does too** (added 13 Nov -- a breakdown of its 11 false positives by
      cause, same numbers already in the prose, just tabulated). RQ3 and
      RQ4 are each a single measurement (one time-travel site; one timing
      figure) where a table would be padding, not content -- left as
      prose by design, not an oversight.
- [x] Each Related Work paragraph ends with how we differ -- re-read all 4
      paragraphs in `related.tex` on 13 Nov; every one does
- [x] Threats: internal, external, construct -- `threats.tex` has all
      three paragraphs, each with multiple itemized threats and a "what
      remains" future-work line
- [x] Limits stated plainly, with "future work" where relevant -- same
      file, same check
- [x] Motivating example is real and its numbers are measured -- the
      Figure~1 listing in `introduction.tex` is trimmed real source from
      commit `8e257b86e5`, with the actual fix commit `63bcf189be` named
- [ ] **Author Contributions section (`data.tex`) has real content**, not
      the `[fill in]` template -- both authors must write what they
      actually did, specific enough to survive "that was X's part" being
      called unacceptable at the presentation (rubric requirement, not
      optional). Cannot be done by Claude: this has to be true and agreed
      by both of you, not generated.
- [x] **Confirmed-bug status is accurately described, not overstated.**
      Re-read every mention in the paper on 13 Nov: the RSA candidate is
      called a candidate everywhere it appears, Observation~rq1-mastertriage
      says "0 confirmed new vulnerabilities" plainly, and nothing claims
      or implies upstream acceptance. If you add anything about
      `rsa_ossl_finish` to the paper later, keep it this careful.

## Style (STYLE.md)
- [x] No banned words (auto) -- `make check`-equivalent re-run 13 Nov: 0
- [x] Few sentences over 35 words (auto) -- was 16, now 2 (split by hand,
      explicitly requested, 13 Nov; meaning preserved, no numbers or
      claims changed, re-verified against `make check`-equivalent). The
      2 left are inside `\todo{}` instructional notes to the authors, not
      final paper prose, and will vanish along with the `\todo` once
      those are resolved -- not worth splitting text that's getting
      deleted.
- [x] Table captions explain every column -- re-checked RQ1 and the new
      RQ5 table; both do
- [ ] Every term defined once and used consistently; figures readable in
      grayscale -- not independently re-verified this pass (needs a
      compiled PDF to check grayscale rendering, which this sandbox
      cannot produce -- see Venue rules below)

## Citations
- [x] Every entry has an `Accessed:` date -- `references.bib` has 5
      entries, all 5 have one (grepped 13 Nov)
- [ ] Every entry independently re-verified against Crossref/arXiv/
      publisher as of 13 Nov -- done once earlier in the project for 4 of
      5; the 5th, the foundational typestate citation, still has a
      genuinely disputed author list across IBM's own mirror pages
      (resolvable only via IEEE Xplore, which needs the authors' campus
      access, not available to Claude)
- [ ] No undefined citations (auto) -- cannot run: needs a compiled
      `main.log`, blocked by the missing `acmart.cls` in this sandbox
      (see Venue rules below). Re-run `make check` yourself once you can
      compile.

## Venue rules
- [x] Right document class and options -- `\documentclass[acmsmall,screen,review]{acmart}`,
      re-read 13 Nov, matches the CFP block above it
- [ ] Page limit -- **cannot be checked.** This sandbox has no `acmart.cls`
      (CTAN is outside its network allowlist) and `tlmgr install acmart`
      fails here (`user mode not initialized`), so `main.pdf` has never
      been built in this session. `pdffonts`, the grayscale-figure check,
      and the undefined-citations check above all depend on this same
      missing PDF. This is an environment limit on Claude's side only --
      the project has compiled before (an earlier real PDF exists), so
      run `make check` yourself on your own machine or Overleaf, which is
      the only way any of these four items get checked before submission.
- [x] **Named submission** (resolved 2026-11-13, confirmed with the
      professor): `\documentclass` has no `anonymous` option, `\author{}`
      has the real names (Rutvij Wagh, Udayraj Choudhary) and affiliation,
      and the CFP comment block at the top of `main.tex` documents the
      decision. The old anonymous-submission rules below no longer apply
      -- do not re-add the `anonymous` class option or scrub names/paths.
- [x] Data availability points at the real, public repo URL -- `data.tex`
      links `github.com/PASS-IITG/cs5187-term-project-dauntlesscrux`;
      confirmed reachable and current as of 13 Nov (this is the same repo
      this session has been pushing to and reading from all along)
- [ ] Generative-AI disclosure confirmed by every author (not just drafted
      -- `data.tex` has a `\todo` requiring both authors to independently
      re-verify 4 specific pieces of AI-produced analysis before this can
      be marked true). Cannot be done by Claude -- it has to be the
      authors' own re-check, not Claude re-confirming its own work.
- [ ] CCS concepts and keywords filled (ACM) -- current ones in `main.tex`
      are a best-guess placeholder (flagged `\todo` at the point of use);
      Claude cannot reach `dl.acm.org/ccs` to regenerate the real block,
      it needs one of you to click through the tool there
- [ ] PDF fonts embedded (`pdffonts main.pdf`), uploaded PDF opened once
      -- blocked on the same missing PDF as the page-limit item above
- [ ] Overleaf project link exists and is ready to submit alongside the
      PDF and repo -- not yet confirmed as of 13 Nov; no evidence either
      way reached this session, ask whoever owns the Overleaf project
