main.pdf: main.tex macros.tex references.bib sections/*.tex figures/*.tex
	pdflatex -interaction=nonstopmode -halt-on-error main
	bibtex main
	pdflatex -interaction=nonstopmode -halt-on-error main
	pdflatex -interaction=nonstopmode -halt-on-error main

check: main.pdf
	sh scripts/check.sh

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc main.pdf

.PHONY: clean check
