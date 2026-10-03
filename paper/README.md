# Paper

Manuscript: *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
(Ramazan Kocaoğlu, Basma Bakırcı), submitted to PeerJ Computer Science as an AI
Application article.

| Path | What it is |
|---|---|
| [`PeerJ_Manuscript.pdf`](PeerJ_Manuscript.pdf) | The compiled manuscript (32 pages, peer-review layout with line numbers), PeerJ compliance revision of 2026-10-03: Data Availability now cites the v1.0.0 release and its DOI, §4.1 states the data provenance, and the generative-AI declaration is complete. The version as originally submitted is preserved unchanged in release v1.0.0. Start here to read the paper. |
| [`latex/main.tex`](latex/main.tex) | Full LaTeX source of the manuscript. |
| [`latex/references.bib`](latex/references.bib) | Bibliography (BibTeX). |
| [`latex/wlpeerj.cls`](latex/wlpeerj.cls) | PeerJ's LaTeX class file, from PeerJ's official template. |
| [`latex/figures/`](latex/figures/) | Figures 1–7 as vector PDF (`Figure_1.pdf` … `Figure_7.pdf`). |
| [`latex/tables/`](latex/tables/) | Tables 1–19 as LaTeX (`Table_1.tex` … `Table_19.tex`), pulled in by `main.tex` via `\input`. |

## Building the PDF from source

A TeX distribution with `latexmk`, `pdflatex` and `bibtex` is required.

```bash
cd paper/latex
latexmk -pdf main.tex
```

This writes `paper/latex/main.pdf` (git-ignored, along with the intermediate build
files). `PeerJ_Manuscript.pdf` in this directory is built from this source; the originally submitted version is in release v1.0.0.

## Where the numbers in the paper come from

| Manuscript item | Source in this repository |
|---|---|
| Tables 2–7, Figure 1 (Section 4) | Scripts in [`../reproducibility/analysis/`](../reproducibility/analysis/); published values in [`../reproducibility/aggregate_data/`](../reproducibility/aggregate_data/) |
| Figures 1, 6, 7 plotted points | [`../reproducibility/figure_data/`](../reproducibility/figure_data/) |
| Table 1 | Qualitative positioning table; no code |
| Tables 8–19, Figures 2–5 (Sections 5–9) | Measured on the deployed production service, which is not part of this repository — see [`../CODE_AVAILABILITY.md`](../CODE_AVAILABILITY.md) |
