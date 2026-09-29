# Learning-Assisted Exposure Assessment at Estate Scale

Manuscript and public reproducibility material for

> **Learning-Assisted Exposure Assessment at Estate Scale: Constraint Recovery,
> Inventory Redundancy, and Engine Placement in Managed Enterprise Networks**
> Ramazan Kocaoğlu, Basma Bakırcı — Department of Computer Engineering, Ostim
> Technical University, Ankara, Turkey
> Submitted to *PeerJ Computer Science* (article type: AI Application).

## Quick links

| I want to… | Go to |
|---|---|
| Read the paper | [`paper/PeerJ_Manuscript.pdf`](paper/PeerJ_Manuscript.pdf) |
| See or build the LaTeX source | [`paper/latex/main.tex`](paper/latex/main.tex) · [build instructions](paper/README.md) |
| Look at the figures / tables | [`paper/latex/figures/`](paper/latex/figures/) · [`paper/latex/tables/`](paper/latex/tables/) |
| Read or run the analysis code | [`reproducibility/analysis/`](reproducibility/analysis/) · [usage](reproducibility/README.md) |
| Check the published numbers | [`reproducibility/aggregate_data/`](reproducibility/aggregate_data/) · [`reproducibility/figure_data/`](reproducibility/figure_data/) |
| Know what is and is not released, and why | [`CODE_AVAILABILITY.md`](CODE_AVAILABILITY.md) · [`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md) |
| Cite this work | [`CITATION.cff`](CITATION.cff) |

## Repository layout

```
.
├── README.md                  ← this file
├── CODE_AVAILABILITY.md       ← which code is public, which is not, and why
├── DATA_AVAILABILITY.md       ← which data is public, which is not, and why
├── CITATION.cff               ← citation metadata
├── LICENSE                    ← MIT (code and aggregate data)
│
├── paper/
│   ├── README.md              ← guide to the paper files, build instructions
│   ├── PeerJ_Manuscript.pdf   ← compiled manuscript (as submitted)
│   └── latex/
│       ├── main.tex           ← manuscript source
│       ├── references.bib     ← bibliography
│       ├── wlpeerj.cls        ← PeerJ LaTeX class
│       ├── figures/           ← Figure_1.pdf … Figure_7.pdf
│       └── tables/            ← Table_1.tex … Table_19.tex
│
└── reproducibility/
    ├── README.md              ← full description, usage, requirements
    ├── analysis/              ← Python analysis scripts (Section 4)
    ├── aggregate_data/        ← published values of Tables 2–7 as CSV
    ├── figure_data/           ← plotted points of Figures 1, 6, 7 as CSV
    ├── example_data/          ← small synthetic export for a smoke test
    ├── docs/reproduction.md   ← step-by-step reproduction walkthrough
    └── environment/           ← requirements.txt
```

## Code ↔ paper map

| Script | Reproduces | Manuscript section |
|---|---|---|
| [`common.py`](reproducibility/analysis/common.py) | Shared export reader and the row-level reduction; imported by the other three | §4.1 |
| [`estate_structure.py`](reproducibility/analysis/estate_structure.py) | Tables 2–5, Figure 1 | §4.2–§4.5 |
| [`lexical_features.py`](reproducibility/analysis/lexical_features.py) | Table 6 | §4.6 |
| [`cpe_route.py`](reproducibility/analysis/cpe_route.py) | Table 7 | §4.7 |

## Quick start

Python 3.10 or later. The scripts use only the standard library for `.csv` input;
`openpyxl` is needed only for `.xlsx` input.

```bash
git clone https://github.com/RakortAcademy/PeerjNetworkPaper.git
cd PeerjNetworkPaper/reproducibility
pip install -r environment/requirements.txt

# smoke test on the shipped synthetic export
python3 analysis/estate_structure.py --dir example_data --out out/
python3 analysis/lexical_features.py --dir example_data --out out/
```

To reproduce the Section 4 analysis on real data, point `--dir` at a directory of
your own NAC installed-application exports. Table 7 (`cpe_route.py`) additionally
needs the public NIST CPE dictionary. Details:
[`reproducibility/README.md`](reproducibility/README.md) and
[`reproducibility/docs/reproduction.md`](reproducibility/docs/reproduction.md).

## Scope of this release

**Included:** the manuscript (PDF and LaTeX source), the analysis scripts behind the
Section 4 estate-structure measurement study, the derived non-identifying aggregate
statistics those scripts produced on the eight study estates, the plotted datapoints
of Figures 1, 6 and 7, and a synthetic example input.

**Not included:** the raw customer inventory exports (confidential third-party data),
and the production assessment service described in Sections 5–9 of the manuscript —
the learned tagger and its weights, the decision engine, and the service tier — which
is a proprietary system. The Section 8–9 performance results were measured on that
deployed system and cannot be regenerated from this repository. The full accounting
is in [`CODE_AVAILABILITY.md`](CODE_AVAILABILITY.md) and
[`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md).

## License

The analysis scripts, documentation, and aggregate/figure CSV data are released under
the MIT License — see [`LICENSE`](LICENSE). The manuscript text and figures under
`paper/` are the authors' under-review submission and are not covered by the MIT
License. `paper/latex/wlpeerj.cls` is the class file from PeerJ's Overleaf template
and is included unmodified, only so that the source builds.

## Contact

Corresponding author: Ramazan Kocaoğlu — ramazan.kocaoglu@ostimteknik.edu.tr
