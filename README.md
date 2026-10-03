# Learning-Assisted Exposure Assessment at Estate Scale — public reproducibility package

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23122101.svg)](https://doi.org/10.5281/zenodo.23122101)

## Description

Manuscript, analysis code and derived data for the estate-structure measurement
study in

> **Learning-Assisted Exposure Assessment at Estate Scale: Constraint Recovery,
> Inventory Redundancy, and Engine Placement in Managed Enterprise Networks**
> Ramazan Kocaoğlu, Basma Bakırcı — Department of Computer Engineering, Ostim
> Technical University, Ankara, Turkey.
> Submitted to *PeerJ Computer Science* (article type: AI Application).

The repository contains **only** material the authors have the right to release:
the manuscript source, the four Python scripts behind the Section 4 measurement
study (Tables 2–7, Figure 1), the derived non-identifying aggregate statistics
those scripts produced on the eight study estates, the plotted datapoints of
Figures 1, 6 and 7, a synthetic example input, a figure-regeneration script and a
release-verification script. It does **not** contain any customer inventory, and it
does not contain the production assessment service described in Sections 5–9 of
the manuscript (see [Restricted Components](#restricted-components)).

## Associated Publication

| Item | Location |
|---|---|
| Compiled manuscript (PeerJ compliance revision of 2026-10-03; the version as originally submitted is preserved in release v1.0.0) | [`paper/PeerJ_Manuscript.pdf`](paper/PeerJ_Manuscript.pdf) |
| LaTeX source, figures, tables | [`paper/latex/`](paper/latex/) · [build notes](paper/README.md) |
| Journal | PeerJ Computer Science, under review; article DOI not yet assigned |
| Source repository | https://github.com/RakortAcademy/PeerjNetworkPaper |
| Archived software release | v1.0.0 (commit `b51f048`), https://github.com/RakortAcademy/PeerjNetworkPaper/releases/tag/v1.0.0 |
| Zenodo record | https://zenodo.org/records/23122101 |
| Software DOI | 10.5281/zenodo.23122101 — https://doi.org/10.5281/zenodo.23122101 |
| Corresponding author | Ramazan Kocaoğlu — ramazan.kocaoglu@ostimteknik.edu.tr |

## Repository Scope

Two levels of reproduction are distinguished throughout this repository:

- **Public reproduction** — what anyone can run from this repository alone:
  the scripts on the shipped synthetic input, Figures 1 and 6 from the released
  datapoints, and the arithmetic consistency of the released tables.
  `reproducibility/verify_release.py` runs all of it.
- **Operator reproduction** — re-running the analysis on a platform-native NAC
  installed-application export. The eight study exports are confidential
  third-party data and are not released, so the manuscript's own per-estate
  numbers can be regenerated only by an authorised operator holding them. On
  any other operator's export the scripts produce *that* estate's structure.

Nothing in Sections 5–9 of the manuscript (service architecture, planning,
transport, performance and scaling results; Tables 8–19, Figures 2–7) is produced by
code in this repository. Those results were measured on a deployed proprietary
system. The plotted values of Figures 6 and 7 are released as CSV so the figures can
be checked against the text; they are not regenerated from source.

```
.
├── README.md                     ← this file
├── CODE_AVAILABILITY.md          ← component-level public/restricted matrix for code
├── DATA_AVAILABILITY.md          ← public / restricted / not-included matrix for data
├── CITATION.cff · LICENSE (MIT) · RELEASE_NOTES.md
├── paper/                        ← manuscript PDF + LaTeX source (figures/, tables/)
└── reproducibility/
    ├── README.md                 ← package-level README (same section structure)
    ├── analysis/                 ← common.py, estate_structure.py, lexical_features.py, cpe_route.py
    ├── aggregate_data/           ← released values of Tables 2–7 (CSV)
    ├── figure_data/              ← released datapoints of Figures 1, 6, 7 (CSV)
    ├── example_data/             ← synthetic estate export; synthetic CPE dictionary + corpus (cpe/)
    ├── reproduce_figures.py      ← Figures 1 and 6 from figure_data/ (public reproduction)
    ├── verify_release.py         ← release checks: files, schema, consistency, smoke test, figures
    ├── environment/requirements.txt
    └── docs/                     ← reproduction.md (walkthrough), release_checklist.md
```

## Dataset Information

**Released (public).**

| Path | Content | Produced by |
|---|---|---|
| `reproducibility/aggregate_data/table2_version_coverage.csv` | Table 2, per estate + pooled | `estate_structure.py` |
| `reproducibility/aggregate_data/estate_structure.csv` | Table 3 (R, U, G, ρ_item, ρ_group, reduction) | `estate_structure.py` |
| `reproducibility/aggregate_data/table4_version_spread.csv` | Table 4 | `estate_structure.py` |
| `reproducibility/aggregate_data/table5_fanout_distribution.csv` | Table 5 | `estate_structure.py` |
| `reproducibility/aggregate_data/table6_lexical_features.csv` | Table 6 | `lexical_features.py` |
| `reproducibility/aggregate_data/table7_cpe_route.csv` | Table 7 | `cpe_route.py` + official CPE dictionary |
| `reproducibility/figure_data/figure1_fanout.csv` | Figure 1 curve points for E3, E6, E8, E7 (60-sample curves plus the Table 5 head-share points) | `estate_structure.py` |
| `reproducibility/figure_data/figure6_speedup.csv` | Figure 6: median speed-up per core count (6 points) | production measurement, not a script |
| `reproducibility/figure_data/figure7_latency.csv` | Figure 7 / Table 18: latency percentiles; per-bucket medians and populations | production measurement, not a script |
| `reproducibility/example_data/synthetic_estate.csv` | 14-row hand-written **synthetic** export (public product names, fictitious endpoints 1001–1005) | hand-written |
| `reproducibility/example_data/cpe/synthetic_cpe_dictionary.xml` | 11-entry **synthetic** excerpt in the official CPE dictionary XML schema | hand-written |
| `reproducibility/example_data/cpe/synthetic_advisory_corpus.csv` | 4-row **synthetic** `cpe_product,version_bounded` corpus | hand-written |

The synthetic files exist only to show the input formats and let the pipeline run
end to end; none of the manuscript's numbers come from them.

**Provenance.** The CSVs in `reproducibility/aggregate_data/` and
`reproducibility/figure_data/figure1_fanout.csv` are the unmodified output of the
public scripts run on the nine study export files (eight estates; the ninth,
unreadable export is excluded and recorded in each file's header) on 2026-10-03,
after the scripts were checked line by line against the original study analysis.
The curve file holds each estate's 60-sample curve plus exact points at the Table 5
head-share positions (1 %, 5 %, 10 % of items). No value in these files was typed in
from the manuscript.

**Restricted (not in this repository).** The eight production estate exports and the
end-to-end scan inventory of Section 9; any endpoint-level record. See
[Data Provenance](#data-provenance) and `DATA_AVAILABILITY.md`.

**Input format for operator reproduction.** A NAC installed-application export
(`.xlsx` or `.csv`), one file per estate, with at least an endpoint identifier, a
product display name, a version string and a deletion flag; vendor, architecture
and operating-system family are used when present. Column names are matched by
alias (see `COLUMN_ALIASES` in `analysis/common.py`). The estate label is derived
from a trailing number in the file name (`estate3.xlsx` → `E3`).

## Code Information

| Script | Reproduces | Manuscript section | Input |
|---|---|---|---|
| `reproducibility/analysis/common.py` | Export reader and the §4.1 reduction (drop deleted / unnamed / versionless rows; merge on normalised product + version, folded by OS family when present). Imported, not run. | §4.1 | — |
| `reproducibility/analysis/estate_structure.py` | Tables 2–5, Figure 1 datapoints, and the §4.1 pre-reduction aggregates (rows held, rows flagged deleted, per-endpoint ratios) | §4.1–§4.5 | exports |
| `reproducibility/analysis/lexical_features.py` | Table 6 (eight lexical classes; summed and cross-estate-distinct name counts) | §4.6 | exports |
| `reproducibility/analysis/cpe_route.py` | Table 7 (four cumulative CPE resolution tiers; optional stage-2 version-bounded check; `--include-os/--include-hardware` for the §4.7 invariance check) | §4.7 | exports + CPE dictionary (+ corpus) |
| `reproducibility/reproduce_figures.py` | Figure 1 and Figure 6 from `figure_data/`; Figure 7(b) medians only, labelled partial | §4.5, §9.6, §9.10 | figure_data/ |
| `reproducibility/verify_release.py` | Release checks (see [Expected Outputs](#expected-outputs)) | — | repository |

All scripts are standard-library Python except for `openpyxl` (only for `.xlsx`
input) and `matplotlib` (only for `reproduce_figures.py`). Run any script with
`--help` for its full interface. No script reads a network service, a database or a
production system.

## Requirements

- Python 3.10 or later.
- `openpyxl==3.1.5` (for `.xlsx` exports only) and `matplotlib==3.8.4` (figures only),
  pinned in `reproducibility/environment/requirements.txt`.
- For Table 7: the official NIST CPE dictionary (not bundled; see
  [Reproducing Tables](#reproducing-tables)).
- A TeX distribution only if you want to rebuild the manuscript PDF (`paper/README.md`).

Tested on Linux with CPython 3.10.12. No GPU, accelerator or network access is needed.

## Installation

```bash
git clone https://github.com/RakortAcademy/PeerjNetworkPaper.git
cd PeerjNetworkPaper
python3 -m venv .venv && . .venv/bin/activate
pip install -r reproducibility/environment/requirements.txt
```

## Usage Instructions

```bash
cd reproducibility

# 1. Public reproduction: everything that runs from this repository alone
python3 verify_release.py                     # prints a PASS / FAIL / NOT TESTED report
python3 reproduce_figures.py --out out/figures # Figure 1, Figure 6 (+ partial 7b) as PDF and PNG

# 2. Smoke test of the analysis pipeline on the synthetic input (illustrative numbers only)
python3 analysis/estate_structure.py --dir example_data --out out/
python3 analysis/lexical_features.py --dir example_data --out out/
python3 analysis/cpe_route.py --dir example_data \
    --cpe-dictionary example_data/cpe/synthetic_cpe_dictionary.xml \
    --advisory-corpus example_data/cpe/synthetic_advisory_corpus.csv --out out/

# 3. Operator reproduction on your own NAC exports (one file per estate)
python3 analysis/estate_structure.py --dir path/to/exports --out out/
python3 analysis/lexical_features.py --dir path/to/exports --out out/
python3 analysis/cpe_route.py --dir path/to/exports \
    --cpe-dictionary official-cpe-dictionary_v2.3.xml --out out/
python3 reproduce_figures.py --figure 1 --figure1-data out/figure1_fanout.csv --out out/figures
python3 verify_release.py --operator-exports path/to/exports --cpe-dictionary official-cpe-dictionary_v2.3.xml
```

`--dir` picks up every `.xlsx`/`.csv` in a directory; `--export PATH` (repeatable)
names files individually. An export that is present but unreadable is skipped and
the exclusion is written into every output file's header comment (the manuscript
records one such export among the nine held, §4.1).

## Reproducing Tables

| Table | Script | Command (from `reproducibility/`) | Output file | Publicly reproducible? |
|---|---|---|---|---|
| 2 | `estate_structure.py` | `python3 analysis/estate_structure.py --dir <exports> --out out/` | `out/table2_version_coverage.csv` | Pipeline yes (synthetic input); published values need the restricted exports |
| 3 | `estate_structure.py` | same | `out/estate_structure.csv` | same |
| 4 | `estate_structure.py` | same | `out/table4_version_spread.csv` | same |
| 5 | `estate_structure.py` | same | `out/table5_fanout_distribution.csv` | same |
| 6 | `lexical_features.py` | `python3 analysis/lexical_features.py --dir <exports> --out out/` | `out/table6_lexical_features.csv` | same |
| 7 | `cpe_route.py` | `python3 analysis/cpe_route.py --dir <exports> --cpe-dictionary <dict> [--advisory-corpus <csv>] --out out/` | `out/table7_cpe_route.csv` | Pipeline yes (synthetic dictionary); published values **not reproducible publicly** (restricted exports, the 3 Aug 2026 production dictionary state and the production measurement code are not available; see below) |

Compare `out/*.csv` with the corresponding file in `aggregate_data/`
(`verify_release.py --operator-exports` does this with a tolerance of half a unit in
the last printed digit). Table 1 and Tables 8–19 are not produced by any script here.

**Table 7 provenance and limits.** The manuscript's Table 7 was measured on 3–4 August
2026 against the production service's product dictionary, which had been populated from
the NVD Products/CPE API 2.0 by a full acquisition on 3 August 2026 (the 896-page
acquisition described in the manuscript's Table 9). That dictionary is keyed by a
normalised product name; the manuscript's 43,706 (applications) and 138,158
(applications, operating systems and hardware) are counts of distinct non-deprecated keys
at that time. The dictionary table is not part of this package, the code that produced
the published measurement is not part of this package, and the exact 3 August deprecation
state of every entry is not recoverable from the live service: a reconstruction from the
current table reproduces 43,706 exactly and gives 138,159 for the second figure, a
one-key difference attributed to a later change in one entry's deprecation state.
`cpe_route.py` is a documented re-implementation of the four-tier procedure described in
§4.7 that reads the public NVD dictionary (XML or flat CSV) and keys it on normalised
titles and product tokens; it is exercised here on a synthetic dictionary only. Table 7's
published values therefore cannot be regenerated from public materials, and no public
check claims that they can.

**Obtaining the CPE dictionary for Table 7.** `cpe_route.py` reads either the
official XML (`official-cpe-dictionary_v2.3.xml`, the legacy NVD data feed listed at
<https://nvd.nist.gov/products/cpe>) or a flat `cpe23uri,title[,part]` CSV/TSV. NVD
has announced the retirement of its legacy feeds in favour of the Products/CPE API
2.0; at the time of writing the feed retirement had been extended "until further
notice". If only the API is available, export its `cpeName` and English `title`
fields to the flat CSV form. The dictionary is not bundled: it is large and changes
daily, so record the download date and the file's own generator timestamp with any
reproduction. Only non-deprecated application entries are admitted by default. The
stage-2 "resolved and version-bounded" row additionally needs a
`cpe_product,version_bounded` CSV; the corpus used for the manuscript is not part of
this package, so that row is reproducible only in form, not in value.

## Reproducing Figures

| Figure | Data | Command | Status |
|---|---|---|---|
| 1 (fan-out concentration, §4.5) | `figure_data/figure1_fanout.csv` | `python3 reproduce_figures.py --figure 1 --out out/figures` | Regenerated from the released points (60-sample curve per estate plus the Table 5 head-share points; the released file is the output of `estate_structure.py` on the study exports). From an operator's own exports: `estate_structure.py` writes a 60-point curve file, plotted with `--figure1-data`. |
| 6 (platform A scaling, §9.6) | `figure_data/figure6_speedup.csv` | `python3 reproduce_figures.py --figure 6 --out out/figures` | Regenerated; all six plotted medians are released. Run-to-run spread is not released. |
| 7 (per-item latency, §9.10) | `figure_data/figure7_latency.csv` | `python3 reproduce_figures.py --figure 7b --out out/figures` | **Not reproducible.** Panel (a) is the empirical distribution of 200 individual latencies, which are not released (only the Table 18 percentiles). Panel (b) medians and bucket populations are released, the per-bucket spread is not; the script draws the medians only as `figure7b_partial`. |
| 2–5 | — | — | Diagrams or production measurements; not generated by code here. |

Output is deterministic for a given matplotlib version (no timestamps in the PDF
metadata). The manuscript's figure styling is approximated, not pixel-matched.

## Verification

```bash
cd reproducibility && python3 verify_release.py
```

The script checks the released package without any restricted input: required files,
forbidden content, compilation, the schema of every released CSV, the arithmetic
consistency of Tables 2–5 with each other and of the Figure 1 points with Table 5, the
synthetic smoke test of all three analysis scripts run twice (byte-identical), and the
regeneration of Figures 1 and 6. Status words are exact: `PASS` only for checks that ran
and succeeded; `FAIL` for a failed check; `NOT TESTED` where the inputs are restricted;
`NOT REPRODUCIBLE` where public materials cannot support the result. An author holding
the study exports adds `--operator-exports DIR [--cpe-dictionary PATH]` to compare a rerun
against the released tables. Exit status is 0 only when no check failed.

## Data Restrictions

The eight production inventory exports, the end-to-end scan inventory, every
endpoint-level record, the production assessment service and its model weights, the
advisory and applicability corpora, and the production product dictionary are not in this
repository and cannot be released (confidential third-party data; proprietary system).
See [Restricted Components](#restricted-components), `DATA_AVAILABILITY.md` and
`CODE_AVAILABILITY.md`.

## Reproducibility Limitations

| Result | Public status |
|---|---|
| Tables 2–6, Figure 1 | Pipeline runs publicly on the synthetic input; the published values were regenerated by the authors from the restricted exports with the released code on 2026-10-03 and installed unchanged. An independent party can check their internal consistency and rerun the pipeline on their own export, not regenerate the study estates' numbers. |
| Table 7 | Not reproducible publicly: restricted exports, 3 Aug 2026 production dictionary state and production measurement code are unavailable; the four-tier procedure is re-implemented and exercised on a synthetic dictionary. |
| Figure 6 | Regenerated from the six released medians; run-to-run spread not released. |
| Figure 7 | Not reproducible: panel (a) needs 200 unreleased latencies; panel (b) is drawn from released medians only, without spread, as a labelled partial figure. |
| Tables 1, 8–19, Figures 2–5 | Qualitative or measured on the proprietary deployed system; not regenerated by any public code. |

## Methodology

The scripts implement the Section 4 definitions as stated in the manuscript:

1. **Reduction (§4.1).** Drop rows flagged deleted and rows without a product name;
   drop rows without a version as unscannable and count them; merge the rest on
   (normalised product name, normalised version), folded further by operating-system
   family only when that column exists. Because the deployed exporter always folds by
   OS family and these exports generally cannot, the reported reduction is an upper
   bound (manuscript §4.1; `common.py` docstring).
2. **Version coverage (§4.2).** Share of live rows (not deleted, named) with no version.
3. **Two-level redundancy (§4.3).** R scannable rows, U distinct (product, version)
   items, G distinct products; ρ_item = R/U, ρ_group = U/G, reduction = 1 − U/R.
   Pooled values sum over estates without cross-estate de-duplication.
4. **Version spread (§4.4).** Products with more than one version; widest spread.
5. **Fan-out (§4.5).** Rows merged into each item (installations; an item installed twice on one endpoint counts twice, which is why E3's maximum exceeds its endpoint count): percentiles (linear interpolation), head
   shares of rows covered by the top 1/5/10 % of items, singleton share, and the
   concentration curve (cumulative rows covered vs. items consumed in descending
   fan-out order, sampled at `--curve-samples` points).
6. **Lexical features (§4.6).** Eight regular-expression classes applied to each
   distinct product name per estate, summed over estates; classes overlap.
7. **CPE route (§4.7).** Four cumulative normalisation tiers looked up against an
   index built from dictionary titles and product tokens at the same tier; optional
   stage 2 intersects resolved products with a version-bounded set.

## Expected Outputs

`python3 reproducibility/verify_release.py` prints one line per check. Status words
are exact: `PASS` only for checks that ran and succeeded; `FAIL` for a failed check;
`NOT TESTED` where the inputs are restricted; `NOT REPRODUCIBLE` where the released
data cannot support the figure. In the state released here every check that can run reports `PASS`; Figure 7 reports
`NOT REPRODUCIBLE`; the published values of Tables 2–6 report `NOT TESTED` without the
restricted exports and Table 7 reports `NOT REPRODUCIBLE` (they were regenerated by the authors on 2026-10-03 and installed
unchanged, see Provenance under Dataset Information).

On the synthetic input, `estate_structure.py` reports 5 endpoints, 12 live rows,
11 scannable rows, 8 items and 7 products. Those numbers are illustrative only.

## Restricted Components

Not in this repository, and not releasable by the authors:

| Component (as named in the manuscript) | Why not released |
|---|---|
| Raw inventory exports of the eight study estates; the 6,129-row end-to-end scan inventory | Confidential third-party data: a complete software inventory of an identifiable organisation (§2.3, Ethics and Data Handling) |
| Learned sequence tagger (BiRNN-CRF with character sub-encoder, 8.8M parameters) and its trained weights | Proprietary production component |
| Constraint-extraction / applicability-gate logic, normalised-name index, full-text candidate retrieval, interval-comparison decision logic | Proprietary production component |
| Compiled concurrent decision engine and its single-threaded reference predecessor; in-memory candidate index; ONNX inference / CRF decoding path | Proprietary production component |
| Service tier (job queue, quota, caching, feed maintenance); deployment and credentials | Proprietary; operated inside customer networks |
| Seven-feed advisory corpus of Table 9 and the applicability corpus used for Table 7 stage 2 | Not part of the public package |

The Section 8–9 results were measured on that system and cannot be regenerated from
this repository. No sanitised substitute is included. Full accounting:
`CODE_AVAILABILITY.md`.

## Data Provenance

The analysed data are software-inventory exports from **eight production enterprise
deployments of a commercial network access control (NAC) platform**, obtained during
integration projects and used with the operators' consent (manuscript §4.1, Ethics
and Data Handling). Each export is a dump of the platform's installed-application
table: endpoint identifier (opaque numeric, internal to the platform), product display
name, version string, vendor string, architecture marker, deletion flag. A ninth
export was unreadable and is excluded. No organisation is named; estates carry
arbitrary labels (E1, E3–E9). The manuscript does not name the platform, product or
database, and no accession number or public URL exists for the data. The exports
were analysed on infrastructure operated by the organisations themselves and the
authors' institution/company; only derived aggregate statistics leave that boundary
and are what this repository publishes.

## Generative AI Use

The public reproducibility scripts, the verification and figure tooling and the
documentation in this repository were prepared with the assistance of Claude Code
(Anthropic), including rerunning the authors' analysis scripts on the study exports and
checking the regenerated outputs against the original analysis outputs and the submitted
manuscript. The experimental design, the analysis definitions, the measurements and the
conclusions are the authors' own; the authors reviewed all AI-assisted material and take
responsibility for it.

## Citations

If you use the scripts or the aggregate data, cite the manuscript (see
`CITATION.cff`; GitHub's "Cite this repository" reads it) and the archived software
release: Kocaoğlu, R. and Bakırcı, B. (2026). *Estate-structure analysis scripts and
aggregate data for Learning-Assisted Exposure Assessment at Estate Scale* (v1.0.0).
Zenodo. https://doi.org/10.5281/zenodo.23122101. The Zenodo archive contains this
repository at v1.0.0 only; it holds no restricted production data.

## License

The analysis scripts, verification and figure scripts, documentation and the
aggregate/figure/synthetic CSV and XML data are released under the MIT License
(`LICENSE`, and identically `reproducibility/LICENSE`); the copyright holder is Rakort
Bilgi Teknoloji A.Ş., Ankara, Turkey. The scientific authors of the work are Ramazan
Kocaoğlu and Basma Bakırcı (`CITATION.cff`). The manuscript text, figures
and tables under `paper/` are the authors' under-review submission and are not
covered by the MIT License. `paper/latex/wlpeerj.cls` is PeerJ's template class file,
included unmodified so the source builds.

## Contribution Guidelines

This is a static reproducibility artefact accompanying one manuscript, not a
maintained software project. Corrections to the documentation or scripts may be
proposed by opening an issue or pull request on the repository; changes to the
released aggregate data will only be accepted when regenerated by the authors from
the restricted exports, never by hand-editing values. Questions about the analysis
go to the corresponding author.
