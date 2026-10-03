# Title

Public reproducibility package for *Learning-Assisted Exposure Assessment at Estate
Scale: Constraint Recovery, Inventory Redundancy, and Engine Placement in Managed
Enterprise Networks* (Kocaoğlu, Bakırcı; PeerJ Computer Science, AI Application).

The repository-level `../README.md` is the full README (PeerJ section structure:
Description, Associated Publication, Repository Scope, Dataset Information, Code
Information, Requirements, Installation, Usage Instructions, Reproducing Tables,
Reproducing Figures, Methodology, Expected Outputs, Restricted Components, Data
Provenance, Citations, License, Contribution Guidelines). This file is the
package-local summary.

## Description

This directory contains **only** material the authors may release: the four analysis
scripts behind the manuscript's Section 4 measurement study, the derived aggregate
statistics they produced on the eight study estates (Tables 2–7), the plotted
datapoints of Figures 1, 6 and 7, synthetic example inputs, a figure-regeneration
script and a release-verification script. It contains no customer inventory and
none of the production assessment service described in manuscript Sections 5–9.

Two reproduction levels are distinguished:

- **Public reproduction** (anyone, from this directory alone): `verify_release.py`
  runs the scripts on the synthetic input, checks the released tables for internal
  consistency and regenerates Figures 1 and 6 from `figure_data/`.
- **Operator reproduction** (an operator holding a platform-native NAC export):
  Tables 2–7 and the Figure 1 curve file from *their own* estate. The eight study
  exports are restricted, so the manuscript's own numbers are regenerable only by the
  authors.

## Dataset Information

| Path | Content |
|---|---|
| `aggregate_data/` | Released values of Tables 2–7 (`table2_version_coverage.csv`, `estate_structure.csv` = Table 3, `table4_version_spread.csv`, `table5_fanout_distribution.csv`, `table6_lexical_features.csv`, `table7_cpe_route.csv`) |
| `figure_data/` | `figure1_fanout.csv` (60-sample curves plus Table 5 head-share points), `figure6_speedup.csv` (6 medians), `figure7_latency.csv` (Table 18 percentiles; bucket medians and populations) |
| `example_data/synthetic_estate.csv` | 14-row hand-written synthetic export, public product names, fictitious endpoints |
| `example_data/cpe/synthetic_cpe_dictionary.xml` | 11-entry synthetic excerpt in the official CPE dictionary XML schema (includes one deprecated, one OS and one hardware entry so the switches can be exercised) |
| `example_data/cpe/synthetic_advisory_corpus.csv` | 4-row synthetic `cpe_product,version_bounded` corpus |

**Not included:** the raw exports of the eight study estates (confidential third-party
data, `../DATA_AVAILABILITY.md`); the official CPE dictionary (public from NIST,
obtained separately, see `docs/reproduction.md`); the applicability corpus of Table 7
stage 2 and the advisory corpus of Table 9.

**Provenance.** `aggregate_data/*.csv` and `figure_data/figure1_fanout.csv` are the
unmodified output of the scripts in this directory on the nine study export files
(2026-10-03; one unreadable export excluded and recorded in each header), checked value
by value against the original study analysis and the manuscript.

**Input format (operator reproduction).** `.xlsx` or `.csv`, one file per estate;
columns resolved by alias (`COLUMN_ALIASES` in `analysis/common.py`): endpoint
identifier, product display name, version string, deletion flag required; vendor,
architecture, operating-system family optional. The estate label comes from a
trailing number in the file stem (`estate3.xlsx` → `E3`), otherwise `E1, E2, …` in
file order.

## Code Information

| Script | Reproduces | Section | Notes |
|---|---|---|---|
| `analysis/common.py` | Export reader, §4.1 reduction | §4.1 | Imported only |
| `analysis/estate_structure.py` | Tables 2–5, Figure 1 curve file; also the §4.1 aggregates (rows held, rows flagged deleted, per-endpoint ratios) as two extra columns of the Table 2 output and in the console summary | §4.1–§4.5 | `--curve-estates`, `--curve-samples` |
| `analysis/lexical_features.py` | Table 6; prints both the summed and the cross-estate-distinct name counts | §4.6 | |
| `analysis/cpe_route.py` | Table 7; `--include-os`, `--include-hardware` for the §4.7 invariance check; `--advisory-corpus` for stage 2 | §4.7 | XML or flat CSV/TSV dictionary |
| `reproduce_figures.py` | Figure 1 and Figure 6 (PDF+PNG) from `figure_data/`; Figure 7(b) medians only as `figure7b_partial`; Figure 7(a) not reproducible | §4.5, §9.6, §9.10 | deterministic output |
| `verify_release.py` | Release checks: required files, forbidden content, compile, released-CSV schema, arithmetic consistency of Tables 2–5 and Figure 1, synthetic smoke test (2 runs, byte-identical), figure regeneration; `--operator-exports` compares a rerun against `aggregate_data/` | — | exit 1 on any FAIL |

Tables 1, 8–19 and Figures 2–5, 7(a) are not produced by any script here. The
production components the manuscript describes (tagger, decision engine, index,
service tier, weights) are proprietary and are not in this package; see
`../CODE_AVAILABILITY.md` for the component matrix.

## Usage Instructions

```bash
pip install -r environment/requirements.txt

python3 verify_release.py                       # public checks
python3 reproduce_figures.py --out out/figures  # Figures 1, 6 (+ partial 7b)

# smoke test on the synthetic input (illustrative numbers only)
python3 analysis/estate_structure.py --dir example_data --out out/
python3 analysis/lexical_features.py --dir example_data --out out/
python3 analysis/cpe_route.py --dir example_data \
    --cpe-dictionary example_data/cpe/synthetic_cpe_dictionary.xml \
    --advisory-corpus example_data/cpe/synthetic_advisory_corpus.csv --out out/

# operator reproduction on your own exports
python3 analysis/estate_structure.py --dir path/to/exports --out out/
python3 analysis/lexical_features.py --dir path/to/exports --out out/
python3 analysis/cpe_route.py --dir path/to/exports \
    --cpe-dictionary official-cpe-dictionary_v2.3.xml --out out/
python3 verify_release.py --operator-exports path/to/exports \
    --cpe-dictionary official-cpe-dictionary_v2.3.xml
```

Every script writes CSV under `--out` and prints a console summary; an unreadable
export is skipped and recorded in each output file's header comment. Full
walkthrough: `docs/reproduction.md`.

## Reproducibility Limitations

See the repository README ("Reproducibility Limitations"): Tables 2–6 and Figure 1 are
regenerable only by the authors from the restricted exports (installed here unchanged);
Table 7 is not reproducible publicly (restricted exports, 3 Aug 2026 production
dictionary state and measurement code unavailable); Figure 7 is not reproducible; Figure 6
is drawn from released medians only.

## Requirements

Python ≥ 3.10. `openpyxl==3.1.5` only for `.xlsx` input; `matplotlib==3.8.4` only for
`reproduce_figures.py` (`environment/requirements.txt`). No network, GPU or
production system is needed.

## Methodology

The scripts implement the Section 4.1 reduction and the §4.2–§4.7 measurement
definitions exactly as stated in the manuscript (row filtering, product+version merge
key, ρ_item and ρ_group, fan-out percentiles and head shares, the eight lexical
regular expressions, the four cumulative CPE tiers). Each module docstring names the
subsection it implements; `../README.md` ("Methodology") lists the definitions.

## Citations

Cite the manuscript via `../CITATION.cff`. A repository DOI will be added there
when the release is archived (`docs/release_checklist.md`); none exists yet.

## License & Contribution Guidelines

Scripts, documentation and the CSV/XML data in this directory are MIT-licensed
(`LICENSE`, same terms as `../LICENSE`). This is a static artefact accompanying one
manuscript: documentation or script corrections may be proposed via the repository;
released aggregate values change only when regenerated by the authors from the
restricted exports. Questions go to the corresponding author.
