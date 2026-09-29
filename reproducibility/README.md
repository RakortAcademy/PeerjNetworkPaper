# Title

Estate-structure analysis scripts and aggregate data for *Learning-Assisted Exposure
Assessment at Estate Scale: Constraint Recovery, Inventory Redundancy, and Engine
Placement in Managed Enterprise Networks* (PeerJ Computer Science, AI Application).

## Description

This package is the public reproducibility material accompanying the manuscript. It
contains **only** material the authors have the right to release: the analysis
scripts for the manuscript's Section 4 measurement study, the derived non-identifying
aggregate statistics those scripts produce, and the CSV data behind three figures. It
does **not** contain any raw customer inventory, endpoint-level data, or the
production assessment service the rest of the manuscript describes.

**What can be reproduced publicly.** An operator of a comparable NAC (network access
control) deployment can regenerate every table and figure in manuscript Section 4 —
Tables 2–7 and Figure 1 — from **their own** installed-application export, using the
three scripts under `analysis/`. Nothing in Sections 5–9 (the service architecture,
planning, transport/continuity, or performance results) can be reproduced from this
package; those sections describe and measure a deployed production system that is
not part of this release (see "Code Information" below and
`../CODE_AVAILABILITY.md`).

## Dataset Information

**Required input format.** A NAC installed-application export in the platform's
native tabular format (`.xlsx` or `.csv`), one file per estate, carrying at minimum:
endpoint identifier, product display name, version string, and a deletion flag; and,
where the exporting platform provides them: vendor string, architecture marker,
operating-system family. Column names are resolved by a set of recognised header
aliases (see `COLUMN_ALIASES` in `analysis/common.py`) rather than by position.

**Raw customer exports are not included.** All three analysis scripts require a NAC
installed-application export as input. The eight exports used to produce the
manuscript's own Tables 2–7 and Figure 1 are restricted raw customer data and are not
shipped (see `../DATA_AVAILABILITY.md`); the scripts are released so a comparable
operator can run them against their own export. Supply your own export to reproduce
the analysis from scratch.

**What is shipped instead.**
- `example_data/synthetic_estate.csv` — a small, hand-written **synthetic** export
  (five fictitious endpoints, public product names) that shows the expected input
  format and lets the scripts be run end to end. It is not derived from any customer
  inventory and none of the manuscript's numbers come from it.
- `aggregate_data/` — the per-estate and pooled CSV outputs the authors obtained on
  the eight study estates (Tables 2–7), so the published numbers can be checked
  without access to the raw exports.
- `figure_data/` — CSV datapoints for Figure 1 (fan-out concentration), Figure 6
  (appliance core-count scaling) and Figure 7 (per-item latency). Figures 6 and 7 are
  properties of the production service, not outputs of the analysis scripts, but
  their plotted points are included as CSV so the figures can be checked against the
  text.

**External/public material some analyses additionally require.** `cpe_route.py`'s
core resolution tiers need the published CPE dictionary (public, from NIST — not
shipped here for size/licensing reasons). Its optional stage-2 check additionally
needs a small applicability corpus in the script's own `cpe_product,version_bounded`
format; this is a different, much smaller artefact than the full seven-feed advisory
corpus of Table 9, which supports the production service and is not part of this
package.

## Code Information

Four Python scripts are provided under `analysis/` (MIT-licensed, see `LICENSE`):

| Script | Reproduces | Manuscript section |
|---|---|---|
| `common.py` | Shared export reader and the Section 4.1 reduction (drop rows flagged deleted, drop rows without a product name, drop rows without a version as unscannable-and-counted, merge remaining rows on normalised product+version, optionally folded further by an operating-system-family column when present). Not run directly; imported by the three scripts below. | §4.1 |
| `estate_structure.py` | Table 2 (version coverage), Table 3 (two-level redundancy: $R$, $U$, $G$, $\rho_{\text{item}}$, $\rho_{\text{group}}$), Table 4 (version spread), Table 5 (fan-out distribution), Figure 1 (fan-out concentration curves) | §4.2–§4.5 |
| `lexical_features.py` | Table 6: prevalence of the eight lexical classes (vendor prefix, embedded version, architecture marker, year designator, packaging vocabulary, non-ASCII characters, locale qualifier, edition qualifier) that normalisation must survive | §4.6 |
| `cpe_route.py` | Table 7: the four cumulative CPE-dictionary resolution tiers, plus an optional stage-2 check of whether the resolved product also carries a version-bounded advisory in a supplied applicability corpus | §4.7 |

Run any script with `--help` for its complete, current argument list; the
`argparse` docstrings are the authoritative interface reference.

Tables 1, 8–19 and Figures 2–5 are not produced by any script in this package: Table
1 is a qualitative positioning table, and Tables 8–19 and Figures 2–5 report
properties of the production service (transport, planning, performance, scaling)
measured directly against the deployed system, not computed from these scripts.

**Production components not contained in this package, and why.** The production
assessment service described in manuscript Sections 5–9 — the learned sequence
tagger, the constraint-extraction and applicability-gate logic, the normalised-name
index and full-text retrieval, the interval-comparison decision logic, the compiled
concurrent decision engine and its single-threaded reference predecessor, the
in-memory candidate index, the ONNX inference/CRF-decoding path, and the service tier
(job queue, quota, caching, feed maintenance) — is a proprietary system operated by
the authors' company inside customer networks. It is not open-source and is not
included here. The Section 8–9 performance results were measured directly against
that deployed system and cannot be regenerated from this package. Full accounting,
including why no sanitised reference implementation is substituted:
`../CODE_AVAILABILITY.md`.

## Usage Instructions

```bash
# install the pinned environment (see Requirements below)

# quick smoke test on the shipped synthetic export (no customer data; the
# numbers it prints are illustrative only and do not appear in the manuscript)
python3 analysis/estate_structure.py --dir example_data --out out/
python3 analysis/lexical_features.py --dir example_data --out out/

# Tables 2-5 and Figure 1
python3 analysis/estate_structure.py --dir path/to/exports --out out/

# Table 6
python3 analysis/lexical_features.py --dir path/to/exports --out out/

# Table 7 (needs the published CPE dictionary; the optional version-bounded
# stage-2 check additionally needs an applicability corpus — see --help)
python3 analysis/cpe_route.py --dir path/to/exports \
    --cpe-dictionary official-cpe-dictionary_v2.3.xml --out out/
```

`--dir` picks up every `.xlsx`/`.csv` file in a directory; `--export PATH` (repeatable)
names individual export files instead. Every script writes its CSV output under
`--out` and prints a console summary. An export that is present but unreadable (see
`_CORRUPT_MARKERS` in `common.py`) is skipped, printed, and recorded in the output
file's own header comment rather than silently contributing zeros — matching the
manuscript's account (§4.1) of one such excluded export among the nine held for the
study. Compare `out/*.csv` against the corresponding file under `aggregate_data/` and
`figure_data/`. See `docs/reproduction.md` for the full worked walkthrough.

## Requirements

- Python 3.10 or later (standard library only for `common.py`, `estate_structure.py`
  and `lexical_features.py`).
- `openpyxl==3.1.5`, required only for `.xlsx` input; a `.csv` export needs nothing
  beyond the standard library.

Exact pin: `environment/requirements.txt`.

## Methodology

The scripts implement exactly the Section 4.1 reduction and the Section 4.2–4.7
measurement definitions as stated in the manuscript: row filtering (deleted /
unnamed / versionless), the product+version merge key, the two reduction ratios
$\rho_{\text{item}}$ and $\rho_{\text{group}}$, the fan-out/concentration statistics,
the eight lexical-noise regular expressions, and the four cumulative
CPE-normalisation tiers. Each script's module docstring cross-references the
manuscript subsection it implements; `docs/reproduction.md` has the reproduction
walkthrough, including how the "unreadable export" exclusion is handled and
reported.

## Citations

If you use these analysis scripts or the aggregate data, please cite the manuscript
via `CITATION.cff` at the repository root (also parseable by GitHub's "Cite this
repository" feature and by other tools that read the Citation File Format).

## License & Contribution Guidelines

The analysis scripts, this README, and the aggregate/figure CSVs in this directory
are released under the MIT License — see `LICENSE` (the same terms as the
repository-level `../LICENSE`). This is a static reproducibility
artefact accompanying a specific manuscript, not an actively maintained open-source
project: there is no issue tracker or pull-request process associated with it, and no
contribution guidelines beyond the license terms are stated or implied. Questions
about the analysis should be directed to the corresponding author (see the
manuscript's front matter).
