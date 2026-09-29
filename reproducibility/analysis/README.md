# Analysis Code

The Section 4 estate-structure analysis scripts referenced in the manuscript's
Data Availability statement: version coverage, two-level redundancy, fan-out
concentration, lexical-feature prevalence, and the CPE-dictionary coverage route.
These scripts consume a NAC installed-application export in the platform's native
format (`.xlsx` or `.csv`) and regenerate Tables 2–7 and Figure 1.

## Scripts

- **`common.py`** — shared export reader and the Section 4.1 reduction
  (drop deleted / unnamed / versionless rows, merge on normalised
  product+version). Not run directly; imported by the three scripts below.
- **`estate_structure.py`** — Tables 2–5 and Figure 1: version coverage,
  two-level redundancy, version spread, fan-out distribution, and the
  fan-out concentration curves.
- **`lexical_features.py`** — Table 6: prevalence of the lexical classes
  (vendor prefix, embedded version, architecture marker, year, packaging
  vocabulary, non-ASCII, locale, edition) that normalisation must survive.
- **`cpe_route.py`** — Table 7: the four-tier CPE-dictionary resolution
  route plus the version-bounded-applicability check, against the published
  CPE dictionary (not shipped here; see `docs/reproduction.md`).

Run each with `--help` for its full argument list; `docs/reproduction.md` has
worked examples and how to check the output against `../aggregate_data/`.

## What is already in this repository

- **Aggregate statistics** (`../aggregate_data/`) — the per-estate and pooled
  measurements the scripts reproduce, as machine-readable CSV.
- **Figure source data** (`../figure_data/`) — data points for Figures 1, 6, 7.
- **Documentation** (`../docs/`) — the data format and measurement methodology,
  and the exact commands to regenerate every Section 4 table and figure.

## What is not included, and will never be

The proprietary assessment engine, service tier, and trained tagger weights that
produced the Section 8–9 performance results are not reproduced here; those
results were measured against a deployed production service, not against the
Section 4 analysis scripts. This limitation is stated in `../../CODE_AVAILABILITY.md`
(full accounting) and `../../DATA_AVAILABILITY.md`.

## PeerJ data/code availability compliance

The restriction on raw customer inventories and on the proprietary engine/service/
tagger is permitted under PeerJ's data availability policy exception for
confidential third-party data and proprietary commercial code. It does not extend
to the Section 4 analysis scripts themselves, which the manuscript states are
provided — see `../../CODE_AVAILABILITY.md` and `../../DATA_AVAILABILITY.md` for the
full public/restricted split.
