# Analysis Code

The Section 4 estate-structure analysis scripts referenced in the manuscript's Data
Availability statement. They consume a NAC installed-application export in the
platform's native format (`.xlsx` or `.csv`) and regenerate Tables 2–7 and the
Figure 1 curve file.

- **`common.py`** — export reader and the §4.1 reduction (drop deleted / unnamed /
  versionless rows, merge on normalised product+version, folded by OS family when
  present). Imported, not run. The estate label is taken from a trailing number in
  the export's file stem (`estate3.xlsx` → `E3`).
- **`estate_structure.py`** — Tables 2–5 and the Figure 1 concentration curves;
  also emits the §4.1 pre-reduction aggregates (rows held, rows flagged deleted) as
  extra columns of the Table 2 output and the per-endpoint ratios in the console.
- **`lexical_features.py`** — Table 6; reports the summed and the cross-estate-distinct
  name counts (§4.6 quotes both).
- **`cpe_route.py`** — Table 7 against the official CPE dictionary (not shipped;
  `../docs/reproduction.md` says how to obtain it) or a flat `cpe23uri,title[,part]`
  table; `../example_data/cpe/` holds a synthetic dictionary and corpus for a smoke
  test only.

Run each with `--help`. Outputs are compared with `../aggregate_data/` by
`../verify_release.py --operator-exports`.

## Not included, and why

The proprietary assessment engine, service tier and trained tagger weights that
produced the Section 8–9 results are not here; those results were measured on a
deployed production service, not computed by these scripts. See
`../../CODE_AVAILABILITY.md` (component matrix) and `../../DATA_AVAILABILITY.md`
(public / restricted / not-included data).
