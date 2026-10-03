# Reproduction notes

## Scope

These scripts reproduce the **estate-structure measurement study** (manuscript
Section 4): version coverage (Table 2), two-level redundancy (Table 3), version
spread (Table 4), fan-out distribution and concentration (Table 5, Figure 1),
lexical-feature prevalence (Table 6) and the CPE-dictionary route (Table 7).

They do **not** reproduce the performance experiments of Sections 8–9, which were
measured on the deployed proprietary assessment service (`../../CODE_AVAILABILITY.md`).
The plotted values of Figures 6 and 7 are released under `../figure_data/` for
checking only.

## A. Public reproduction (no customer data)

From `reproducibility/`:

```
pip install -r environment/requirements.txt
python3 verify_release.py            # file / schema / consistency / smoke-test / figure checks
python3 reproduce_figures.py --out out/figures
```

`reproduce_figures.py` regenerates Figure 1 from `figure_data/figure1_fanout.csv`
(piecewise-linear through the released points) and Figure 6 from
`figure_data/figure6_speedup.csv`. Figure 7 is **not** regenerable: panel (a) needs
the 200 individual latencies and panel (b) the per-bucket spread, neither of which is
released; the script draws the released 7(b) medians only, as `figure7b_partial`.

`figure1_fanout.csv` is the output of step B.2 on the study exports
(`--curve-estates E3,E6,E8,E7 --curve-samples 60`); the released Table 2–6 CSVs come
from the same run.

The synthetic smoke test (`example_data/`) exercises every code path, including the
official-schema XML dictionary parser, the stage-2 corpus and the OS/hardware
switches, on fictitious data; its numbers mean nothing scientifically.

## B. Operator reproduction (your own NAC export)

1. Export the installed-application table of each estate as `.xlsx` or `.csv` with
   at least: endpoint identifier, product display name, version string, deletion
   flag (vendor, architecture, operating-system family if available). Name the files
   with a trailing estate number (`estate1.xlsx`, `estate3.xlsx`, …) so the output
   labels read `E1`, `E3`, …; raw exports must never be committed (`.gitignore`
   excludes `*.xlsx` and `exports/`).
2. Run:
   ```
   python3 analysis/estate_structure.py --dir <exports> --out out/          # Tables 2-5, Figure 1 file
   python3 analysis/lexical_features.py --dir <exports> --out out/          # Table 6
   python3 analysis/cpe_route.py --dir <exports> --cpe-dictionary <dict> --out out/   # Table 7 tiers
   python3 reproduce_figures.py --figure 1 --figure1-data out/figure1_fanout.csv --out out/figures
   ```
   An export that is present but unreadable (a serialised database error in every
   cell, as one of the nine held for this study was, §4.1) is skipped and the
   exclusion is printed and written into every output file's header comment.
3. Compare: `python3 verify_release.py --operator-exports <exports> --cpe-dictionary <dict>`
   checks each produced table against `../aggregate_data/` (tolerance: half a unit of
   the last printed digit). Only the authors' eight exports are expected to match;
   another estate yields its own structure.

## C. Obtaining the CPE dictionary (Table 7)

`cpe_route.py` accepts either:

- the official NVD dictionary XML, `official-cpe-dictionary_v2.3.xml` (distributed
  gzipped as the legacy data feed listed at <https://nvd.nist.gov/products/cpe>), or
- a flat CSV/TSV with columns `cpe23uri,title[,part]` (`part` ∈ a/o/h; missing part
  = application).

NVD has announced the retirement of its legacy data feeds in favour of the
Products/CPE API 2.0 (<https://nvd.nist.gov/developers/products>); at the time of
writing the feed retirement had been extended "until further notice". If only the
API is available, write each product's `cpeName` and English `title` into the flat
CSV form above. By default only non-deprecated **application** entries are admitted;
`--include-os` and `--include-hardware` admit the other parts for the §4.7 invariance
check. The dictionary is not bundled (it is large and changes daily); record the
download date and the file's own `<generator><timestamp>` with any reproduction, as
the resolved shares depend on the snapshot.

Note that the manuscript's own Table 7 was measured against the production service's
product dictionary (NVD Products/CPE API 2.0, full acquisition 3 Aug 2026), keyed on a
normalised product name, with code that is not part of this package; its published values
are not reproducible from public materials (`../../CODE_AVAILABILITY.md`, "Table 7").

The stage-2 row ("resolved and version-bounded") needs `--advisory-corpus`, a CSV of
`cpe_product,version_bounded` (no comment lines). The corpus used for the manuscript
is not released, so that row is reproducible in form only.

## D. Verification against the paper

`../aggregate_data/estate_structure.csv` holds the Table 3 values as published;
`table2_…`, `table4_…`, `table5_…`, `table6_…`, `table7_…` the other tables;
`../figure_data/figure6_speedup.csv` and `figure7_latency.csv` the plotted values of
Figures 6 and 7. `verify_release.py` checks that these released files agree with
each other arithmetically (ρ_item = R/U, pooled sums, Table 2 ↔ Table 3 columns,
Table 4 ↔ Table 3 G, Figure 1 head points ↔ Table 5).
