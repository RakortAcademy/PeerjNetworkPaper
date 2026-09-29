# Reproduction notes

## Scope
These scripts reproduce the **estate-structure measurement study** (manuscript
Section 4): version coverage (Table 2), two-level redundancy (Table 3), version
spread (Table 4), fan-out distribution (Table 5, Figure 1), lexical-feature
prevalence (Table 6), and the CPE-dictionary coverage route (Table 7).

They do **not** reproduce the performance experiments of Sections 8–9: those were
measured against the deployed assessment service (engine, service tier, learned
tagger), which is proprietary and operated inside customer networks and is not part
of this public package (see `../../CODE_AVAILABILITY.md`). The measured values are
provided as aggregate CSVs under `../figure_data/` and `../aggregate_data/` so the
published tables and figures can be checked.

## Input
A NAC installed-application export in the platform's native format, with columns:
endpoint id, product display name, version string, vendor string, architecture
marker, deletion flag (and, if available, OS-family join). Raw customer exports are
**not** included — supply your own (see `../../DATA_AVAILABILITY.md`).

## Steps
1. Install `../environment/requirements.txt`.
2. Run the three analysis scripts against one export per estate (repeat
   `--export`, or pass `--dir <exports>` to pick up every `.xlsx`/`.csv` file
   in a directory). An export that is unreadable — e.g. produced against a
   dropped database connection, as one of the nine held for this study was
   (Section 4.1) — is skipped and the exclusion is printed and written into
   every output file's header comment, rather than silently contributing
   zeros.

   ```
   # Tables 2-5 and Figure 1
   python3 analysis/estate_structure.py --dir <exports> --out out/

   # Table 6
   python3 analysis/lexical_features.py --dir <exports> --out out/

   # Table 7 (needs the published CPE dictionary; the version-bounded
   # stage additionally needs an applicability corpus, see the script's
   # --help)
   python3 analysis/cpe_route.py --dir <exports> \
       --cpe-dictionary official-cpe-dictionary_v2.3.xml --out out/
   ```

3. Compare `out/*.csv` against the corresponding file under
   `../aggregate_data/` and `../figure_data/`.

## Verification against the paper
`../aggregate_data/estate_structure.csv` holds the pooled and per-estate values as
published. `../figure_data/figure6_speedup.csv` and `figure7_latency.csv` hold the
plotted values for Figures 6 and 7.
