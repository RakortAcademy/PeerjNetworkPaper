# Data Availability

**Manuscript:** *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
**Authors:** Ramazan Kocaoğlu, Basma Bakırcı
**Target journal:** PeerJ Computer Science (AI Application)
**Repository:** https://github.com/RakortAcademy/PeerjNetworkPaper (archived release v1.0.0,
DOI https://doi.org/10.5281/zenodo.23122101; the archive contains the public files only)

PeerJ requires that raw data and/or code be made available whenever possible, and
that where third-party data cannot be shared for confidentiality or security reasons
the authors explain why. This document records the split for the **data** side; the
corresponding split for **code** is in `CODE_AVAILABILITY.md`.

## PUBLIC — in this repository

| Data | Location | What it is |
|---|---|---|
| Derived aggregate statistics, Tables 2–7 | `reproducibility/aggregate_data/*.csv` | Per-estate and pooled values exactly as printed in the manuscript; produced by the public scripts on the eight study estates |
| Table reproduction data | same files | The reference an operator's rerun is compared against (`verify_release.py --operator-exports`) |
| Figure reproduction data | `reproducibility/figure_data/figure1_fanout.csv`, `figure6_speedup.csv`, `figure7_latency.csv` | Plotted datapoints: Figure 1 curve points (60-sample curves plus Table 5 head-share points), Figure 6 medians, Figure 7 percentiles (= Table 18) and per-bucket medians/populations |
| Synthetic / example data | `reproducibility/example_data/synthetic_estate.csv`, `example_data/cpe/*` | Hand-written, fictitious; shows the input formats and lets the pipeline run; no manuscript number derives from it |
| Manuscript figures | `paper/latex/figures/Figure_1.pdf` … `Figure_7.pdf` | Vector PDF crops of the submitted figures; no TikZ/PGFPlots source exists |

The public figure data support Figures 1 and 6 only partially or fully as stated in
`README.md` ("Reproducing Figures"); Figure 7 cannot be regenerated from them.

**Provenance.** The Table 2–6 CSVs and `figure1_fanout.csv` are the unmodified output
of the public scripts on the study exports (2026-10-03), checked value by value against
the original study analysis and the manuscript.

## RESTRICTED — cannot be released

| Data | Why |
|---|---|
| Raw inventory exports of the eight production estates (and the excluded ninth) | Confidential third-party data: each enumerates the complete software estate of an identifiable organisation, which §2.3 of the manuscript argues must not leave the network that produces it. Obtained under terms permitting analysis, not redistribution. |
| The 6,129-row / 183-endpoint inventory of the end-to-end scan (§9.11) | Same |
| Any endpoint-level or customer-identifying record | Same |

The exports identify endpoints only by an opaque platform-internal number (no
hostname, user, address or location), no organisation is named, and only derived
aggregates are reported; even so the raw rows remain third-party confidential. This
is the confidentiality/security exception PeerJ's policy provides for.

## NOT INCLUDED — not data of this study

| Item | Note |
|---|---|
| Proprietary assessment engine, service tier, trained model weights | Code/model, not data; see `CODE_AVAILABILITY.md` |
| Credentials, production databases, deployment configuration | Never part of any package |
| Seven-feed advisory corpus (Table 9) and the applicability corpus used for Table 7 stage 2 | Operational feeds of the production service; not released. |
| Production product dictionary used for Table 7 (NVD Products/CPE API 2.0, full acquisition 3 Aug 2026) and its 3 Aug 2026 deprecation state | Operational table of the production service; not released. The public NVD dictionary is obtainable from NIST, but the historical state behind the published key counts (43,706 / 138,158) is not recoverable exactly; see `CODE_AVAILABILITY.md`, "Table 7". |
| The 200 individual latency observations behind Figure 7(a) and the per-bucket spread of Figure 7(b); run-to-run spread behind Figure 6 | Not released; only the summary values are |

## Third-party data source

The data are software-inventory exports from a **commercial network access control
(NAC) platform**, drawn from **eight production enterprise deployments**, obtained
during integration projects with the operators' consent (manuscript §4.1, "Ethics
and Data Handling"). Each export is a dump of the platform's installed-application
table with, per row, an endpoint identifier, product display name, version string,
vendor string, architecture marker and deletion flag. The manuscript does not name
the specific commercial platform, product or database, and no public database,
accession number or URL exists for these exports.

## What a comparable operator needs to reproduce the Section 4 analysis

1. An installed-application export from a NAC/asset-management platform with the
   columns above (operating-system family optional but recommended).
2. For Table 7: the official CPE dictionary (tiers 1–4), and, only for the stage-2
   row, a `cpe_product,version_bounded` CSV in the script's format.
3. The public scripts in `reproducibility/analysis/`.

The scripts regenerate Tables 2–6 and the Figure 1 curve file from item 1 alone and
Table 7 from items 1–2; nothing in this repository regenerates the Section 8–9
results, which required the deployed production service.
