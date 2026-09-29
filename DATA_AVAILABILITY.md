# Data Availability

**Manuscript:** *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
**Authors:** Ramazan Kocaoğlu, Basma Bakırcı
**Target journal:** PeerJ Computer Science (AI Application)

PeerJ requires that raw data and/or code be made available whenever possible, and
that where third-party data cannot be shared for confidentiality or security reasons,
the authors provide an explanation. This document records the public/restricted split
for the **data** side of this submission. The corresponding split for **code** —
including which production components discussed in the manuscript are not publicly
releasable — is recorded separately in `CODE_AVAILABILITY.md`.

## What is public

Provided in this repository, and as supplemental files with the submission (see
`reproducibility/`):

- **Analysis scripts** that reproduce the estate-structure measurement study
  (Section 4): version coverage, two-level redundancy, fan-out concentration,
  lexical-feature prevalence, and the CPE-dictionary coverage route. See
  `CODE_AVAILABILITY.md` for the full accounting of what these scripts do and do
  not reproduce.
- **Derived, non-identifying aggregate statistics** — the per-estate and pooled
  numbers that appear in Tables 2–7 and Figure 1 — as machine-readable CSV
  (`reproducibility/aggregate_data/`).
- **Figure source data** as CSV, for the three figures whose underlying datapoints
  are tabular and recoverable: Figure 1 (fan-out concentration), Figure 6
  (appliance core-count scaling) and Figure 7 (per-item latency)
  (`reproducibility/figure_data/`). Figures 1–7 themselves are supplied as vector
  PDF crops of the approved manuscript figures (`paper/latex/figures/Figure_1.pdf` –
  `Figure_7.pdf`), not as TikZ/PGFPlots source; no such source files are part of
  this package.
- A **README** (`reproducibility/README.md`) describing how to regenerate the
  figures and tables from a NAC installed-application export in the platform's
  native format.

Because the scripts consume an export in the platform's native format, any operator
of a comparable NAC deployment can reproduce the Section 4 analysis against **their
own** inventory.

## What is restricted (cannot be released)

- **Raw customer inventories** — the eight production estate exports and the
  end-to-end scan inventory.
- **Endpoint-level customer data** of any kind.
- **Internal customer-identifying exports.**

## Why the raw inventories cannot be released

The underlying customer inventories enumerate the complete software estate of
identifiable organisations. That document is precisely the map of an organisation's
attack surface which the manuscript itself (Section 2.3) argues should never leave
the network that produces it. The exports were obtained during integration projects
under confidentiality terms that permit **analysis** but not redistribution, and
releasing them would disclose security-sensitive third-party data. This is the
confidentiality/security exception PeerJ's data-availability policy provides for.

The exports identify endpoints only by an opaque numeric identifier internal to the
management platform (no hostname, user, address, or location), no organisation is
named, and only derived aggregate statistics are reported — but even so the raw rows
remain third-party confidential and are withheld.

## Third-party data source

The data is software inventory exported from a **commercial network access control
(NAC) platform**, drawn from **eight production enterprise deployments**, obtained
during integration projects with the operators' consent (manuscript Section 4.1,
"Data and Method"). Each export is a dump of the platform's installed-application
table, carrying per row an endpoint identifier, a product display name, a version
string, a vendor string, an architecture marker and a deletion flag. The manuscript
does not name the specific commercial platform, product, or database.

## What a comparable operator would need to reproduce the analysis

1. An installed-application export from a NAC/asset-management platform, carrying per
   row: endpoint identifier, product display name, version string, vendor string,
   architecture marker, deletion flag, and (ideally) an operating-system-family join.
2. For the Section 4.7 CPE-dictionary route (`cpe_route.py`): the published CPE
   dictionary (always required), and, only for the optional stage-2 "resolved and
   version-bounded" check, a small `cpe_product,version_bounded` CSV supplied via
   `--advisory-corpus` (script-defined format, documented in the script's own
   `--help`). This is a different, much smaller artefact than the seven-feed
   advisory corpus of Table 9, which is not part of this public package.
3. For an end-to-end scan reproducing Sections 8–9 (not something these scripts do —
   see `CODE_AVAILABILITY.md`): the full advisory corpus of Table 9 and the
   proprietary assessment engine itself.
4. The public analysis scripts in `reproducibility/analysis/`.

The scripts regenerate every Section 4 table and Figure 1 from item (1) alone (Table
7 additionally needs item (2)'s dictionary); nothing in this public package
reproduces the Section 8–9 performance results, which required the deployed
production service (item 3).
