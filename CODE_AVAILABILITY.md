# Code Availability

**Manuscript:** *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
**Authors:** Ramazan Kocaoğlu, Basma Bakırcı
**Repository:** https://github.com/RakortAcademy/PeerjNetworkPaper (DOI: not yet
assigned; added at the v1.0.0 archive, see `reproducibility/docs/release_checklist.md`)

PeerJ's technical check flagged "Computer Code Required". This document states
precisely which code is public and which is not, component by component, so the
boundary does not have to be reverse-engineered from the archive.

## Component matrix

| Component | Availability | Repository location | Reason / notes |
|---|---|---|---|
| Export reader and §4.1 reduction | **Public** (MIT) | `reproducibility/analysis/common.py` | Imported by the three scripts below |
| Tables 2–5, Figure 1 datapoints, §4.1 aggregates | **Public** (MIT) | `reproducibility/analysis/estate_structure.py` | Needs a NAC export as input |
| Table 6 lexical-feature prevalence | **Public** (MIT) | `reproducibility/analysis/lexical_features.py` | Needs a NAC export as input |
| Table 7 CPE-dictionary route (tiers 1–4, optional stage 2, OS/hardware invariance switches) | **Public** (MIT) | `reproducibility/analysis/cpe_route.py` | Needs a NAC export and the official CPE dictionary; stage 2 needs an applicability corpus that is not released |
| Figure regeneration (Figures 1, 6; partial 7b) | **Public** (MIT) | `reproducibility/reproduce_figures.py` | From released `figure_data/` only |
| Release verification | **Public** (MIT) | `reproducibility/verify_release.py` | Files, schema, consistency, smoke test, figures |
| Learned sequence tagger (BiRNN-CRF, character sub-encoder, 8.8M parameters) — architecture, training code, trained weights | **Not released** | — | Proprietary production component of the authors' company |
| Constraint extraction and applicability gate | **Not released** | — | Proprietary |
| Normalised-name index and full-text candidate retrieval | **Not released** | — | Proprietary |
| Interval-comparison decision logic | **Not released** | — | Proprietary |
| Compiled concurrent decision engine; single-threaded reference predecessor; in-memory candidate index | **Not released** | — | Proprietary; subject of the §8–9 engine comparisons |
| ONNX export / host-language CRF decoding path | **Not released** | — | Proprietary |
| Service tier (job queue, quota, caching, feed maintenance), deployment configuration, credentials | **Not released** | — | Proprietary; operated inside customer networks |
| Instrumentation and timing harness of §7–9 | **Not released** | — | Part of the production system |

## What the public code does and does not establish

The six public scripts are **all and only** the code behind the Section 4
estate-structure measurement study (Tables 2–7, Figure 1) and the figure/verification
tooling around it. They were run against the eight confidential exports to produce
the values in `reproducibility/aggregate_data/`; the exports themselves are not
released (`DATA_AVAILABILITY.md`), so an independent party can run the pipeline on
the synthetic input or on their own export, but not regenerate the manuscript's
per-estate numbers.

Sections 5–9 describe and measure a production assessment service. **None of that
system's source code, model weights or configuration is in this repository**, and
the Section 8–9 performance results (engine comparison, scaling, latency, CPU-vs-GPU,
the end-to-end scan) cannot be regenerated from it. The plotted values of Figures 6
and 7 are released as CSV for checking only. No sanitised or reference
re-implementation of any production component is included, and none is fabricated
here to appear to satisfy the "Computer Code Required" item; whether a sanitised
reference implementation of a component (most plausibly the tagger) can be released,
or whether the Section 4 code plus this transparent statement is the appropriate
release for a systems paper on a proprietary deployment, is a decision for the
authors' company and the handling editor and remains open.

## Provenance of the released data

The Table 2–6 CSVs and the Figure 1 curve file are the unmodified output of the public
scripts on the nine study export files (2026-10-03), after the scripts were checked
against the original study analysis; the eight-estate values they contain were
verified against the original analysis outputs and the submitted manuscript, value by
value. No value was typed in from the manuscript.

## Table 7 (CPE route)

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

## PeerJ data/code availability compliance

The restriction on the raw inventories and on the proprietary engine, service tier
and tagger falls under PeerJ's policy exception for confidential third-party data and
proprietary commercial code. It does not extend to the Section 4 analysis scripts,
which are released in full under an MIT licence, nor to the aggregate, figure and
synthetic data derived from or accompanying them.
