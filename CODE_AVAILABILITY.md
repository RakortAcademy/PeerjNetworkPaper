# Code Availability

**Manuscript:** *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
**Authors:** Ramazan Kocaoğlu, Basma Bakırcı
**Repository:** https://github.com/RakortAcademy/PeerjNetworkPaper
**Concept DOI (all versions):** https://doi.org/10.5281/zenodo.23122100
**Archived releases:** v1.0.0 (commit `b51f048`, as originally submitted; version DOI
https://doi.org/10.5281/zenodo.23122101); v1.1.0 (adds `reference_implementation/`;
version DOI assigned by Zenodo on publication — see `README.md`, "Versions"). The same
content is supplied to PeerJ as a supplemental archive with the manuscript.

The public code and derived data described below are available from the repository and,
in archived form, from Zenodo. Each archive contains exactly the repository at that tag;
the proprietary production components listed as "Not released" and the restricted data
are not part of any archive.

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
| Per-item decision procedure (prepare/decide, four verdicts, final status rule, policy gate) — the manuscript's single-threaded reference engine | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/scanner.py`, `policy.py`, `rationale.py` | Research code; production couplings replaced at four seams (`reference_implementation/MAPPING.md`) |
| Learned sequence tagger (BiLSTM-CRF with character sub-encoder): architecture, training, inference, ONNX export, host-side CRF decoding | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/extraction/architecture.py`, `training/`, `export/` | Code only. The trained production weights (8.8M parameters) and training corpus are **not released**; the tests train a small model on synthetic data |
| Constraint extraction and applicability gates | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/extraction/`, `applicability.py`, `identity.py`, `disambiguation.py` | Verbatim modulo imports |
| Interval-comparison decision logic | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/versioning/` | Verbatim modulo imports |
| Candidate retrieval (two arms, acceptance, relevance) and the store's query semantics | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/search.py`, `corpus.py` | In-memory corpus reproducing the production store's queries; the PostgreSQL store itself is not released |
| Estate-level reduction, fan-back, request-level grouping | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/planning/` | |
| Extraction cache and model identity (§7 cache coherence) | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/extraction_cache.py`, `engine_identity.py` | In-process providers with the production key discipline |
| Golden-set metrics, engine-parity comparator, promotion gate, prioritisation | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/refimpl/evaluation/`, `prioritization.py` | |
| Synthetic corpus, inventory, training and golden data; reviewer example | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/example_data/`, `examples/run_pipeline.py`, `tests/` | 12 fictional advisories; no real product or customer data |
| Compiled concurrent decision engine (Go), worker pool, phase-timing instrumentation, local benchmark mode | **Inspectable** (PolyForm Noncommercial 1.0.0) | `reference_implementation/compiled_engine/goscan/` | Research-snapshot source; `go vet`/`go test` pass; end-to-end run needs a populated store and ONNX Runtime |
| In-memory candidate index and start-up equivalence self-check (§9) | **Not in this release** | — | Post-dates the source snapshot; not included in this release (`README.md`, "Restricted components") |
| Trained production tagger weights (8.8M) | **Not in this release** | — | Not included in this release; the training corpus is derived from the production advisory store (`README.md`, "Restricted components") |
| Service tier of the research snapshot: HTTP API (submission/retrieval split, blocking cap), authentication, durable job queue + worker, verdict cache (scope + engine identity), extraction-cache table, store-side pagination, engine client, feed scheduler, migrations, proxy limits, load-test harness | **Public** (PolyForm Noncommercial 1.0.0) | `reference_implementation/service_tier/` | Research-snapshot code with imports rewritten and six documented seams (`reference_implementation/MAPPING.md`, "Service tier"); runs on a local PostgreSQL with the engine shim; 60 tests without a database, 8 more with one |
| Item-metered allowance (§7.3) and per-feed refresh scheduler with skip reasons (§7.6) | **Not in this release** | — | Post-date the source snapshot (`README.md`, "Restricted components") |
| Feed acquisition modules, management panel, deployment units, TLS material, credentials | **Not released** | — | Data acquisition into the store, operator console, secrets |
| Repetition / latency-distribution / CPU-counter measurement harnesses of §7–9 | **Not in this release** | — | Part of the deployed service; not included in this release (`README.md`, "Restricted components") |

## What the public code does and does not establish

The six public scripts are **all and only** the code behind the Section 4
estate-structure measurement study (Tables 2–7, Figure 1) and the figure/verification
tooling around it. They were run against the eight confidential exports to produce
the values in `reproducibility/aggregate_data/`; the exports themselves are not
released (`DATA_AVAILABILITY.md`), so an independent party can run the pipeline on
the synthetic input or on their own export, but not regenerate the manuscript's
per-estate numbers.

Sections 5–9 describe and measure a production assessment service. The decision
method of Sections 5–7 is released as a reference implementation
(`reference_implementation/`): the authors' research code, with the four production
couplings (database store, extraction cache, model identity, checkpoint location)
replaced by in-process providers of the same call shape, together with a test suite
and a synthetic corpus so that it runs end to end without the production
environment. `reference_implementation/MAPPING.md` gives every file's origin, lists the code edits file by
file and describes the substituted content (rule tables, test fixtures, comments) by category. Together with `compiled_engine/goscan/` and `service_tier/` it forms the package's
**research reference implementation**. It is a means for reviewers to inspect and
exercise the method; it is not a simulation of the production system, it is **not
identical to the deployed system** (it predates the in-memory candidate index, the
item-metered allowance and the per-feed scheduler), and it produces no manuscript value.

The trained production weights, the deployed build of the compiled engine with its
in-memory candidate index, the two service-tier features that post-date the snapshot and
the measurement harnesses other than the load test are **not released**,
and therefore the Section 8–9 performance results (engine comparison, scaling, latency
distribution, CPU-vs-GPU, end-to-end scans, verdict preservation; Tables 8–19, Figures
2–7) **cannot be regenerated** from this repository. The plotted values of Figures 6
and 7 are released as CSV for checking only.

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

The restriction on the raw inventories and on the deployed engine build with its
in-memory index, the trained weights, the post-snapshot service-tier features and the
measurement harnesses falls under
PeerJ's policy exception for confidential third-party data and proprietary commercial
code. It does not extend to the Section 4 analysis scripts, which are released in full
under the MIT licence, nor to the aggregate, figure and synthetic data derived from or
accompanying them, nor to the reference implementation, the service tier of the research snapshot and the
Go engine source, which are released under the PolyForm Noncommercial License 1.0.0
(noncommercial use, including scientific review, research and teaching, permitted;
commercial use requires a separate licence from the copyright holder).
