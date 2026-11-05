# Learning-Assisted Exposure Assessment at Estate Scale — Research Reference Implementation and Reproducibility Package

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23122100.svg)](https://doi.org/10.5281/zenodo.23122100)

**Version 1.1.1** (documentation release; supersedes v1.1.0 as the package accompanying the
revised manuscript). Repository: <https://github.com/RakortAcademy/PeerjNetworkPaper>.
Concept DOI (resolves to the latest archived version): <https://doi.org/10.5281/zenodo.23122100>.

This README follows the structure requested by PeerJ Computer Science for code and data
README files. Each required item has its own numbered section:

| PeerJ README item | Section |
|---|---|
| Title | [1. Title](#1-title) |
| Description | [2. Description](#2-description) |
| Dataset Information | [3. Dataset Information](#3-dataset-information) |
| Code Information | [4. Code Information](#4-code-information) |
| Usage Instructions | [5. Usage Instructions](#5-usage-instructions) |
| Requirements | [6. Requirements](#6-requirements) |
| Methodology | [7. Methodology](#7-methodology) |
| Citations | [8. Citations](#8-citations) |
| License & Contribution Guidelines | [9. License and Contribution Guidelines](#9-license-and-contribution-guidelines) |

Supporting sections: [10. What can and cannot be reproduced](#10-what-can-and-cannot-be-reproduced),
[11. Verification record](#11-verification-record), [12. Versions](#12-versions),
[13. Generative AI use](#13-generative-ai-use). The record of executing every command in
this README in a clean environment is [`REPRODUCIBILITY_REPORT.md`](REPRODUCIBILITY_REPORT.md).

---

## 1. Title

**Project:** Research reference implementation and reproducibility package for
*Learning-Assisted Exposure Assessment at Estate Scale: Constraint Recovery, Inventory
Redundancy, and Engine Placement in Managed Enterprise Networks*.

**Associated manuscript:** Ramazan Kocaoğlu and Basma Bakırcı, Department of Computer
Engineering, Ostim Technical University, Ankara, Turkey. Submitted to *PeerJ Computer
Science* (article type: AI Application), manuscript CS-2026:09:148327. Corresponding
author: Ramazan Kocaoğlu — ramazan.kocaoglu@ostimteknik.edu.tr.

**Relationship to the manuscript.** This repository is the code and data supplement of the
manuscript. It contains (a) the scripts and derived aggregate data of the Section 4
estate-structure measurement study, (b) a research reference implementation of the method of
Sections 5–7 that runs end to end on synthetic data, (c) the Go source of the compiled
decision engine of Sections 8–9, and (d) the manuscript itself (`paper/`). It is the same
material as the code archive supplied to PeerJ as a supplemental file
(`PeerjNetworkPaper_v1.1.1.zip`).

## 2. Description

### 2.1 Scientific purpose

An enterprise software inventory lists every installed application on every managed
endpoint. Deciding, for each installed (product, version), whether a published
vulnerability advisory applies requires (a) matching the inventory's product name to the
advisory's product, (b) recovering the affected-version constraint, which is often present
only in the advisory's free text, and (c) comparing the installed version against that
constraint. The manuscript:

- measures how redundant real enterprise inventories are (Section 4: eight production
  estates; version coverage, two-level redundancy, fan-out concentration, lexical features,
  the standard CPE naming route);
- describes a decision method that combines deterministic applicability gates and
  version-interval comparison with a learned sequence tagger (BiLSTM-CRF) that recovers
  version constraints from advisory prose (Section 5);
- describes redundancy-aware planning that prepares each product once and decides each
  version separately (Section 6), and the service around the method — transport,
  admission, durable queue, caches and feed maintenance (Section 7);
- measures a deployed system: where time goes, a compiled concurrent engine, scaling,
  CPU versus GPU (central / graphics processing unit) placement of the model, throughput,
  latency and verdict preservation (Sections 8–9).

### 2.2 Scope of this package

| Part | Manuscript | Content |
|---|---|---|
| `reproducibility/` | §4 | The four analysis scripts behind Tables 2–7 and Figure 1; the derived aggregate values they produced on the eight study estates; the plotted datapoints of Figures 1, 6 and 7; synthetic example inputs; figure regeneration; release verification and a sensitive-content scanner. |
| `reference_implementation/` | §5–7 (and the Go engine of §8–9) | The authors' research code of the decision method from the research snapshot of 1 August 2026: Python reference engine, BiLSTM-CRF tagger (training, inference, ONNX export, host-side CRF decoding), constraint recovery, applicability gates, version-interval comparison, inventory reduction, request-level grouping, caches, evaluation gates; the service tier (HTTP API, job queue, caches, database migrations) with a local engine stand-in; the Go source of the compiled engine. Production couplings are replaced by in-process or local providers; all data is synthetic. |
| `paper/` | — | The manuscript PDF and its LaTeX source. |

### 2.3 Architecture of the released implementation

```
 inventory rows ──► estate reduction (§6.1) ──► scan items (product, version, OS family)
                                                     │
                                                     ▼
                                   request-level grouping by product (§6.2)
                                                     │
                     ┌───────────────── per product group: PREPARE once ─────────────────┐
                     │ name cleaning, vendor resolution, candidate retrieval (structural  │
                     │ arm + full-text arm), relevance ranking, structural bounds          │
                     └─────────────────────────────────┬───────────────────────────────────┘
                                                       ▼
                     ┌──────────────── per version: DECIDE separately ───────────────────┐
                     │ tagger spans → constraint by closed-class operator rules (§5.1);   │
                     │ product identity + applicability gates; interval comparison;       │
                     │ structural bounds take precedence over text; final policy gate     │
                     └─────────────────────────────────┬───────────────────────────────────┘
                                                       ▼
          verdict per item: THREAT / SAFE / UNCERTAIN / NOT_FOUND ──► fan-back to endpoints

 Service tier (§7): HTTP API → durable PostgreSQL job queue → worker → engine (/scan)
                    verdict cache keyed by (product, version, scope, engine identity);
                    extraction cache keyed by (advisory text digest, model identity)
```

### 2.4 Limitations (read before using the results)

- **Not the production system.** The reference implementation is taken from the research
  snapshot of 1 August 2026. It is **not identical to the deployed system** and **reproduces
  no Section 8–9 measurement** (Tables 8–19, Figures 2–7). It predates the in-memory candidate
  index of the measured engine build, the item-metered allowance (§7.3) and the per-feed
  refresh scheduler (§7.6).
- **No production model.** The trained 8.8M-parameter production tagger, its training
  corpus and dictionaries are not released. The instructions train a ~28k-parameter tagger of
  the same architecture on synthetic sentences; its outputs are illustrative only.
- **The two released engines are not in full verdict parity.** The Go source lacks the
  language-binding applicability gate that the Python reference applies
  (`reference_implementation/compiled_engine/goscan/divergence_test.go` pins this). The
  engine parity reported in manuscript §9 was measured on the deployed build.
- **Synthetic content.** Every product name, version, advisory and endpoint in the data,
  tests and rule tables of `reference_implementation/` is fictional; curated rule tables that
  the deployed system fills from operation hold fictional entries here, so the gates
  demonstrate the mechanism without encoding real-world product knowledge
  (`reference_implementation/MAPPING.md`, "Synthetic substitution").
- **Confidential inputs.** The eight customer inventories behind Section 4 cannot be
  released (Section 3.4). Their derived, non-identifying aggregates are released and are
  checked for internal consistency; they cannot be recomputed without the exports.
- **The Go engine is inspectable, not runnable end to end here**: it compiles and its unit
  tests pass, but a scan needs a populated PostgreSQL advisory store and ONNX Runtime, which
  are not provided.

Full list: [Section 10](#10-what-can-and-cannot-be-reproduced).

## 3. Dataset Information

### 3.1 Overview

| Dataset | Path | Type | Records | Used by |
|---|---|---|---|---|
| Released Section 4 aggregates (Tables 2–7) | `reproducibility/aggregate_data/*.csv` | Derived from confidential exports, non-identifying | 6 CSV files | `verify_release.py` (consistency checks); comparison target for operator reruns |
| Figure datapoints (Figures 1, 6, 7) | `reproducibility/figure_data/*.csv` | Derived (Fig. 1) / production measurement summaries (Figs. 6, 7) | 3 CSV files | `reproduce_figures.py` |
| Synthetic NAC export | `reproducibility/example_data/synthetic_estate.csv` | Synthetic, hand-written | 14 rows, 5 endpoints | Section 4 scripts (smoke test) |
| Synthetic CPE dictionary and advisory corpus | `reproducibility/example_data/cpe/` | Synthetic, hand-written | 11 dictionary entries; 4 corpus rows | `cpe_route.py` |
| Synthetic advisory corpus | `reference_implementation/example_data/synthetic_corpus.jsonl` | Synthetic, generated | 12 advisories (`CVE-2099-xxxx`) | reference engine, tests, engine shim |
| Synthetic inventory | `reference_implementation/example_data/synthetic_inventory_rows.json` | Synthetic, generated | 25 rows, endpoints 1001–1007 | `examples/run_pipeline.py` |
| Synthetic tagger training data | `reference_implementation/example_data/synthetic_training.jsonl` | Synthetic, generated | 600 sentences | `refimpl.training.train` |
| Synthetic decoding-verification texts | `reference_implementation/example_data/synthetic_verify_texts.txt` | Synthetic, generated | 132 lines | `refimpl.export.export_onnx --verify-texts` |
| Synthetic golden set | `reference_implementation/example_data/synthetic_golden.jsonl` | Synthetic, generated | 8 cases | `refimpl.evaluation.golden_metrics` |

No manuscript number is derived from any synthetic file.

### 3.2 Schemas

**Section 4 aggregates** (`reproducibility/aggregate_data/`; one row per estate E1, E3–E9
plus pooled rows; header comment lines start with `#` and record provenance):

| File | Manuscript | Columns |
|---|---|---|
| `table2_version_coverage.csv` | Table 2 | `estate,endpoints,live_rows,no_version_pct,raw_rows,deleted_rows` |
| `estate_structure.csv` | Table 3 | `estate,endpoints,live_rows,no_version_pct,R_scannable,U_items,G_products,rho_item,rho_group,reduction_pct` |
| `table4_version_spread.csv` | Table 4 | `estate,products_G,multi_version_count,multi_version_pct,widest_spread` |
| `table5_fanout_distribution.csv` | Table 5 | `estate,p50,p90,p99,max,top1pct,top5pct,top10pct,singletons_pct` |
| `table6_lexical_features.csv` | Table 6 | `feature,example_fragment,share_pct` |
| `table7_cpe_route.csv` | Table 7 | `stage,by_name_pct,by_row_pct` |

**Figure datapoints** (`reproducibility/figure_data/`): `figure1_fanout.csv`
(`estate,items_consumed_pct,rows_covered_pct`; 60-sample curves of estates E3, E6, E8, E7 plus
the Table 5 head-share points), `figure6_speedup.csv` (`cores,speedup`; medians),
`figure7_latency.csv` (`percentile,latency_s`; the Table 18 percentiles, plus per-bucket
medians and populations).

**NAC installed-application export** (input of the Section 4 scripts;
`reproducibility/example_data/synthetic_estate.csv` shows the format):
`endpoint_id,name,version,vendor,architecture,client_deleted,os_family`. Column names are
matched by alias (`COLUMN_ALIASES` in `reproducibility/analysis/common.py`); `.csv` and
`.xlsx` are accepted; `os_family` is optional.

**CPE inputs of `cpe_route.py`:** the official NVD CPE dictionary XML
(`official-cpe-dictionary_v2.3.xml`) or a flat `cpe23uri,title[,part]` CSV/TSV (`part` ∈
`a`/`o`/`h`, missing = application); stage 2 additionally reads a
`cpe_product,version_bounded` CSV.

**Advisory corpus** (`synthetic_corpus.jsonl`, one JSON object per line):

```json
{"cve_id": "CVE-2099-0001",
 "description": "Acme Ledgerly Server before 2.4.1 allows remote attackers to execute arbitrary code via a crafted request.",
 "published_at": "2099-01-10", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
 "affected": [{"product": "Ledgerly Server", "vendor": "Acme", "version": "", "less_than": "2.4.1",
               "less_than_or_equal": "", "greater_equal": "2.0.0", "default_status": "unaffected"}],
 "risk": {"kev": true, "epss": 0.42, "cvss": 9.8, "kev_due_date": "2099-02-01"}}
```

`affected` mirrors the structured product/version fields of a CVE JSON 5 record (empty list =
the advisory has prose only, so the constraint must be recovered from `description`); `risk`
carries the KEV / EPSS / CVSS signals used for prioritisation.

**Inventory rows** (`synthetic_inventory_rows.json`): `{"_note": ..., "rows": [[endpoint_id,
name, version, vendor, architecture, os_text, os_type], ...]}`.

**Training data** (`synthetic_training.jsonl`): `{"cve_id", "text", "product", "version"}` per
line; BIO labels are derived from `product`/`version` by fuzzy alignment in
`refimpl/training/dataset.py`.

**Golden set** (`synthetic_golden.jsonl`): `{"product", "version", "vendor",
"expected_status", "accept_statuses", "expected_cve_ids", "category", "evidence"}`.

### 3.3 Synthetic versus derived data, and how to generate or load it

- **Generated synthetic data** (`reference_implementation/example_data/`) is produced
  deterministically by `generate_synthetic.py` (fixed seed). Regenerate with
  `cd reference_implementation && python example_data/generate_synthetic.py`; the five files
  are rewritten byte-identically. The loaders are `refimpl/corpus.py` (corpus),
  `examples/run_pipeline.py` (inventory rows), `refimpl/training/dataset.py` (training data) and
  `refimpl/evaluation/golden_metrics.py` (golden set); every CLI takes the file path as an
  argument, so edited copies can be used (Section 5.3, "Modify the inputs").
- **Hand-written synthetic data** (`reproducibility/example_data/`) is small and fixed;
  no generator is needed. Load it with `--dir example_data` (Section 5.6).
- **Derived data** (`reproducibility/aggregate_data/`, `figure_data/figure1_fanout.csv`) is the
  unmodified output of the public Section 4 scripts on the nine study export files
  (eight estates; the unreadable ninth is recorded in each file header), produced on
  2026-10-03 after the scripts were checked against the original study analysis; no value was
  typed in from the manuscript. `figure6_speedup.csv` and `figure7_latency.csv` are summary
  values of production measurements, released for checking only.
- **Your own data.** An operator holding a NAC installed-application export can run the
  Section 4 scripts on it (Section 5.6, "Your own export"). Raw exports must never be
  committed: `.gitignore` excludes `*.xlsx`, `*.xls`, `exports/`, database files and dumps.

### 3.4 Provenance and access restrictions

The Section 4 data are software-inventory exports from **eight production enterprise
deployments of a commercial network access control (NAC) platform**, obtained during
integration projects and used with the operating organisations' consent (manuscript §4.1 and
"Ethics and Data Handling"). Each export is a dump of the platform's installed-application
table (opaque numeric endpoint identifier, product display name, version string, vendor,
architecture marker, deletion flag). A ninth export was unreadable and is excluded. No
organisation is named; estates carry arbitrary labels (E1, E3–E9).

**Restricted, not released:** the raw exports (each enumerates the complete software estate
of an identifiable organisation — a map of its potential attack surface; removing endpoint
identifiers would not anonymise it, because the software mix itself can identify the
organisation); the 6,129-row inventory of the end-to-end scan (§9); the seven-feed advisory
corpus of the production service (Table 9) and the applicability corpus of Table 7 stage 2;
the production product dictionary state of 3 August 2026 behind Table 7; the original records
of the 200 latency measurements behind Figure 7(a). The exports come from no public database,
so no accession number or URL exists. Per-dataset status: [`DATA_AVAILABILITY.md`](DATA_AVAILABILITY.md).

**Third-party public data that you obtain yourself:** the NVD CPE dictionary
(<https://nvd.nist.gov/products/cpe>) for `cpe_route.py`. It is not bundled (large, changes
daily); record its download date and generator timestamp.

## 4. Code Information

### 4.1 Directory tree

```
.
├── README.md                     ← this file (single entry point)
├── REPRODUCIBILITY_REPORT.md     ← clean-environment execution record of this README
├── CLAIM_TO_CODE_MATRIX.md       ← every §5–9 claim → code + test; every reported result → reproducibility status
├── CODE_AVAILABILITY.md          ← public / not released, per code component
├── DATA_AVAILABILITY.md          ← public / restricted / not included, per dataset
├── RELEASE_NOTES.md · CITATION.cff
├── LICENSE                       ← MIT (v1.0.0 components; see §9)
├── paper/                        ← PeerJ_Manuscript.pdf; latex/ (main.tex, tables/, figures/, references.bib, wlpeerj.cls)
├── reproducibility/              ← Section 4 (MIT; reproducibility/LICENSE)
│   ├── analysis/                 ← common.py, estate_structure.py, lexical_features.py, cpe_route.py
│   ├── aggregate_data/           ← released Tables 2–7 (CSV)
│   ├── figure_data/              ← released datapoints of Figures 1, 6, 7 (CSV)
│   ├── example_data/             ← synthetic NAC export; cpe/ synthetic dictionary + corpus
│   ├── docs/                     ← reproduction.md (operator guide), release_checklist.md
│   ├── environment/requirements.txt
│   └── reproduce_figures.py · verify_release.py · scan_sensitive.py
└── reference_implementation/     ← Sections 5–7 + Go engine (PolyForm Noncommercial 1.0.0; LICENSE, NOTICE)
    ├── MAPPING.md                ← file origins, every code edit, synthetic substitutions, known divergence
    ├── requirements.txt · pytest.ini · conftest.py
    ├── refimpl/                  ← Python decision method (package)
    ├── tests/                    ← unit and synthetic end-to-end tests of refimpl
    ├── examples/run_pipeline.py  ← end-to-end example with every intermediate stage written out
    ├── example_data/             ← synthetic data + generate_synthetic.py
    ├── service_tier/             ← §7 API, queue, worker, caches, migrations, engine shim, load test, tests
    └── compiled_engine/goscan/   ← Go source of the compiled engine, its README and tests
```

### 4.2 Python reference implementation (`reference_implementation/refimpl/`)

| Module | Responsibility | § |
|---|---|---|
| `scanner.py` | `ThreatScanner`: the per-item decision procedure — `_prepare` (once per product group), `_decide` (per version), `_apply_gates`, `_resolve_with_structured_bounds`, `_finalize_status` | 5.1 |
| `extraction/architecture.py` | BiLSTM-CRF tagger with character sub-encoder: forward pass, CRF loss, decoding, checkpoint loading, batched prediction | 5.1 |
| `extraction/extractor.py`, `constraints.py` | Product + version extraction from advisory text; tagger spans → constraints by closed-class operator rules (`lt`/`le`/`ge`/ranges) | 5.1 |
| `extraction/rule_based.py`, `aggressive_regex.py`, `confidence.py`, `version_scheme.py` | Rule and regex fallback layers, confidence scoring, version-scheme inference | 5.1 |
| `versioning/parser.py`, `comparator.py`, `range_matcher.py` | Version parsing, ordering, interval comparison and boundary semantics | 5.1 |
| `fuzzy/matcher.py`, `fuzzy/vendor_aliases.py`, `vendors.py` | Product-name normalisation and fuzzy matching; vendor aliases and first-party vendor inference | 5.1 |
| `disambiguation.py`, `identity.py` | Resolution of ambiguous inventory names; product identity (is the advisory's product the installed one?) | 5.1 |
| `applicability.py` | Applicability gates: OS family, platform, plugin, vendor, language binding, suite component, OS-as-product | 5.1 |
| `policy.py`, `rationale.py` | Final policy gate before a THREAT is published; per-decision explanation and product decision summary | 5.1 |
| `search.py`, `corpus.py`, `store.py` | Two-arm candidate retrieval and relevance ranking over an in-memory corpus that reproduces the production store's queries; store facade | 5.1 |
| `prioritization.py` | Threat prioritisation from KEV / EPSS / CVSS | 5.1 |
| `planning/estate_reduction.py` | Estate-level reduction (normalise, de-duplicate on product, version, OS family) and fan-back to endpoints | 6.1 |
| `planning/planner.py` | Request-level grouping by product; order- and length-preserving assignment | 6.2 |
| `extraction_cache.py`, `engine_identity.py` | Extraction cache keyed by advisory-text digest + model identity; model identity = digest of the checkpoint bytes | 7 |
| `training/dataset.py`, `training/train.py` | BIO dataset construction with fuzzy alignment, vocabularies, seeded split; training (Adam, ReduceLROnPlateau, gradient clipping, early stopping), token-level P/R/F1 | 5.1 |
| `export/export_onnx.py`, `export/crf_decode.py` | ONNX export of the network up to emissions (CRF exported as JSON); host-side Viterbi; decoding-equivalence check | 9 |
| `evaluation/golden_metrics.py`, `parity.py`, `promote_gate.py` | Golden-set decision metrics; engine-parity comparator; model promotion gate | 5, 9 |

Log messages and many code comments are in Turkish, as in the authors' original code.

### 4.3 Service tier (`reference_implementation/service_tier/`)

| Path | Responsibility |
|---|---|
| `backend/main.py` | FastAPI application, start-up (migrations, model warm-up), engine health |
| `backend/routers/scan.py`, `jobs.py`, `scans.py`, `health.py` | Blocking scan with item cap; asynchronous job submission/polling/result; scan summary + paginated findings; health |
| `backend/security.py` | API-key and admin-token authentication |
| `backend/services/scanner.py`, `goscan.py`, `worker.py`, `cve_updater.py` | Cache-aware scan service; engine client (no fallback, 503 when the engine is down); background job worker (per-group persistence, resumption); feed scheduler (no feed modules registered here) |
| `storage/pool.py`, `migrate.py`, `migrations/*.sql` | PostgreSQL connection pool; forward-only migrations |
| `storage/jobs.py`, `cache.py`, `extractions.py`, `api_keys.py` | Job queue (`FOR UPDATE SKIP LOCKED` claim, requeue cap); verdict cache (product, version, scope, engine identity); extraction-cache table; API-key store |
| `config.py`, `env.example`, `docker-compose.example.yml`, `deploy/nginx.example.conf` | Settings from environment variables; local placeholder configuration; local PostgreSQL container; example proxy limits |
| `tools/engine_shim.py` | Serves the Python reference engine over the compiled engine's `/health` + `/scan` HTTP contract |
| `tools/loadtest.py` | Job-queue load test (functional check here, Section 5.4) |
| `tests/` | API, worker and scan-retrieval tests (no database); `test_e2e_postgres.py` (needs `SERVICE_TIER_E2E=1` and a local PostgreSQL) |

### 4.4 Go compiled engine (`reference_implementation/compiled_engine/goscan/`)

Go module `reference-implementation/compiled-engine` (Go 1.25.0, `go.mod`; dependencies
`github.com/jackc/pgx/v5` and `github.com/yalue/onnxruntime_go`, pinned in `go.sum`).
`main.go` (HTTP service / benchmark / extraction-equivalence modes; engine identity = binary
digest), `scan.go` (worker pool over product groups, prepare-once / decide-per-version,
per-group error isolation), `db.go` (store queries), `match.go`, `fuzzy.go`, `gates.go`,
`policy.go`, `version.go`, `constraints.go`, `extract.go`, `model.go` (ONNX inference with
host-side CRF decoding), `risk.go`, `summary.go`, `remediation.go`, `timing.go` (phase
accumulators, `GOSCAN_TIMING`). Tests: `match_test.go`, `falsepositive_test.go`,
`policy_test.go`, `divergence_test.go`. Design rationale, parity method and known differences:
[`compiled_engine/goscan/README.md`](reference_implementation/compiled_engine/goscan/README.md).

### 4.5 Section 4 analysis, figure and verification scripts (`reproducibility/`)

| Script | Produces | § |
|---|---|---|
| `analysis/common.py` | Export reader and the §4.1 reduction (drop deleted / unnamed / versionless rows; merge on normalised product + version, folded by OS family when present). Imported, not run | 4.1 |
| `analysis/estate_structure.py` | Tables 2–5, the Figure 1 curve file, §4.1 pre-reduction aggregates | 4.1–4.5 |
| `analysis/lexical_features.py` | Table 6 (eight lexical classes; summed and cross-estate-distinct name counts) | 4.6 |
| `analysis/cpe_route.py` | Table 7 (four cumulative CPE resolution tiers; optional stage-2 version-bounded check; `--include-os` / `--include-hardware` for the invariance check) | 4.7 |
| `reproduce_figures.py` | Figures 1 and 6 from `figure_data/`; Figure 7(b) medians only, labelled partial | 4.5, 9 |
| `verify_release.py` | Required files, forbidden content, compilation, CSV schemas, arithmetic consistency of Tables 2–5 and of Figure 1 against Table 5, synthetic smoke test of the three scripts run twice (byte-identical), Figures 1 and 6. Reports `PASS` only for checks that ran and succeeded, `NOT TESTED` where inputs are restricted, `NOT REPRODUCIBLE` where public materials cannot support a result; exits 0 only if nothing failed | — |
| `scan_sensitive.py` | Scans the tree for credentials, private addresses, absolute paths, model weights and office files | — |

Every script prints its options with `--help`.

### 4.6 Tests

| Suite | Location | Needs |
|---|---|---|
| Reference implementation | `reference_implementation/tests/` (run from `reference_implementation/`) | nothing beyond the Python requirements; one test also needs a trained checkpoint |
| Service tier | `reference_implementation/service_tier/tests/` | nothing; 8 end-to-end tests additionally need `SERVICE_TIER_E2E=1` and a local PostgreSQL |
| Go engine | `reference_implementation/compiled_engine/goscan/*_test.go` | Go toolchain; no database |
| Section 4 release checks | `reproducibility/verify_release.py` | Python requirements |

Exact counts and outputs are in Section 5 and [`REPRODUCIBILITY_REPORT.md`](REPRODUCIBILITY_REPORT.md).

## 5. Usage Instructions

Commands are run from the repository root unless a `cd` says otherwise. Expected outputs are
those observed in the clean-environment run recorded in `REPRODUCIBILITY_REPORT.md`.

### 5.1 Obtain the code

```bash
git clone --branch v1.1.1 https://github.com/RakortAcademy/PeerjNetworkPaper.git
cd PeerjNetworkPaper
# or, from the supplemental archive: unzip PeerjNetworkPaper_v1.1.1.zip && cd PeerjNetworkPaper-1.1.1
```

### 5.2 Install (one virtual environment for everything)

```bash
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -U pip wheel
# recommended: CPU-only torch first (no GPU is used; avoids about 4 GB of CUDA libraries)
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r reference_implementation/requirements.txt \
            -r reference_implementation/service_tier/requirements.txt \
            -r reproducibility/environment/requirements.txt
```

This installs `torch`, `pytorch-crf`, `numpy<2`, `snowballstemmer`, `onnx`, `onnxruntime`,
`pytest`, `fastapi`, `uvicorn`, `pydantic`, `psycopg2-binary`, `httpx`, `openpyxl` and
`matplotlib`. The CPU-only line is optional: without it, `pip` takes `torch` from PyPI, which on
Linux also installs the CUDA runtime libraries (the virtual environment then occupies about
5.5 GB instead of about 1.1 GB); both variants were tested (`REPRODUCIBILITY_REPORT.md` gives the scope of each).
On Windows, activate with `.venv\Scripts\activate` (untested; see Section 6.5).

### 5.3 Decision method on synthetic data (§5–6)

```bash
cd reference_implementation
python -m pytest                       # expected: 389 passed, 1 skipped (the skipped test needs the checkpoint of step b)
```

The suite covers version algebra and boundary semantics, constraint-recovery rules, product
normalisation and matching, applicability gates, the full decision procedure on the synthetic
corpus, inventory reduction and fan-back, request-level grouping, the extraction-cache key
discipline, model construction / forward / CRF loss / decode, the host-side Viterbi against
`torchcrf`, ONNX export equivalence, golden-set metrics, the parity comparator and the
promotion gate. No test needs a network, database or GPU.

**(a) Regenerate the synthetic data (optional; byte-identical):**

```bash
python example_data/generate_synthetic.py
```

**(b) Train a small tagger** (2–4 minutes on a 12-core CPU; seeded):

```bash
python -m refimpl.training.train --data example_data/synthetic_training.jsonl \
    --output example_data/tiny_model --epochs 40 --patience 6 --batch-size 32 --max-len 64 \
    --embedding-dim 24 --char-embedding-dim 12 --char-hidden-dim 12 --word-hidden-dim 32 \
    --min-word-freq 1 --workers 0 --label-workers 1 --device cpu
# ends with "Test — precision … | recall … | F1 …" (log messages are in Turkish)
```

Same architecture as the manuscript's model (BiLSTM-CRF with a character sub-encoder), about
28k parameters instead of 8.8M; writes `example_data/tiny_model/` (git-ignored).

**(c) Run the pipeline end to end:**

```bash
python examples/run_pipeline.py --model example_data/tiny_model --out out/
```

Expected (verdict counts are fixed by the deterministic rules on the synthetic corpus; the
tagger's extracted spans may vary slightly between training runs):

```
[1 estate reduction] 25 rows -> 16 items (rho_item=1.56); dropped: no version 1, no name 1
[2 planner] {'received': 16, 'unique': 16, 'duplicates': 0, 'product_groups': 11}
[3 prepare] group 00 'Orbital Browser' vendor='stellar software' -> 2 candidate(s), top relevance 115.0
[5 decide ] group 00 'Orbital Browser' '109.0.1': THREAT threats=1 safe=1 uncertain=0 ignored=0
…
[6 results] 16 items in submitted order: {'THREAT': 9, 'SAFE': 4, 'NOT_FOUND': 3}; extraction cache: {…}
[7 fan-back] 16 verdicts -> 22 endpoint exposures (= sum of endpoint_count = 22)
```

| Stage | What it demonstrates | Code | Written to `out/` |
|---|---|---|---|
| 1 estate reduction | 25 endpoint rows → 16 (product, version, OS family) items; versionless and nameless rows dropped; endpoint lists kept (§6.1) | `refimpl/planning/estate_reduction.py` | `estate_reduction.json` |
| 2 planner | Items grouped by product so preparation runs once per group (§6.2) | `refimpl/planning/planner.py` | `plan.json` |
| 3 prepare | Candidate retrieval (structural + full-text arm), structural bounds, product identity | `refimpl/scanner.py::_prepare`, `search.py`, `corpus.py` | `prepare_NN.json` |
| 4 extraction | Tagger spans → constraint by closed-class operator rules; extraction cache keyed by text digest + model id (§5.1, §7) | `refimpl/extraction/`, `extraction_cache.py` | `extraction.json` |
| 5 decide | Per-version decision: gates, interval comparison, structural-over-text precedence, policy gate | `refimpl/scanner.py::_decide`, `_apply_gates`, `_finalize_status`; `policy.py` | `decisions.json` |
| 6 results | One verdict per item in submitted order; each version keeps its own decision | `examples/run_pipeline.py` | `results.json` |
| 7 fan-back | Item verdicts mapped back to every endpoint row (§6.1) | `estate_reduction.py::fan_back` | `fan_back.json` |

The example yields no UNCERTAIN item: `Notes 4.13` is attributed to Apple from its macOS
context and, with no matching advisory, is NOT_FOUND; the same name without vendor or OS
context is UNCERTAIN (`tests/test_engine_synthetic.py::test_generic_name_without_vendor_is_uncertain`).

**Modify the inputs.** `--inventory` and `--corpus` accept edited copies of
`example_data/synthetic_inventory_rows.json` and `example_data/synthetic_corpus.jsonl`
(schemas in Section 3.2). For example, changing the two `Acme Ledgerly Server` `2.3.9` rows
(Windows Server) to `2.4.1`, the fixed version of `CVE-2099-0001`, turns that item from THREAT
into SAFE (stage 6: `{'THREAT': 8, 'SAFE': 5, 'NOT_FOUND': 3}`) while every other item keeps
its verdict. It stays a separate item from endpoint 1004's `ACME LEDGERLY SERVER 2.4.1`
because the reduction key includes the OS family (Ubuntu there).

**(d) ONNX export and decoding equivalence (§9 procedure):**

```bash
python -m refimpl.export.export_onnx --checkpoint example_data/tiny_model/bilstm_crf.pth \
    --out example_data/tiny_model/onnx --verify-texts example_data/synthetic_verify_texts.txt
# expected: "132/132 cümlede etiket dizisi AYNI" (identical label sequences) for the ONNX path and for the host-side Viterbi
```

**(e) Golden-set metrics and the trained-tagger test:**

```bash
python -m refimpl.evaluation.golden_metrics --golden example_data/synthetic_golden.jsonl \
    --corpus example_data/synthetic_corpus.jsonl --model example_data/tiny_model
REFIMPL_MODEL_PATH=example_data/tiny_model python -m pytest tests/test_tagger.py    # expected: 9 passed
cd ..
```

### 5.4 Service tier (§7)

Without a database:

```bash
cd reference_implementation
python -m pytest service_tier/tests                     # expected: 60 passed, 8 skipped

# the engine shim alone answers POST /scan (one item, or {"items": [...]}); omit --model to run without the tagger
python -m service_tier.tools.engine_shim --addr 127.0.0.1:8390 --model example_data/tiny_model &
curl -s -X POST localhost:8390/scan -d '{"product":"Acme Ledgerly Server","version":"2.3.9","vendor":"Acme"}'
# -> "status": "THREAT", threats[0].cve_id "CVE-2099-0001", reason "Version 2.3.9 < 2.4.1 (exclusive)";
#    2.4.1 -> SAFE; "Notes" without vendor/OS -> UNCERTAIN; an unknown product -> NOT_FOUND;
#    a missing or empty product/version -> 422
kill %1
```

End to end with a local PostgreSQL (any version ≥ 14; the compose file starts PostgreSQL 17 on
`127.0.0.1:55432`):

```bash
docker compose -f service_tier/docker-compose.example.yml up -d
set -a; . service_tier/env.example; set +a              # PG*, API_KEYS, ADMIN_TOKEN, GOSCAN_URL — local placeholders only
SERVICE_TIER_E2E=1 python -m pytest service_tier/tests  # expected: 68 passed (TRUNCATES the job/cache tables of that database)
```

Interactive use (two terminals with the same environment variables):

```bash
python -m service_tier.tools.engine_shim --addr 127.0.0.1:8390             # terminal 1
python -m uvicorn service_tier.backend.main:app --host 127.0.0.1 --port 8000 # terminal 2

curl -s localhost:8000/health                                           # "status":"ok","database":true
curl -s -X POST localhost:8000/scan -H "X-API-Key: $API_KEYS" -H 'Content-Type: application/json' \
     -d '{"items":[{"product":"Acme Ledgerly Server","version":"2.3.9","vendor":"Acme"},
                   {"product":"Acme Ledgerly Server","version":"2.3.9","vendor":"Acme"},
                   {"product":"Contoso Photolens Viewer","version":"1.2.3","vendor":"Contoso"}]}'
# -> 202 {"job_id": ..., "poll_url": "/jobs/<id>", "result_url": "/jobs/<id>/result"}
curl -s localhost:8000/jobs/<id> -H "X-API-Key: $API_KEYS"              # "status":"DONE","completed":3
curl -s localhost:8000/jobs/<id>/result -H "X-API-Key: $API_KEYS"       # the duplicate item is marked "cached": true
curl -s 'localhost:8000/admin/scans/1/findings?bucket=threats&limit=10' -H "X-Admin-Token: $ADMIN_TOKEN"
python service_tier/tools/loadtest.py --items 300 --url http://127.0.0.1:8000 --api-key "$API_KEYS"
docker compose -f service_tier/docker-compose.example.yml down -v       # remove the container and its data
cd ..
```

The load test is a functional check only: on the synthetic corpus the jobs finish before its
first 5 s status poll, so its reported duration is the polling interval, not a throughput
measurement, and is not comparable with any manuscript value.

### 5.5 Compiled engine (Go)

```bash
cd reference_implementation/compiled_engine/goscan
go vet ./... && go test ./...     # expected: vet clean; "ok  reference-implementation/compiled-engine"
go build -o goscan .              # builds; running a scan needs a populated PostgreSQL advisory store and ONNX Runtime (not included)
cd ../../..
```

If your Go is older than 1.25.0, `GOTOOLCHAIN=auto` (the default) downloads the toolchain named
in `go.mod`. `go test` needs no database. To point the service tier at a compiled engine you
operate yourself, set `GOSCAN_URL` to its address.

### 5.6 Section 4 estate-structure analysis

```bash
cd reproducibility
python verify_release.py          # expected: "OK: 0 check(s) failed, 27 passed, 7 not tested / not reproducible"
python scan_sensitive.py          # expected: "0 finding(s)"
python reproduce_figures.py --out out/figures   # Figure 1, Figure 6, Figure 7(b) partial (PDF + PNG)

# pipeline on the synthetic input (illustrative: 5 endpoints, 12 live rows, 11 scannable rows, 8 items, 7 products)
python analysis/estate_structure.py --dir example_data --out out/
python analysis/lexical_features.py --dir example_data --out out/
python analysis/cpe_route.py --dir example_data \
    --cpe-dictionary example_data/cpe/synthetic_cpe_dictionary.xml \
    --advisory-corpus example_data/cpe/synthetic_advisory_corpus.csv --out out/
cd ..
```

**Your own export (operator reproduction).** Export each estate's installed-application table
with at least endpoint identifier, product display name, version string and deletion flag
(vendor, architecture, OS family if available). Name files with a trailing estate number
(`estate3.xlsx` → `E3`; otherwise `E1, E2, …` in file order). Run the three scripts with
`--dir path/to/exports` (or `--export PATH`, repeatable), plot with
`reproduce_figures.py --figure 1 --figure1-data out/figure1_fanout.csv`, and compare with the
released tables using `verify_release.py --operator-exports path/to/exports [--cpe-dictionary PATH]`
(tolerance: half a unit in the last printed digit). An unreadable export is skipped and the
exclusion is written into every output header. Only the study's eight exports reproduce the
released values; another estate yields its own structure. Step-by-step guide:
[`reproducibility/docs/reproduction.md`](reproducibility/docs/reproduction.md).

### 5.7 Rebuild the manuscript PDF (optional)

```bash
cd paper/latex && latexmk -pdf main.tex && cd ../..   # needs a TeX distribution; writes the git-ignored main.pdf (33 pages)
```

### 5.8 Complete end-to-end example (copy and paste)

From a fresh clone or extracted archive, on Linux with Python 3.10 (about 5 minutes after the
download of the dependencies; no database, GPU or network service other than PyPI):

```bash
python3 -m venv .venv && . .venv/bin/activate && python -m pip install -U pip wheel
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r reference_implementation/requirements.txt -r reference_implementation/service_tier/requirements.txt \
            -r reproducibility/environment/requirements.txt
(cd reproducibility && python verify_release.py && python reproduce_figures.py --out out/figures)
cd reference_implementation
python -m pytest
python -m refimpl.training.train --data example_data/synthetic_training.jsonl --output example_data/tiny_model \
    --epochs 40 --patience 6 --batch-size 32 --max-len 64 --embedding-dim 24 --char-embedding-dim 12 \
    --char-hidden-dim 12 --word-hidden-dim 32 --min-word-freq 1 --workers 0 --label-workers 1 --device cpu
python examples/run_pipeline.py --model example_data/tiny_model --out out/
python -m refimpl.export.export_onnx --checkpoint example_data/tiny_model/bilstm_crf.pth \
    --out example_data/tiny_model/onnx --verify-texts example_data/synthetic_verify_texts.txt
python -m pytest service_tier/tests
```

Each command's expected output is given in Sections 5.3–5.6.

### 5.9 Troubleshooting

| Symptom | Cause and remedy |
|---|---|
| `pip` cannot find a `torch` wheel | Use a Python version for which PyPI ships torch wheels for your platform (3.10 was tested). On platforms with a vendor-built torch (e.g. NVIDIA Jetson), create the venv with `python3 -m venv --system-site-packages .venv` and remove the `torch` line from the install. |
| `UserWarning: CUDA initialization: The NVIDIA driver on your system is too old` | Harmless: the default PyPI `torch` probes for a GPU at import; nothing uses it. Install the CPU-only `torch` (Section 5.2) to avoid the warning and the CUDA libraries. |
| `ModuleNotFoundError: refimpl` or `service_tier` | Run the reference-implementation and service-tier commands from `reference_implementation/` (that directory holds `conftest.py` and is the package root). |
| ONNX export asks for `onnxscript` | Not expected: with torch ≥ 2.9 the exporter is called with `dynamo=False` (TorchScript exporter). Verified with torch 2.5 and 2.14. |
| `test_tagger.py` reports 1 skipped | Expected without a checkpoint; set `REFIMPL_MODEL_PATH=example_data/tiny_model` after step 5.3(b). |
| End-to-end service tests are skipped | Expected unless `SERVICE_TIER_E2E=1` is set and the `PG*` variables from `env.example` point to a running PostgreSQL. |
| `docker compose` fails: port 55432 in use | Another service uses the port. Change the host port in `docker-compose.example.yml` and `PGPORT` in your environment together. |
| `uvicorn` reports `[Errno 98] address already in use` for port 8000 (or 8390) | Another program already listens on that port, and the `curl` commands would then reach that program instead. Start the API with another port (e.g. `--port 18000`) and use that port in every `curl` and `loadtest.py --url`; for the shim, change `--addr` and `GOSCAN_URL` together. |
| `curl localhost:8000/health` reports `"database": false` or the job never finishes | PostgreSQL not reachable or the engine shim not running at `GOSCAN_URL`; start both first, with the same environment variables. |
| `go: go.mod requires go >= 1.25.0` | Install Go ≥ 1.25.0, or leave `GOTOOLCHAIN=auto` so Go downloads it. |
| `goscan` binary exits with "veritabanına bağlanılamadı" (cannot connect to the database) or "model damgası gerekli" (model version required) | Expected: the binary needs a populated PostgreSQL advisory store (`PG*` variables), a model version label (`-model-version` or `MODEL_VERSION`) and, for inference, ONNX Runtime (`ONNXRUNTIME_LIB`); the store and model are not released (`main.go`). Running the binary was not part of the verification. |
| `cpe_route.py` reports zero matches on a real export | Pass the real NVD dictionary with `--cpe-dictionary`; the synthetic dictionary covers only the synthetic export. |

## 6. Requirements

### 6.1 Mandatory

| Requirement | Version | Notes |
|---|---|---|
| Operating system | Linux (tested: Ubuntu 22.04, aarch64) | macOS and Windows are untested (Section 6.5) |
| Python | ≥ 3.10 (tested: CPython 3.10.12 for every step; 3.12.16 for the test suites) | `python3 -m venv` |
| Python packages, reference implementation | `numpy>=1.24,<2`, `torch>=2.0`, `pytorch-crf>=0.7.2`, `snowballstemmer>=2.2`, `onnx>=1.14`, `onnxruntime>=1.16`, `pytest>=8.0` | `reference_implementation/requirements.txt` |
| Python packages, service tier | `fastapi>=0.115`, `uvicorn[standard]>=0.30`, `pydantic>=2.7`, `psycopg2-binary>=2.9`, `httpx>=0.27` | `reference_implementation/service_tier/requirements.txt` |
| Python packages, Section 4 | `openpyxl==3.1.5` (only for `.xlsx` exports), `matplotlib==3.8.4` (figures) | `reproducibility/environment/requirements.txt`; the analysis scripts otherwise use the standard library |
| Hardware | Any 64-bit CPU; 4 GB RAM (measured peak resident memory of the largest step, tagger training: about 0.4 GB); free disk about 2 GB with the CPU-only torch (about 6 GB with the default PyPI torch, which bundles CUDA libraries) | No GPU is needed or used. Tested on a 12-core aarch64 machine |
| Network | PyPI (and the Go module proxy for the Go step) during installation only | Nothing in the package contacts a network service at run time |

The exact package versions resolved in the verification run are listed in
`REPRODUCIBILITY_REPORT.md` (pip freeze).

### 6.2 Optional

| Requirement | Needed for | Version |
|---|---|---|
| Go toolchain | `go vet`, `go test`, `go build` of the compiled engine | 1.25.0 (from `go.mod`; tested with go1.25.0 linux/arm64) |
| PostgreSQL | the 8 end-to-end service-tier tests and the interactive HTTP demo | ≥ 14 (tested: 17, from `docker-compose.example.yml`) |
| Docker with the `docker compose` plugin | the provided local PostgreSQL container | tested: Docker 29.4.2, Compose v5.1.3 |
| `curl` | the HTTP examples | any |
| TeX distribution with `latexmk`, `pdflatex`, `bibtex` | rebuilding the manuscript PDF | tested: TinyTeX (TeX Live, tlmgr revision 79639) |
| NVD CPE dictionary | `cpe_route.py` on real data | download from NIST |

### 6.3 Runtime services

None for Sections 5.3, 5.5 and 5.6. Section 5.4 uses two local processes (the engine shim on
`127.0.0.1:8390` and the API on `127.0.0.1:8000`) and a local PostgreSQL on
`127.0.0.1:55432`. No service of the authors or of any company is contacted.

### 6.4 Configuration variables

| Variable | Default / example | Used by | Purpose |
|---|---|---|---|
| `REFIMPL_MODEL_PATH` | unset | `refimpl`, tests, engine shim | Tagger checkpoint (file or directory); unset = run without the tagger |
| `SERVICE_TIER_E2E` | unset | `service_tier/tests/test_e2e_postgres.py` | `1` enables the PostgreSQL end-to-end tests (they truncate job/cache tables) |
| `PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`, `PG_MIN_CONN`, `PG_MAX_CONN` | `127.0.0.1`, `55432`, `refimpl`, `postgres`, `change-me`, `1`, `8` | service tier | Local PostgreSQL connection (placeholders, `env.example`) |
| `API_KEYS`, `ADMIN_TOKEN` | `local-dev-key`, `local-admin-token` | service tier | Static API keys for scan/job endpoints; token for `/admin` retrieval endpoints (empty = off) |
| `GOSCAN_URL`, `GOSCAN_TIMEOUT_SECONDS`, `WARM_MODEL_ON_STARTUP` | `http://127.0.0.1:8390`, `900`, `1` | service tier | Engine address (shim or compiled engine); timeout; model warm-up |
| `CACHE_ENABLED`, `CACHE_TTL_DAYS` | `1`, `7` | service tier | Verdict cache |
| `JOB_WORKERS`, `MAX_BATCH_ITEMS`, `MAX_JOB_ITEMS` | `1`, `500`, `50000` | service tier | Worker count; item cap of the blocking variant; job size limit |
| `CVE_SYNC_INTERVAL_HOURS`, `CVE_SYNC_ON_STARTUP` | `0`, `0` | service tier | Feed scheduler (no feed modules are registered in this package) |
| `GOSCAN_MODEL_DIR`, `MODEL_VERSION`, `ONNXRUNTIME_LIB`, `GOSCAN_TIMING`, `GOSCAN_TRACE`, `GOSCAN_SWEEP`, `BENCH_ITEMS` | unset | Go engine | Model directory and version label, ONNX Runtime library, phase timing, tracing and benchmark options |

`service_tier/env.example` holds local placeholders only; it is named without a leading dot
because `.env*` files are git-ignored.

### 6.5 Platforms not tested

All commands were executed on Linux/aarch64 with Python 3.10.12; the release checks and both
Python test suites were also run with Python 3.12.16 (`REPRODUCIBILITY_REPORT.md`). x86-64 Linux
and macOS are expected to work with the same commands (all dependencies publish wheels for
them) but were not executed for this release. On Windows, the shell syntax (`set -a; . file`,
`&`, `kill`) differs and the commands are untested.

## 7. Methodology

### 7.1 Scientific workflow

1. **Estate-structure measurement (§4).** Inventory exports of eight estates are reduced and
   characterised (Section 7.2); the results (Tables 2–7, Figure 1) set the redundancy the
   service can exploit and the normalisation it must survive.
2. **Per-item decision procedure (§5).** For each (product, version): retrieve candidate
   advisories, recover each advisory's affected-version constraint, establish product
   identity and applicability, compare the version, and emit one of four verdicts.
3. **Redundancy-aware planning (§6).** Reduce the estate to unique items, group items by
   product, prepare once per group, decide per version, and fan the verdicts back to endpoints.
4. **Service and continuity (§7).** Submission/retrieval split, admission limits, a durable job
   queue, caches whose keys include the engine identity, background feed maintenance.
5. **Measurement of a deployed system (§8–9).** Phase timing, a compiled concurrent engine,
   scaling, model placement on CPU versus GPU, throughput, latency, verdict preservation. These
   measurements were taken on the deployed system and are not reproducible from this package
   (Section 10).

### 7.2 Data preprocessing and inventory reduction (§4.1, §6.1)

Rows flagged deleted or without a product name are dropped; versionless rows are counted and
dropped as unscannable; the remaining rows are merged on (normalised product, normalised
version), folded by OS family only when that column exists — so the reported reduction is an
upper bound (manuscript §4.1). Two-level redundancy: R scannable rows, U distinct items,
G distinct products; ρ_item = R/U, ρ_group = U/G, reduction = 1 − U/R; pooled values sum over
estates without cross-estate de-duplication. Version spread: products with more than one
version. Fan-out: rows merged into each item (percentiles by linear interpolation, head shares
of the top 1/5/10 % of items, singleton share, concentration curve). Lexical features: eight
overlapping regular-expression classes per distinct product name. CPE route: four cumulative
normalisation tiers looked up against an index of dictionary titles and product tokens;
optional stage 2 intersects with a version-bounded set. Code: `reproducibility/analysis/`.
The service-side reduction (§6.1) uses the merge key (product, version, OS family), adopts the
vendor by majority and keeps every endpoint list for fan-back:
`refimpl/planning/estate_reduction.py`.

### 7.3 Version-constraint extraction (§5.1)

A BiLSTM-CRF sequence tagger with a character sub-encoder labels product and version spans in
advisory prose (`refimpl/extraction/architecture.py`; training with BIO labels aligned by fuzzy
matching, `refimpl/training/`). The model only emits spans: comparison operators (`before`,
`through`, `prior to`, ranges …) are attached by closed-class rules
(`refimpl/extraction/extractor.py::_extract_version_info`, `constraints.py`), and the model never
emits a verdict. Rule-based and regex layers act as fallbacks. Results are cached per advisory
by (text digest, model identity) (`refimpl/extraction_cache.py`).

### 7.4 Product matching (§5.1)

Inventory names are cleaned and normalised; candidates are retrieved by two arms that are
always merged — structural product/vendor fields and full text over descriptions — filtered,
scored and ranked deterministically (`refimpl/search.py`, `corpus.py`). Matching uses token
overlap, substring, sequence ratio and Levenshtein distance with catalog-first and
extracted-name fallback (`refimpl/fuzzy/`), vendor resolution (`vendors.py`), disambiguation of
generic names (`disambiguation.py`) and product identity checks (`identity.py`).

### 7.5 Version-range adjudication and applicability (§5.1)

Applicability gates reject or demote candidates whose OS family, platform, plugin host,
vendor, language binding, suite component or OS-as-product reading does not fit the item
(`refimpl/applicability.py`, `scanner.py::_apply_gates`). The installed version is compared with
the constraint under explicit boundary semantics (`<` vs `<=`, build-number containment,
degenerate ranges, branch selection, exact-version lists with `defaultStatus`) in
`refimpl/versioning/`; structural bounds from the advisory record take precedence over bounds
recovered from text (`scanner.py::_resolve_with_structured_bounds`). A final policy gate
(`refimpl/policy.py`) checks a THREAT before publication; the final status rule
(`scanner.py::_finalize_status`) yields THREAT, SAFE, UNCERTAIN or NOT_FOUND.

### 7.6 Group-level sharing with per-version verdicts (§6.2)

The planner (`refimpl/planning/planner.py`) keeps two mappings: a de-duplication key with the
version and a product key without it. Version-invariant preparation (name cleaning, vendor,
retrieval, structural bounds) runs once per product group (`scanner.py::_prepare`); each version
is then decided separately (`_decide`), so sharing never changes a verdict. Copied results are
marked (`"cached": true` / `copied: true`).

### 7.7 Caching (§7)

Verdict cache keyed by (product, version, scope, engine identity) with TTL and conservative purge
(`service_tier/storage/cache.py`); engine identity = model digest + binary digest, so a model or
engine change invalidates cached verdicts (`refimpl/engine_identity.py`,
`compiled_engine/goscan/main.go`). Extraction cache keyed by advisory-text digest + model id
(`refimpl/extraction_cache.py`, `service_tier/storage/extractions.py`).

### 7.8 Engine placement (§8–9)

The released Go source is the concurrent engine (worker pool over product groups,
prepare-once/decide-per-version) with phase timing and ONNX inference plus host-side Viterbi on
the CPU (`compiled_engine/goscan/scan.go`, `timing.go`, `model.go`); its Python mirror is
`refimpl/export/`. The decoding-equivalence check (Section 5.3 d) and the parity comparator
(`refimpl/evaluation/parity.py`) are the released verification procedures. The placement
measurements themselves (CPU versus GPU, core counts, appliance versus server) are §9 results of
the deployed system and are not reproducible here.

### 7.9 Where to look further

Claim-by-claim mapping with line references and tests: [`CLAIM_TO_CODE_MATRIX.md`](CLAIM_TO_CODE_MATRIX.md).
File origin, every code edit and the synthetic substitutions:
[`reference_implementation/MAPPING.md`](reference_implementation/MAPPING.md). Operator
reproduction of Section 4: [`reproducibility/docs/reproduction.md`](reproducibility/docs/reproduction.md).

## 8. Citations

If you use this code or data, please cite the article and the archived software release.
`CITATION.cff` holds the machine-readable metadata (GitHub's "Cite this repository" reads it).

**Article** (under review; update with the final reference when published):

> Kocaoğlu, R., & Bakırcı, B. (2026). Learning-assisted exposure assessment at estate scale:
> Constraint recovery, inventory redundancy, and engine placement in managed enterprise
> networks. *PeerJ Computer Science* (submitted, manuscript CS-2026:09:148327).

**Software and data:**

> Kocaoğlu, R., & Bakırcı, B. (2026). *PeerjNetworkPaper: research reference implementation and
> reproducibility package* (Version 1.1.1) [Computer software]. Zenodo.
> https://doi.org/10.5281/zenodo.23122100

The concept DOI above always resolves to the latest archived version. Version DOIs:
v1.0.0 = <https://doi.org/10.5281/zenodo.23122101>, v1.1.0 = <https://doi.org/10.5281/zenodo.23840722>;
the v1.1.1 version DOI is assigned by Zenodo when that version is archived.

**Public data sources and standards used in the research**, as cited in the manuscript (full
bibliography: `paper/latex/references.bib`): the CVE Program's cvelistV5 records; the NIST
National Vulnerability Database and its CPE dictionary; OSV; the CISA Known Exploited
Vulnerabilities catalog; FIRST EPSS and CVSS; endoflife.date; ONNX. Software dependencies
(PyTorch, `pytorch-crf`, ONNX Runtime, FastAPI, PostgreSQL, pgx, onnxruntime_go) are used under
their own licences and are listed in Section 6.

## 9. License and Contribution Guidelines

### 9.1 Licences by component

| Component | Licence | Licence files |
|---|---|---|
| `reproducibility/` (Section 4 analysis scripts, release verification, figure regeneration, and the aggregate, figure and synthetic data in it) and the repository-level documentation | MIT License, as released in v1.0.0 | `LICENSE`, `reproducibility/LICENSE` |
| `reference_implementation/` (Python reference implementation, Go engine source, service tier, their tests and the synthetic data in `reference_implementation/example_data/`) | PolyForm Noncommercial License 1.0.0 (SPDX `PolyForm-Noncommercial-1.0.0`) | `reference_implementation/LICENSE`, `reference_implementation/NOTICE` |
| `paper/` (manuscript text, figures, tables) | Neither software licence. The article is published under **CC BY 4.0**, as selected in the PeerJ submission system. `paper/latex/wlpeerj.cls` is the third-party PeerJ template class under its own terms | — |

The **MIT License** permits anyone, including for commercial purposes, to use, modify and
redistribute the covered code, provided the copyright and licence notice are retained. The
**PolyForm Noncommercial License 1.0.0** permits use, modification and redistribution for
noncommercial purposes, including scientific review, research and teaching; commercial use
requires a separate licence from the copyright holder. It is a source-available licence, not
an OSI-approved open-source licence. The software licences do not cover the article, and
CC BY 4.0 does not cover the code.

### 9.2 Copyright

Copyright holder of the code: Rakort Information Technology (legal name: Rakort Bilgi ve
İletişim Teknolojileri Ltd. Şti.), Ankara, Turkey; `reference_implementation/NOTICE` carries the
required notice. The MIT licence files (`LICENSE`, `reproducibility/LICENSE`) are kept exactly as
published in v1.0.0; their copyright line names the holder as "Rakort Bilgi Teknoloji A.Ş.",
which refers to the same company. The MIT permissions granted in v1.0.0 are unchanged. The
scientific authors are Ramazan Kocaoğlu and Basma Bakırcı. No third-party source code is
included; dependencies are installed from PyPI and the Go module proxy under their own licences.

### 9.3 Contributions

This is a static research artefact accompanying one manuscript, not a maintained software
project. Questions and corrections are welcome as GitHub issues or pull requests at
<https://github.com/RakortAcademy/PeerjNetworkPaper>, or by e-mail to the corresponding author.
Contributions to `reference_implementation/` are accepted under its PolyForm Noncommercial
licence and to the rest under MIT. Changes to the released aggregate data are accepted only
when regenerated by the authors from the restricted exports, never by hand-editing values.
Never submit inventory exports, credentials or model weights (`reproducibility/scan_sensitive.py`
checks a tree for them).

## 10. What can and cannot be reproduced

Three classes: **A** — algorithms a reviewer can execute and test; **B** — results reproducible
from the included synthetic inputs; **C** — historical measurements that need restricted data or
infrastructure.

| Class | Result | Status |
|---|---|---|
| A | §5–6 mechanisms (decision procedure, gates, constraint recovery, reduction, grouping, fan-back, per-version decisions, cache key discipline) | **Runnable** on synthetic data (5.3) |
| A | §7 mechanisms (queue durability, resumption, copy marking, cache coherence, store-side paging) | **Runnable** on a local PostgreSQL (5.4) |
| A | §9 procedures (decoding equivalence, parity comparison, restart recovery) | **Runnable** on synthetic inputs; the reported instances are not |
| B | Example outputs of 5.3 and 5.6 (verdict counts, reduction and fan-back, 132/132 decoding equivalence, golden-set confusion, Section 4 smoke test) | **Reproducible** from the synthetic inputs; illustrative only, not manuscript values |
| B | Table 19 projections | **Recomputable by hand** from Table 3 and the rates stated in the manuscript (no script is provided) |
| C | Tables 2–6, Figure 1, §4.1 aggregates | **Check-only**: the pipeline runs on synthetic or your own export; the published values need the confidential exports and are checked for internal consistency |
| C | Figure 6; Figure 7(b) medians | **Check-only**: redrawn from released medians; run-to-run and per-bucket spread not released |
| C | Table 7 | **Not reproducible**: confidential exports, 3 Aug 2026 dictionary state and measurement code unavailable |
| C | Tables 8–18, Figures 2–5, Figure 7(a), every §5–9 timing, throughput, latency, footprint, end-to-end and parity value | **Not reproducible**: measured on the deployed system with the unreleased weights, corpus snapshot, inventories, index build and harnesses |

**Restricted components** (not in this repository):

| Not included | Needed for | Why |
|---|---|---|
| Raw inventory exports of the eight study estates; the 1,443-item / 6,129-row end-to-end and 146-item inventories | Per-estate values; end-to-end scans | Confidential third-party data (Section 3.4) |
| Trained production tagger (8.8M parameters), its dictionaries and training corpus | Any inference matching the manuscript; Tables 15–16; CPU-vs-GPU; verdict preservation | Proprietary; the corpus is derived from the production advisory store |
| Deployed engine build with the in-memory candidate index and start-up equivalence self-check | Table 14; §9 "Taking the Store Off the Hot Path" | Post-dates the 1 August 2026 snapshot |
| Repetition, latency-distribution (N = 200) and CPU-counter harnesses | Tables 11, 17–18; Figures 6–7 raw runs | Part of the deployed service |
| Item-metered allowance (§7.3); per-feed refresh scheduler (§7.6) | §7 admission and feed-maintenance claims | Post-date the snapshot |
| Advisory corpus snapshot (seven feeds, Table 9; 3 Aug 2026) and Table 7 stage-2 corpus | End-to-end runs with real advisories | The populated store is not released; the feeds themselves are public |
| CPE dictionary state of 3 Aug 2026 | Exact Table 7 key counts | Not recoverable (one key drifted) |
| Feed acquisition modules, management panel, the rest of the admin router, the corpus-store module, deployment units, TLS material, credentials | — | Data acquisition / operator console / secrets; not part of the method (the corpus-store queries are reproduced in memory by `refimpl/corpus.py`) |

**Known paper–code differences** (`CLAIM_TO_CODE_MATRIX.md`, "Paper–code inconsistencies"): the
Go source has no language-binding gate, so the two released engines are not in full verdict
parity; the in-memory candidate index, the item-metered allowance and per-feed scheduling are
described in the manuscript but are not in this snapshot. Row-by-row status of every reported
number: `CLAIM_TO_CODE_MATRIX.md`, Part B. Per component: `CODE_AVAILABILITY.md`; per dataset:
`DATA_AVAILABILITY.md`.

## 11. Verification record

Every command of Section 5 was executed in a clean environment (empty home directory, fresh
PyPI virtual environment, empty Go module cache, the shipped PostgreSQL container) on the
v1.1.1 release-candidate archive, and repeated on the final v1.1.1 archive (the report's Section 2
states how the two differ). Environment, commands, full outputs, expected versus observed results and
deviations: [`REPRODUCIBILITY_REPORT.md`](REPRODUCIBILITY_REPORT.md).

| Step | Result |
|---|---|
| `verify_release.py`; `scan_sensitive.py` | 27 passed, 0 failed, 7 not tested / not reproducible; 0 findings |
| `generate_synthetic.py` | five files regenerated byte-identically |
| `python -m pytest` (reference implementation) | 389 passed, 1 skipped (passes with a trained checkpoint) |
| Example (5.3 b–e) | pipeline output as in 5.3; 132/132 identical decodings (ONNX and host-side Viterbi); `test_tagger.py` 9 passed |
| Service tier without / with PostgreSQL | 60 passed, 8 skipped / 68 passed |
| HTTP round trip; load test (300 items) | health ok; job DONE 3/3; duplicate served from cache; 300/300, 0 errors |
| Go `vet`, `test`, `build` | clean; tests pass; builds |

## 12. Versions

| Version | Content |
|---|---|
| v1.0.0 (2026-10-03; commit `b51f048`; DOI [10.5281/zenodo.23122101](https://doi.org/10.5281/zenodo.23122101)) | Manuscript as originally submitted; Section 4 scripts, released aggregates and figure datapoints; verification tooling |
| v1.1.0 (2026-10-31; commit `106eee0`; DOI [10.5281/zenodo.23840722](https://doi.org/10.5281/zenodo.23840722)) | Adds `reference_implementation/` (decision method, Go engine source, service tier) and `CLAIM_TO_CODE_MATRIX.md`; revised manuscript |
| **v1.1.1** (this version; version DOI assigned by Zenodo when archived) | Documentation release for PeerJ's second technical check: README reorganised under the PeerJ README items; `REPRODUCIBILITY_REPORT.md` added; DOI, version and licence statements aligned across the documents; manuscript revision M43 (Data Availability points to the README and the report). No code, data or scientific result changed (`RELEASE_NOTES.md`) |

Details of every change: [`RELEASE_NOTES.md`](RELEASE_NOTES.md).

## 13. Generative AI use

The reproducibility scripts, verification and figure tooling and the documentation were
prepared with the assistance of Claude Code (Anthropic; https://claude.com/claude-code;
command-line tool; version 2.1.316 at the time of the v1.1.0 release and the M42 manuscript
revision, and the version recorded in `REPRODUCIBILITY_REPORT.md` for this v1.1.1
documentation revision; earlier versions of the same tool were used during development),
including rerunning the authors' analysis scripts on the study exports and checking the
regenerated outputs against the original analysis and the manuscript, and preparing
`reference_implementation/` from the authors' research code (rewriting imports, replacing
production couplings with in-process providers, removing internal identifiers, writing its
tests and documentation; `reference_implementation/MAPPING.md` lists the code edits file by file
and the substituted content by category), and, for v1.1.1, reorganising this README, executing
its commands in a clean environment and writing the reproducibility report. The experimental
design, analysis definitions, measurements and conclusions are the authors' own; the authors
reviewed all AI-assisted material and take responsibility for it. The full disclosure for the
manuscript, which also covers language editing and LaTeX formatting, is its "Declaration of
Generative AI Use" (`paper/latex/main.tex`).
