# Learning-Assisted Exposure Assessment at Estate Scale — research reference implementation and reproducibility package

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23122100.svg)](https://doi.org/10.5281/zenodo.23122100)

> **Learning-Assisted Exposure Assessment at Estate Scale: Constraint Recovery,
> Inventory Redundancy, and Engine Placement in Managed Enterprise Networks**
> Ramazan Kocaoğlu, Basma Bakırcı — Department of Computer Engineering, Ostim
> Technical University, Ankara, Turkey.
> Submitted to *PeerJ Computer Science* (article type: AI Application).

**Version.** v1.1.0 (adds `reference_implementation/`; see `RELEASE_NOTES.md`). The DOI badge
above is the concept DOI, which resolves to the latest archived version; v1.0.0, which does not
contain `reference_implementation/`, is https://doi.org/10.5281/zenodo.23122101.

## 1. What this repository is

**Research problem.** An enterprise software inventory lists every installed
application on every endpoint. Deciding, for each (product, version), whether a
published vulnerability advisory applies requires (a) matching an inventory name to
the advisory's product, (b) recovering the affected-version constraint — often only
present in free text — and (c) comparing the installed version against it. The
manuscript studies how redundant real inventories are (Section 4), describes a
decision method that combines rule-based applicability gates and interval comparison
with a learned sequence tagger that recovers version constraints from advisory text
(Sections 5–6), the service around it (Section 7), and measures a deployed system
(Sections 8–9).

**What is here.**

| Part | Manuscript | What it is |
|---|---|---|
| `reference_implementation/` | §5–7 | The authors' research code of the decision method (Python reference engine, BiLSTM-CRF tagger, constraint recovery, gates, interval comparison, inventory reduction, grouping, caches, evaluation gates), the Go source of the compiled engine, and the service tier (API, job queue, caches) — from the research snapshot of 1 August 2026, with production couplings replaced by in-process or local providers. Runs end to end on **synthetic** data. |
| `reproducibility/` | §4 | The four scripts behind the estate-structure study (Tables 2–7, Figure 1), the derived aggregate values they produced on the eight study estates, plotted datapoints of Figures 1, 6, 7, synthetic inputs, figure regeneration and release verification. |
| `paper/` | — | Manuscript PDF and LaTeX source. |

**What it is not.** It is not the deployed production system and it regenerates **no
Section 8–9 measurement** (Tables 8–19, Figures 2–7). The trained 8.8M-parameter
tagger weights, the deployed engine build with its in-memory candidate index, two
post-snapshot service features, the measurement harnesses, the advisory corpus snapshot
and all customer inventories are not included ([§9](#9-restricted-components)). The
Python and Go engines released here are **not in full verdict parity** (the Go source
lacks the language-binding gate; [§7](#7-where-each-method-is-implemented)).

**Synthetic throughout.** Every product name, version, advisory and endpoint in the
data, tests and rule knowledge base is fictional. The curated tables that the deployed
system fills with verified product pairs (`refimpl/identity.py` and its Go twin
`policy.go`) hold fictional entries here, so they demonstrate the mechanism but do not
encode real-world product knowledge; public lexicons the gates need (operating-system
names, common words, vendor aliases) are kept. Details: `reference_implementation/MAPPING.md`,
"Synthetic substitution".

```
.
├── README.md                     ← this file (single entry point)
├── CLAIM_TO_CODE_MATRIX.md       ← every §5–9 claim → code + test; every reported result → reproducibility status
├── CODE_AVAILABILITY.md          ← PeerJ code-availability statement: public / not released, per component
├── DATA_AVAILABILITY.md          ← PeerJ data-availability statement: public / restricted / not included
├── RELEASE_NOTES.md
├── CITATION.cff · LICENSE (MIT; see §14 for the per-component licences)
├── paper/                        ← PeerJ_Manuscript.pdf; latex/ (main.tex, figures/, tables/, references.bib, wlpeerj.cls)
├── reference_implementation/
│   ├── LICENSE · NOTICE          ← PolyForm Noncommercial 1.0.0 for this directory
│   ├── MAPPING.md                ← file-by-file origin, code edits file by file, substituted content by category, status (cited by the manuscript)
│   ├── refimpl/                  ← Python decision method (scanner, extraction/, versioning/, fuzzy/, planning/, training/, export/, evaluation/)
│   ├── tests/                    ← 390 tests
│   ├── examples/run_pipeline.py  ← end-to-end reviewer example
│   ├── example_data/             ← synthetic corpus, inventory, training, golden data + generate_synthetic.py
│   ├── service_tier/             ← §7 API, queue, worker, caches, migrations, engine shim, load test; 68 tests
│   └── compiled_engine/goscan/   ← Go engine source; README.md: design, parity method, known differences; 15 tests
└── reproducibility/
    ├── analysis/                 ← common.py, estate_structure.py, lexical_features.py, cpe_route.py
    ├── aggregate_data/           ← released values of Tables 2–7 (CSV)
    ├── figure_data/              ← released datapoints of Figures 1, 6, 7 (CSV)
    ├── example_data/             ← synthetic estate export; synthetic CPE dictionary + corpus (cpe/)
    ├── reproduce_figures.py · verify_release.py · scan_sensitive.py
    └── environment/requirements.txt
```

## 2. Installation (one environment for everything)

Requirements: Python ≥ 3.10, network access for `pip` only. Optional: a PostgreSQL
≥ 14 you own (a container is enough) for the service tier's end-to-end tests; Go (the
toolchain version is in `go.mod`, fetched automatically with `GOTOOLCHAIN=auto`) for the
Go unit tests. No GPU, company network, credentials, database dump or model checkpoint
is needed.

```bash
git clone --branch v1.1.0 https://github.com/RakortAcademy/PeerjNetworkPaper.git
cd PeerjNetworkPaper
# or, from the archive supplied with the manuscript: unzip it and cd into the extracted folder
python3 -m venv .venv && . .venv/bin/activate
python -m pip install -U pip wheel
pip install -r reference_implementation/requirements.txt \
            -r reference_implementation/service_tier/requirements.txt \
            -r reproducibility/environment/requirements.txt
```

This installs `torch` (CPU is enough), `pytorch-crf`, `numpy<2`, `snowballstemmer`,
`onnx`, `onnxruntime`, `pytest`, `fastapi`, `uvicorn`, `pydantic`, `psycopg2-binary`,
`httpx`, `openpyxl`, `matplotlib`. On a platform with a vendor-built torch (e.g. NVIDIA
Jetson), create the venv with `--system-site-packages` and omit torch from the install.
With torch ≥ 2.9 the ONNX export requests the TorchScript exporter explicitly
(`dynamo=False`), so `onnxscript` is not needed; verified with torch 2.5 and 2.14.

Commands below are run from the repository root unless a `cd` says otherwise.

## 3. Run the decision method on synthetic data (§5–6)

All data used here is fictional (products such as "Acme Ledgerly Server", advisories
`CVE-2099-xxxx`, endpoints 1001–1007), generated deterministically by
`reference_implementation/example_data/generate_synthetic.py` (re-running it rewrites the
five files byte-identically).

```bash
cd reference_implementation
python -m pytest                       # expected: 389 passed, 1 skipped (the skipped test needs a trained checkpoint, step 3.4)
```

The suite covers version algebra and boundary semantics, constraint-recovery rules,
product normalisation and matching, applicability gates, the full decision procedure on
the synthetic corpus, inventory reduction and fan-back, request-level grouping, the
extraction-cache key discipline, model construction / forward / CRF loss / decode, the
host-side Viterbi against `torchcrf`, ONNX export equivalence, golden-set metrics, the
parity comparator and the promotion gate. No test needs a network, database or GPU.

### 3.1 Train a small tagger (about 2 min on a CPU; seeded)

```bash
python -m refimpl.training.train --data example_data/synthetic_training.jsonl \
    --output example_data/tiny_model --epochs 40 --patience 6 --batch-size 32 --max-len 64 \
    --embedding-dim 24 --char-embedding-dim 12 --char-hidden-dim 12 --word-hidden-dim 32 \
    --min-word-freq 1 --workers 0 --label-workers 1 --device cpu
# ends with "Test — precision … | recall … | F1 …" (log messages are in Turkish, as in the original code)
```

Same architecture as the manuscript's model (BiLSTM-CRF with a character sub-encoder),
about 28k parameters instead of 8.8M. It is illustrative; its extractions are not the
production model's. `example_data/tiny_model/` is git-ignored output.

### 3.2 The pipeline end to end

```bash
python examples/run_pipeline.py --model example_data/tiny_model --out out/
```

Expected (verdict counts are fixed by the deterministic rules on the synthetic corpus;
the tagger's extracted spans may vary slightly between training runs). The example
yields no UNCERTAIN item: `Notes 4.13` is attributed to Apple from its macOS context and,
with no matching advisory, is NOT_FOUND; the same name without vendor or OS context is
UNCERTAIN (`tests/test_engine_synthetic.py::test_generic_name_without_vendor_is_uncertain`):

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
| 1 estate reduction | Inventory normalisation and de-duplication: 25 endpoint rows → 16 (product, version, OS family) items; versionless and nameless rows dropped; endpoint lists kept (§6.1) | `refimpl/planning/estate_reduction.py` | `estate_reduction.json` |
| 2 planner | Request-level grouping: items grouped by product so that preparation runs once per product group (§6.2) | `refimpl/planning/planner.py` | `plan.json` |
| 3 prepare | Candidate retrieval (structural arm + full-text arm), structural bounds, product identity | `refimpl/scanner.py::_prepare`, `refimpl/search.py`, `refimpl/corpus.py` | `prepare_NN.json` |
| 4 extraction | Tagger spans → constraint by closed-class operator rules; extraction cache keyed by text digest + model id (§5.1, §7) | `refimpl/extraction/`, `refimpl/extraction_cache.py` | `extraction.json` |
| 5 decide | Per-version decision: applicability gates, interval comparison, structural-over-text precedence, policy gate; THREAT / SAFE / UNCERTAIN / NOT_FOUND | `refimpl/scanner.py::_decide`, `_apply_gates`, `_finalize_status`; `refimpl/policy.py` | `decisions.json` |
| 6 results | One verdict per item, in submitted order; each version of a product keeps its own decision | `examples/run_pipeline.py` | `results.json` |
| 7 fan-back | Item verdicts mapped back to every endpoint row (§6.1) | `estate_reduction.py::fan_back` | `fan_back.json` |

**Modify the inputs.** `--inventory` and `--corpus` accept edited copies of
`example_data/synthetic_inventory_rows.json` (rows: `[endpoint_id, name, version, vendor,
architecture, os_text, os_type]`) and `example_data/synthetic_corpus.jsonl`. For example,
changing the two `Acme Ledgerly Server` `2.3.9` rows (Windows Server) to `2.4.1`, the
fixed version of `CVE-2099-0001`, turns that item from THREAT into SAFE (step 6:
`{'THREAT': 8, 'SAFE': 5, 'NOT_FOUND': 3}`) while every other item keeps its verdict. It
stays a separate item from endpoint 1004's `ACME LEDGERLY SERVER 2.4.1` because the
reduction key includes the OS family (Ubuntu there); give both rows the same OS and
they merge into one item.

### 3.3 ONNX export and decoding equivalence (§9 procedure)

```bash
python -m refimpl.export.export_onnx --checkpoint example_data/tiny_model/bilstm_crf.pth \
    --out example_data/tiny_model/onnx --verify-texts example_data/synthetic_verify_texts.txt
# expected: "132/132 cümlede etiket dizisi AYNI" (identical label sequences) for the ONNX path and for the host-side Viterbi
```

### 3.4 Golden-set metrics and the trained-tagger test

```bash
python -m refimpl.evaluation.golden_metrics --golden example_data/synthetic_golden.jsonl \
    --corpus example_data/synthetic_corpus.jsonl --model example_data/tiny_model
REFIMPL_MODEL_PATH=example_data/tiny_model python -m pytest tests/test_tagger.py    # expected: 9 passed
cd ..
```

## 4. Run the service tier locally (§7)

The research snapshot's service tier: HTTP API with submission/retrieval split and a
blocking variant with an item cap, API-key authentication, durable job queue
(`FOR UPDATE SKIP LOCKED` claim, per-group persistence, derived resumption, requeue
attempt cap), verdict cache keyed by (product, version, scope, engine identity),
extraction-cache table, store-side pagination of findings, engine client without
fallback (503), feed scheduler (one global interval), proxy limits
(`deploy/nginx.example.conf`) and the 300-item load-test harness. An **engine shim**
serves the Python reference engine over the compiled engine's `/health` + `/scan`
contract, so nothing beyond a local PostgreSQL is needed. Comments and log messages are
in Turkish, as in the original.

```bash
cd reference_implementation
python -m pytest service_tier/tests                     # expected: 60 passed, 8 skipped (no database needed)

# query the decision method without a database: the shim alone answers POST /scan
# (one item as the body, or {"items": [...]}); omit --model to run without the tagger
python -m service_tier.tools.engine_shim --addr 127.0.0.1:8390 --model example_data/tiny_model
curl -s -X POST localhost:8390/scan -d '{"product":"Acme Ledgerly Server","version":"2.3.9","vendor":"Acme"}'
# -> "status": "THREAT", threats[0].cve_id "CVE-2099-0001", reason "Version 2.3.9 < 2.4.1 (exclusive)";
#    2.4.1 -> SAFE; "Notes" without vendor/OS -> UNCERTAIN; an unknown product -> NOT_FOUND;
#    a missing or empty product/version -> 422. Every result has decision_summary.summary.

# end-to-end, with a PostgreSQL you own (any ≥ 14; this is one way):
docker compose -f service_tier/docker-compose.example.yml up -d
set -a; . service_tier/env.example; set +a              # PG*, API_KEYS, ADMIN_TOKEN, GOSCAN_URL — local placeholders only
SERVICE_TIER_E2E=1 python -m pytest service_tier/tests  # expected: 68 passed (TRUNCATES the job/cache tables of that database)
```

The 8 end-to-end tests cover migrations, exclusive claim across threads, queue → worker →
results with copies marked, restart resumption from stored rows, the requeue attempt
cap, the cache key (scope + engine identity), store-side pagination and a full HTTP round
trip. Interactive use (two terminals, same environment variables; the shim uses the
tagger from §3.1):

```bash
python -m service_tier.tools.engine_shim --addr 127.0.0.1:8390
python -m uvicorn service_tier.backend.main:app --host 127.0.0.1 --port 8000

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
```

The load test is a functional check only: jobs on the synthetic corpus finish before its
first 5 s status poll, so its reported duration is the polling interval, not a
throughput measurement, and is not comparable with any manuscript value. Not in the
snapshot (they post-date it): the item-metered allowance (§7.3) and per-feed refresh
intervals with skip reasons (§7.6). Also not included: the management panel and the
rest of the admin router, the corpus-store module (its queries are reproduced in memory
by `refimpl/corpus.py`) and the feed acquisition modules.

## 5. Compiled engine (Go)

```bash
cd reference_implementation/compiled_engine/goscan
go vet ./... && go test ./...     # expected: vet clean, "ok reference-implementation/compiled-engine" (15 test functions)
go build -o goscan .              # builds; running it needs a populated PostgreSQL corpus and ONNX Runtime, neither included
```

Inspectable source of the concurrent engine (worker pool over product groups,
prepare-once / decide-per-version, ONNX inference with host-side CRF decoding, phase
timing, binary digest as engine identity). It predates the in-memory candidate index of
the measured build: candidate retrieval still queries the store per product group.
`compiled_engine/goscan/README.md` records its design rationale, the parity method and the
known differences from the Python reference. `divergence_test.go` pins the one known divergence from the Python reference
(no language-binding gate). To point the service tier at it, set `GOSCAN_URL` to its
address.

## 6. Section 4 estate-structure analysis

The scripts consume a NAC installed-application export (`.xlsx` or `.csv`, one file per
estate) and regenerate Tables 2–7 and the Figure 1 curve file. They use only the standard
library (plus `openpyxl` for `.xlsx` and `matplotlib` for figures) and read no network
service or database. Run any script with `--help`.

```bash
cd reproducibility
python verify_release.py          # expected: "OK: 0 check(s) failed, 27 passed, 7 not tested / not reproducible"
python scan_sensitive.py          # expected: "0 finding(s)" (credentials, private addresses, absolute paths, weight/office files)
python reproduce_figures.py --out out/figures   # Figure 1, Figure 6, Figure 7(b) partial (PDF + PNG)

# pipeline on the synthetic input (illustrative numbers: 5 endpoints, 12 live rows, 11 scannable rows, 8 items, 7 products)
python analysis/estate_structure.py --dir example_data --out out/
python analysis/lexical_features.py --dir example_data --out out/
python analysis/cpe_route.py --dir example_data \
    --cpe-dictionary example_data/cpe/synthetic_cpe_dictionary.xml \
    --advisory-corpus example_data/cpe/synthetic_advisory_corpus.csv --out out/
cd ..
```

| Script | Produces | § |
|---|---|---|
| `analysis/common.py` | Export reader and the §4.1 reduction (drop deleted / unnamed / versionless rows; merge on normalised product + version, folded by OS family when present). Imported, not run | 4.1 |
| `analysis/estate_structure.py` | Tables 2–5, Figure 1 curve file, §4.1 pre-reduction aggregates | 4.1–4.5 |
| `analysis/lexical_features.py` | Table 6 (eight lexical classes; summed and cross-estate-distinct name counts) | 4.6 |
| `analysis/cpe_route.py` | Table 7 (four cumulative CPE resolution tiers; optional stage-2 version-bounded check; `--include-os/--include-hardware` for the invariance check) | 4.7 |
| `reproduce_figures.py` | Figures 1 and 6 from `figure_data/`; Figure 7(b) medians only, labelled partial | 4.5, 9.6, 9.10 |
| `verify_release.py` | Required files, forbidden content, compilation, CSV schemas, arithmetic consistency of Tables 2–5 and Figure 1 vs Table 5, synthetic smoke test of all three scripts run twice (byte-identical), Figures 1 and 6. `PASS` only for checks that ran and succeeded; `NOT TESTED` where inputs are restricted; `NOT REPRODUCIBLE` where public materials cannot support the result; exit 0 only if nothing failed | — |

**Methodology (§4).** (1) Reduction: drop rows flagged deleted or without a product name;
count and drop versionless rows as unscannable; merge on (normalised product, normalised
version), folded by OS family only when that column exists — so the reported reduction
is an upper bound (manuscript §4.1). (2) Version coverage: share of live rows without a
version. (3) Two-level redundancy: R scannable rows, U distinct items, G distinct
products; ρ_item = R/U, ρ_group = U/G, reduction = 1 − U/R; pooled values sum over
estates without cross-estate de-duplication. (4) Version spread: products with more than
one version. (5) Fan-out: rows merged into each item (installations; an item installed
twice on one endpoint counts twice): percentiles (linear interpolation), head shares of
the top 1/5/10 % of items, singleton share, concentration curve. (6) Lexical features:
eight overlapping regular-expression classes per distinct product name. (7) CPE route:
four cumulative normalisation tiers looked up against an index of dictionary titles and
product tokens; optional stage 2 intersects with a version-bounded set.

**Your own export (operator reproduction).** Export each estate's installed-application
table with at least endpoint identifier, product display name, version string and
deletion flag (vendor, architecture, OS family if available; column names are matched by
alias, `COLUMN_ALIASES` in `analysis/common.py`). Name files with a trailing estate
number (`estate3.xlsx` → `E3`; otherwise `E1, E2, …` in file order). Then run the three scripts with `--dir path/to/exports`
(or `--export PATH`, repeatable), plot with `reproduce_figures.py --figure 1
--figure1-data out/figure1_fanout.csv`, and compare with the released tables using
`verify_release.py --operator-exports path/to/exports [--cpe-dictionary PATH]` (tolerance:
half a unit in the last printed digit). An unreadable export is skipped and the exclusion
is written into every output header (one of the nine study exports was, §4.1). Only the
study's eight exports reproduce the released values; another estate yields its own
structure. Raw exports must never be committed (`.gitignore` excludes `*.xlsx`,
`exports/`).

**CPE dictionary for Table 7.** `cpe_route.py` reads the official NVD dictionary XML
(`official-cpe-dictionary_v2.3.xml`, legacy feed at <https://nvd.nist.gov/products/cpe>)
or a flat `cpe23uri,title[,part]` CSV/TSV (`part` ∈ a/o/h; missing = application) — e.g.
the `cpeName` and English `title` fields exported from the NVD Products/CPE API 2.0.
Only non-deprecated application entries are admitted by default. The dictionary is not
bundled (large, changes daily); record its download date and generator timestamp. The
stage-2 row needs a `cpe_product,version_bounded` CSV; the manuscript's corpus is not
released, so that row is reproducible in form only.

**Released data and provenance.** `aggregate_data/*.csv` (Tables 2–7) and
`figure_data/figure1_fanout.csv` (run with `--curve-estates E3,E6,E8,E7
--curve-samples 60`; 60-sample curves plus the Table 5 head-share points) are the
unmodified output of these scripts on the nine study export files (eight estates; the
unreadable ninth recorded in each header) on 2026-10-03, after the scripts were checked
against the original study analysis; no value was typed in from the manuscript.
`figure6_speedup.csv` and `figure7_latency.csv` are production measurements released for
checking only. The vector Figure 7(a) additionally draws the 200 latency values of the
distribution as plotted points, recoverable at plotting precision; they are plot
coordinates, not the original measurement records, and are not distributed as a dataset. Table 7's published values were measured on 3–4 August 2026 against the
production service's product dictionary (full NVD Products/CPE API 2.0 acquisition of 3
August 2026, keyed by normalised product name; 43,706 and 138,158 distinct
non-deprecated keys); neither that table nor the measurement code is released, and a
reconstruction from the current table gives 43,706 and 138,159 (one entry's deprecation
state changed). `cpe_route.py` is a documented re-implementation of the §4.7 procedure on
the public dictionary, exercised here on a synthetic dictionary only.

## 7. Where each method is implemented

Paths under `reference_implementation/`. Line-level references and the test for every
claim: `CLAIM_TO_CODE_MATRIX.md`. File origins and edits: `reference_implementation/MAPPING.md`.

| Manuscript | Method | Code |
|---|---|---|
| §5.1 | Per-item decision procedure: prepare (per product) / decide (per version); four verdicts; final status rule; policy gate | `refimpl/scanner.py` (`_prepare`, `_decide`, `_apply_gates`, `_finalize_status`), `refimpl/policy.py`, `refimpl/rationale.py` |
| §5.1 | Product and version extraction: BiLSTM-CRF with character sub-encoder; training with BIO alignment | `refimpl/extraction/architecture.py`, `refimpl/training/` |
| §5.1 | Constraint recovery: model emits spans, operators come from closed-class rules | `refimpl/extraction/extractor.py` (`_extract_version_info`), `refimpl/extraction/constraints.py` |
| §5.1 | Product matching and identity; applicability gates (OS family, platform, plugin, vendor, language binding, suite component, OS-as-product, common-word identity) | `refimpl/fuzzy/`, `refimpl/disambiguation.py`, `refimpl/identity.py`, `refimpl/applicability.py`, `refimpl/vendors.py` |
| §5.1 | Version-constraint comparison and boundary semantics; structural bounds before text | `refimpl/versioning/`, `refimpl/scanner.py` (`_resolve_with_structured_bounds`) |
| §5.1 | Two-arm candidate retrieval over an in-memory corpus reproducing the store's queries | `refimpl/search.py`, `refimpl/corpus.py` |
| §5.1 | Threat prioritisation (KEV / EPSS / CVSS) | `refimpl/prioritization.py` |
| §6.1 | Estate-level reduction (normalisation, de-duplication) and fan-back | `refimpl/planning/estate_reduction.py` |
| §6.2 | Request-level grouping by product; copies marked | `refimpl/planning/planner.py`; `service_tier/backend/services/worker.py` |
| §7 | Extraction cache (text digest + model id); model identity | `refimpl/extraction_cache.py`, `refimpl/engine_identity.py`, `service_tier/storage/extractions.py` |
| §7 | Submission/retrieval split, authentication, summary + paginated findings | `service_tier/backend/routers/`, `service_tier/backend/security.py`, `service_tier/storage/cache.py` |
| §7 | Durable job queue, resumption, failure isolation; verdict cache; engine client (503, no fallback) | `service_tier/storage/jobs.py`, `service_tier/backend/services/` |
| §7 | Proxy limits (20 r/s, 5 r/s, 32 MB) | `service_tier/deploy/nginx.example.conf` |
| §8–9 | Compiled concurrent engine, phase timing, benchmark mode, ONNX + host-side Viterbi | `compiled_engine/goscan/` (`scan.go`, `timing.go`, `main.go`, `model.go`) |
| §9 | Decoding equivalence; engine-parity comparator; golden-set metrics; promotion gate | `refimpl/export/`, `refimpl/evaluation/` |

**Known paper–code differences** (details: `CLAIM_TO_CODE_MATRIX.md`, "Paper–code
inconsistencies"): the Go source has no language-binding gate, so the two released
engines are not in full verdict parity — the parity reported in §9 was measured on the
deployed build; the in-memory candidate index, the
item-metered allowance and per-feed scheduling are described in the manuscript but are
not in this snapshot.

## 8. What can and cannot be reproduced

Three classes: **A** — algorithms a reviewer can execute and test; **B** — results
reproducible from the included synthetic inputs; **C** — historical measurements that
need restricted data or infrastructure.

| Class | Result | Status |
|---|---|---|
| A | §5–6 mechanisms (decision procedure, gates, constraint recovery, reduction, grouping, fan-back, per-version decisions, cache key discipline) | **Runnable** on synthetic data (§3) |
| A | §7 mechanisms (queue durability, resumption, copy marking, cache coherence, store-side paging) | **Runnable** on a local PostgreSQL (§4) |
| A | §9 procedures (decoding equivalence, parity comparison, restart recovery) | **Runnable** on synthetic inputs; the reported instances are not |
| B | The example outputs of §3 and §6 (verdict counts, reduction and fan-back, 132/132 decoding equivalence, golden-set confusion, Section 4 smoke test) | **Reproducible** from the synthetic inputs; illustrative only, not manuscript values |
| B | Table 19 projections | **Reproducible** arithmetic from Table 3 and the stated rates |
| C | Tables 2–6, Figure 1, §4.1 aggregates | **Check-only**: pipeline runs on synthetic or your own export; published values need the confidential exports and are checked for internal consistency |
| C | Figure 6; Figure 7(b) medians | **Check-only**: redrawn from released medians; run-to-run and per-bucket spread not released |
| C | Table 7 | **Not reproducible**: confidential exports, 3 Aug 2026 dictionary state and measurement code unavailable |
| C | Tables 8–18, Figures 2–5, Figure 7(a), every §5–9 timing, throughput, latency, footprint, end-to-end and parity value | **Not reproducible**: measured on the deployed system with the unreleased weights, corpus snapshot, inventories, index build and harnesses |

The reference implementation produces no manuscript value and is not a simulation of
the production system. Row-by-row status of every reported number:
`CLAIM_TO_CODE_MATRIX.md`, Part B.

## 9. Restricted components

| Not in this repository | Needed for | Why |
|---|---|---|
| Raw inventory exports of the eight study estates; the 1,443-item / 6,129-row end-to-end and 146-item inventories | Per-estate values; end-to-end scans | Confidential third-party data (manuscript, Ethics and Data Handling); never released |
| Trained production tagger (8.8M parameters), its dictionaries and training corpus | Any inference matching the manuscript; Tables 15–16; CPU-vs-GPU; verdict preservation | Not part of this release; the corpus is derived from the production advisory store |
| Deployed engine build with the in-memory candidate index and start-up equivalence self-check | Table 14; §9 "Taking the Store Off the Hot Path" | Post-dates the 1 August 2026 snapshot in `compiled_engine/goscan/` |
| Repetition, latency-distribution (N = 200) and CPU-counter harnesses | Tables 11, 17–18; Figures 6–7 raw runs | Part of the deployed service, not of the snapshot |
| Item-metered allowance (§7.3); per-feed refresh scheduler (§7.6) | §7 admission and feed-maintenance claims | Post-date the snapshot |
| Advisory corpus snapshot (seven feeds, Table 9; snapshot date 3 Aug 2026) and Table 7 stage-2 corpus | End-to-end runs with real advisories | The populated store is not released; the feeds themselves are public |
| CPE dictionary state of 3 Aug 2026 | Exact Table 7 key counts | Not recoverable (one key drifted) |
| Feed acquisition modules, management panel, deployment units, TLS material, credentials | — | Data acquisition / operator console / secrets; not part of the method |

Per-component availability: `CODE_AVAILABILITY.md`; per-dataset: `DATA_AVAILABILITY.md`.

## 10. Verification record

Latest run (2026-10-30, after the synthetic substitution of fixtures, rule knowledge base
and synthetic data): Linux/aarch64, 12 cores, no GPU, CPython 3.10.12 in a virtual
environment over the platform's vendor torch 2.5 build (`--system-site-packages`), Go
1.25.0, PostgreSQL 17 from `docker-compose.example.yml`. An earlier run of the same day in
a fresh PyPI environment (torch 2.14.1, empty Go module cache) gave the same results on
the pre-substitution code. A clean-room run on the current tree (2026-10-31: fresh PyPI
environment, empty HOME and Go module cache, shipped PostgreSQL container) reproduced every
result below; the 300-item load test also completed 300/300 with 0 errors. After that run,
development-time profiling figures were removed from code comments (comment text only; the
Python syntax trees and the Go code outside comments are unchanged), and the supplemental
archive built from this tree was re-checked with `verify_release.py`, `scan_sensitive.py`
and the reference implementation's tests.

| Step | Result |
|---|---|
| `verify_release.py`; `scan_sensitive.py` | 27 passed, 0 failed, 7 not tested / not reproducible; 0 findings |
| `generate_synthetic.py` | five files regenerated (training data unchanged) |
| `python -m pytest` (reference implementation) | 389 passed, 1 skipped (passes with a trained checkpoint, §3.4) |
| Reviewer example | test F1 1.000 on 221 entities; pipeline output as in §3.2; 132/132 identical decodings (ONNX and host-side Viterbi); golden-set confusion all on the diagonal; `test_tagger.py` 9 passed |
| Service tier without / with PostgreSQL | 60 passed, 8 skipped / 68 passed |
| HTTP round trip (shim, API, queue, cache); load test (300 items) | health ok; job DONE 3/3; duplicate served from cache; load test 300/300, 0 errors, all four verdicts present |
| Go `vet`, `test`, `build` | clean; 15 tests pass; builds |

## 11. Data provenance

The analysed data are software-inventory exports from **eight production enterprise
deployments of a commercial network access control (NAC) platform**, obtained during
integration projects and used with the operators' consent (manuscript §4.1, Ethics and
Data Handling). Each export is a dump of the platform's installed-application table:
opaque numeric endpoint identifier, product display name, version string, vendor string,
architecture marker, deletion flag. A ninth export was unreadable and is excluded. No
organisation is named; estates carry arbitrary labels (E1, E3–E9). The exports were
analysed on infrastructure operated by the organisations and the authors' institution /
company; only derived aggregate statistics leave that boundary.

## 12. Versions

| Version | Content |
|---|---|
| v1.0.0 (2026-10-03; commit `b51f048`; DOI [10.5281/zenodo.23122101](https://doi.org/10.5281/zenodo.23122101)) | Manuscript as originally submitted; Section 4 scripts, released aggregates and figure datapoints; verification tooling |
| v1.1.0 (version DOI assigned by Zenodo on publication; see the concept DOI) | Adds `reference_implementation/` (decision method, Go engine source, service tier) and `CLAIM_TO_CODE_MATRIX.md`; revised manuscript in `paper/` (Funding, Competing Interests, Data Availability and generative-AI statements; values the authors' records do not support corrected or withdrawn: the §5.1 estate-reduction effect is 909 findings, 33,406 → 32,497, not 882; the test count is 486 Python tests plus 13 Go test functions in the 1 August 2026 snapshot, not 498; the appliance end-to-end run, the index speed-up and index-load figures and intra-group slicing are withdrawn, and the remaining indexed run is reported without a speed-up). The v1.0.0 statement that no reference implementation is included is withdrawn |

The concept DOI [10.5281/zenodo.23122100](https://doi.org/10.5281/zenodo.23122100)
resolves to the latest archived release. Source:
<https://github.com/RakortAcademy/PeerjNetworkPaper>. Corresponding author: Ramazan
Kocaoğlu — ramazan.kocaoglu@ostimteknik.edu.tr.

**Manuscript.** `paper/PeerJ_Manuscript.pdf` is built from `paper/latex/main.tex`
(tables in `latex/tables/` via `\input`, vector figures in `latex/figures/`, PeerJ's
unmodified `wlpeerj.cls`). Rebuild with `cd paper/latex && latexmk -pdf main.tex` (needs
a TeX distribution; writes the git-ignored `main.pdf`).

## 13. Generative AI use

The reproducibility scripts, verification and figure tooling and the documentation were
prepared with the assistance of Claude Code (Anthropic), including rerunning the
authors' analysis scripts on the study exports and checking the regenerated outputs
against the original analysis and the manuscript, and preparing `reference_implementation/`
from the authors' research code (rewriting imports, replacing production couplings with
in-process providers, removing internal identifiers, writing its tests and
documentation; `reference_implementation/MAPPING.md` lists the code edits file by file and the substituted content by category). The
experimental design, analysis definitions, measurements and conclusions are the authors'
own; the authors reviewed all AI-assisted material and take responsibility for it.

## 14. Citation, license, contributions

Cite the manuscript and the archived release (`CITATION.cff`; GitHub's "Cite this
repository" reads it). Each Zenodo archive contains this repository at one tag only; none
holds restricted production data.

Licences differ by component:

| Component | Licence | Licence files |
|---|---|---|
| `reproducibility/` (Section 4 analysis scripts, release verification, figure regeneration, and the aggregate, figure and synthetic data in it) and the repository documentation | MIT License, as released in v1.0.0 (that release and its DOI are unchanged) | `LICENSE`, `reproducibility/LICENSE` |
| `reference_implementation/` (Python reference implementation, Go engine source, service tier, their tests and the synthetic data in `reference_implementation/example_data/`) | PolyForm Noncommercial License 1.0.0 (SPDX `PolyForm-Noncommercial-1.0.0`) | `reference_implementation/LICENSE`, `reference_implementation/NOTICE` |
| `paper/` (manuscript text, figures, tables) | Neither software licence; the article's licence is the one stated by PeerJ on publication (the authors have requested CC BY-NC 4.0). `paper/latex/wlpeerj.cls` is the third-party PeerJ/Overleaf template class under its own terms | — |

The **MIT License** permits anyone, including for commercial purposes, to use, modify and
redistribute the covered code, provided the copyright and licence notice are retained.
The **PolyForm Noncommercial License 1.0.0** permits use, modification and redistribution
for noncommercial purposes, including scientific review, research and teaching;
commercial use requires a separate licence from the copyright holder. It is a
source-available licence, not an OSI-approved open-source licence.

Copyright holder of the code: Rakort Bilgi ve İletişim Teknolojileri Ltd. Şti., Ankara, Turkey.
The MIT licence files (`LICENSE`, `reproducibility/LICENSE`) are kept exactly as published in
v1.0.0; their copyright line names the holder as "Rakort Bilgi Teknoloji A.Ş.", which refers to
the same company, whose correct legal name is Rakort Bilgi ve İletişim Teknolojileri Ltd. Şti.
The MIT permissions granted in v1.0.0 are unchanged. The scientific
authors are Ramazan Kocaoğlu and Basma Bakırcı. No third-party source code is included;
dependencies are installed from PyPI and the Go module proxy under their own licences.

This is a static research artefact accompanying one manuscript, not a maintained
software project. Corrections may be proposed by issue or pull request; changes to the
released aggregate data are accepted only when regenerated by the authors from the
restricted exports, never by hand-editing values.
