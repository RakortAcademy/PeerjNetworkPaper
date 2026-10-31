# Manuscript ↔ code mapping

Most source files are taken from the authors' research code (snapshot of 1 August
2026). "Verbatim" means the file's logic is unchanged: imports were rewritten to the
package layout, and the rule knowledge base, code comments and test fixtures were
replaced by synthetic equivalents (see "Synthetic substitution" below). "Seam" edits
replace a production coupling with an in-process provider of the same call shape; the
exact edits are listed below. Locations in the original source tree are not
given. Status values: **RUNNABLE** (exercised by the tests/example),
**INSPECTABLE** (source included under `compiled_engine/goscan/`, unit-tested but not
executable end to end here), **PARTIAL**, **MISSING** (not present in the source
snapshot this package was prepared from; see `../README.md`, "Restricted components"),
**EXCLUDED** (not required for scientific review).

## Sections 5–9 → components

| Manuscript section | Scientific component | Reference implementation | Reviewer runnable? | Status | Notes |
|---|---|---|---|---|---|
| §5.1 pipeline | Per-item decision procedure: prepare (product) / decide (version); four verdicts; final status rule | `refimpl/scanner.py` | yes — `tests/test_engine_synthetic.py`, `examples/run_pipeline.py` | RUNNABLE | 48 changed lines, all seam edits (listed below) |
| §5.1 pipeline | Final policy gate before THREAT (kernel mismatch, line-number constraint, broad range, identity) | `refimpl/policy.py` | yes | RUNNABLE | verbatim |
| §5.1 pipeline | Row explanations and product decision summary | `refimpl/rationale.py` | yes | RUNNABLE | verbatim |
| §5.1 learned component | BiLSTM-CRF with character sub-encoder; forward, NLL loss, CRF decode; checkpoint loading; batched prediction | `refimpl/extraction/architecture.py` | yes — `tests/test_tagger.py` | RUNNABLE | 4 changed lines (checkpoint file-name constant) |
| §5.1 learned component | Extractor: model spans → operators by regex rule → constraint dict; rule-based and regex fallback layers; confidence; version scheme | `refimpl/extraction/` (same names) | yes | RUNNABLE | `extractor.py`: checkpoint location seam only; others verbatim |
| §5.1 learned component | Training: JSONL dataset, BIO labelling with fuzzy alignment, vocabularies, split with fixed seed, Adam + ReduceLROnPlateau, gradient clipping, early stopping, token-level P/R/F1 | `refimpl/training/` | yes — `../README.md` §3.1 | RUNNABLE | store-backed loader removed; layer-size flags added (defaults unchanged) |
| §5.1 "what the component is not permitted to decide" | Comparison operators from closed-class rules; structural bounds take precedence; model never emits a verdict | `refimpl/extraction/constraints.py`; `refimpl/scanner.py` | yes | RUNNABLE | verbatim |
| §5.1 | Interval comparison, boundary semantics (`<` vs `<=`, build-number containment, degenerate ranges, branch selection, exact-version lists with `defaultStatus`) | `refimpl/versioning/`, `refimpl/scanner.py` | yes — `tests/test_versioning.py` | RUNNABLE | `range_matcher.py`: leftover debug-log block removed (22 lines, inert) |
| §5.1 | Applicability gates: OS family, platform declared unaffected, web/CMS plugin, vendor, language binding, suite component, OS-as-product, common-word identity, distinct product pairs; demotion and veto of promotion | `refimpl/applicability.py`, `identity.py`, `disambiguation.py`, `scanner.py` | yes — `tests/test_applicability.py`, `test_false_positives.py`, `test_disambiguation.py` | RUNNABLE | verbatim ("Acme" example substitution in comments) |
| §5.1 | Product matching: inventory-name cleaning, normalisation, fuzzy match (token overlap, substring, sequence ratio, Levenshtein), catalog-first / extracted-name fallback, coverage, compound family, sole-family binding, specificity rejection | `refimpl/fuzzy/`, `refimpl/vendors.py`, `refimpl/disambiguation.py`, `refimpl/scanner.py` | yes | RUNNABLE | verbatim |
| §5.1 | Candidate retrieval: two arms always merged (structural product/vendor fields; full-text over descriptions), acceptance filter, relevance scoring and deterministic ranking, relevance threshold | `refimpl/search.py` | yes | RUNNABLE | 5 changed lines (docstring) |
| §5.1 | The store's queries behind retrieval (DISTINCT ON + tie-break ordering, anchor-token regex, LIKE predicates, bounds/CPE selection and caps, family-name prefix query) | `refimpl/corpus.py` (in-memory; SQL quoted in docstrings), `refimpl/store.py` | yes — `tests/test_corpus.py` | PARTIAL | reproduction of SQL semantics over JSONL; full-text arm approximates PostgreSQL `english` config with the Snowball stemmer |
| §5.1 "corpus defects handled in the engine" | Commit-hash bounds dropped, non-version-like bounds dropped, build vs semver scheme mismatch, date-form versions, update-package records | same names under `refimpl/` | yes | RUNNABLE | **No rule named for "OS build placed where the upper bound belongs" exists in the source snapshot**; the mechanisms listed here are the closest (`../CLAIM_TO_CODE_MATRIX.md`, I-1). |
| §5.1 "platform applicability class" | OS-family conflict, `platform_declared_unaffected`, `platform_mismatch`, `applicability_os` demotion kept separate from other-product demotions in the final status | `refimpl/applicability.py`, `refimpl/scanner.py` | yes | RUNNABLE | the manuscript term is not used in code |
| §6.1 | Estate-level reduction: merge key (product, version, OS family), vendor adopted by majority, versionless/nameless rows dropped, endpoint lists retained; fan-back | `refimpl/planning/estate_reduction.py` | yes — `tests/test_planning_and_cache.py` | RUNNABLE | database query and CLI removed; `fan_back` is a labelled reviewer wrapper (production performed the join in the console) |
| §6.2 | Request-level grouping: dedup key with version; product key without version; assignment preserving order and length | `refimpl/planning/planner.py` | yes — `tests/test_planner.py` | RUNNABLE | verbatim |
| §6.2 | Copied results marked as such | `service_tier/backend/routers/scan.py`, `service_tier/backend/services/worker.py`; also `examples/run_pipeline.py` (step 6) | yes — `service_tier/tests/test_worker.py`, `test_api.py` | RUNNABLE | verbatim modulo imports |
| §7 cache coherence | Extraction cache keyed by text digest (sha256[:16]) + model id; hit requires equal digest | `refimpl/extraction_cache.py` | yes | RUNNABLE | in-process dictionary replaces the table; same key discipline |
| §7 cache coherence | Model identifier = digest of checkpoint bytes, not path | `refimpl/engine_identity.py` | yes | RUNNABLE | fallback branch of the original (service-tier lookup removed) |
| §7 cache coherence | Engine identifier = digest of the compiled binary | `compiled_engine/goscan/main.go` | no | INSPECTABLE | |
| §7 | Verdict cache keyed by (product, version, scope, engine id) with TTL and conservative purge; engine id = model digest + binary digest | `service_tier/storage/cache.py`, `service_tier/backend/services/scanner.py` | yes — `service_tier/tests/test_scan_retrieval.py::TestCacheVersioning`, `test_e2e_postgres.py::test_verdict_cache_key_covers_scope_and_engine_identity` (PostgreSQL) | RUNNABLE | `cache.py` verbatim modulo imports; `scanner.py`: checkpoint-location seam, one product name in a comment |
| §7 | Job queue: claim with `FOR UPDATE SKIP LOCKED`, per-group persistence, derived resumption, requeue with attempt cap, per-group failure isolation | `service_tier/storage/jobs.py`, `service_tier/backend/services/worker.py`, `service_tier/storage/migrations/` | yes — `service_tier/tests/test_worker.py` (no database), `test_e2e_postgres.py` (claim exclusivity, resumption, requeue cap) | RUNNABLE | verbatim modulo imports |
| §7 | Submission/retrieval split, blocking variant with item cap, authentication | `service_tier/backend/` (same names) | yes — `service_tier/tests/test_api.py` | RUNNABLE | verbatim modulo imports |
| §7 | Response restructured into summary + paginated findings, sliced in the store | `service_tier/backend/routers/scans.py`, `service_tier/storage/cache.py` | yes — `service_tier/tests/test_scan_retrieval.py`, `test_e2e_postgres.py::test_store_side_pagination` | RUNNABLE | the three functions copied verbatim into their own router module |
| §7 | Proxy limits: 20 r/s scan, 5 r/s admin, 32 MB bodies, TLS, HTTP/2, compression | `service_tier/deploy/nginx.example.conf` | no (configuration) | INSPECTABLE | certificate paths and hostnames replaced by placeholders |
| §7 | Item-metered allowance; whole-submission rejection; health reachable when exhausted | — | — | MISSING | not in the 1 August 2026 snapshot (`api_keys.py` only logs item counts); post-dates it |
| §7 | Extraction cache table (text digest + model id) | `service_tier/storage/extractions.py` (table-backed) and `refimpl/extraction_cache.py` (in-process) | yes — `refimpl` tests; table exercised by the PostgreSQL tests' migrations | RUNNABLE | verbatim modulo imports |
| §7 | Feed maintenance scheduler | `service_tier/backend/services/cve_updater.py` | import only | PARTIAL | scheduler/trigger/start/stop verbatim; the five concrete feed calls replaced by a registry (seam). **Per-feed intervals with skip reasons are not in the snapshot** (one global interval) |
| §7 | Feed acquisition (cvelistV5, NVD CPE, OSV, KEV/EPSS, endoflife.date) | — | — | EXCLUDED | data acquisition into the store; depends on the corpus store module |
| §7 | Engine client: no fallback, 503 on unavailability, health caching | `service_tier/backend/services/goscan.py`, `service_tier/backend/main.py` | yes — `test_e2e_postgres.py::test_http_api_round_trip` | RUNNABLE | |
| §7 | Management panel, key management endpoints, corpus browser, logs | — | — | EXCLUDED | operator console; not a decision or transport component |
| §8 workloads | 300-item load test (cold/warm throughput) | `service_tier/tools/loadtest.py` | yes (against a running service) | RUNNABLE | one example URL removed |
| §8 instrumentation | Phase accumulators (atomic per-phase time/calls/items), report | `compiled_engine/goscan/timing.go` | no (Go; `go test` runs) | INSPECTABLE | enabled by `GOSCAN_TIMING` |
| §8 workloads / §9 scaling | Local benchmark mode; worker-count passes | `compiled_engine/goscan/main.go` | no | PARTIAL | no repetition loop, no median/IQR aggregation, no per-process CPU-counter instrumentation, no engine-identity-stamped report in the snapshot |
| §9 latency distribution | 200 single-item requests, per-decade medians | — | — | MISSING | harness not in the source snapshot |
| §9 "taking the store off the hot path" | In-memory candidate index built once per engine process; equivalence self-check against the production query form when it is built | — | — | MISSING | the snapshot predates this component |
| §9 compiled engine | Worker pool over product groups (semaphore of `workers`), prepare-once/decide-per-version, per-group error isolation, verdict logic and `finalize` identical to the Python reference | `compiled_engine/goscan/scan.go` | unit tests (`go test`) | INSPECTABLE | `go vet`/`go test` pass; running needs PostgreSQL |
| §9 compiled engine | Go ports of matching, gates, version algebra, constraint rules, identity policy | same names | unit tests (`go test`) | INSPECTABLE | known Python/Go differences (`compiled_engine/goscan/README.md`, `../CLAIM_TO_CODE_MATRIX.md`): no language-binding gate in Go; Go `ParseVersion` lacks several Python normalisations; prerelease ordering lexical in Go |
| §9 "the model runs faster without the accelerator" | ONNX export of the network up to emissions; CRF transitions exported as JSON; host-side Viterbi; CPU provider only | `refimpl/export/export_onnx.py`, `refimpl/export/crf_decode.py` (Python port of `model.go`), `compiled_engine/goscan/model.go` | yes — `tests/test_tagger.py`, `../README.md` §3.3 | RUNNABLE | verification texts from a file instead of the store; the 4.0 vs 8.3 ms figures are not reproduced |
| §9 verdict preservation | Decoding equivalence (identical label sequences from both decoders) | `refimpl/export/export_onnx.py::verify` | yes | RUNNABLE | run on synthetic texts with the tiny model: 132/132 identical |
| §9 verdict preservation | Engine parity: status agreement, missed vs invented threats reported separately | `refimpl/evaluation/parity.py` | yes — `tests/test_evaluation.py` | RUNNABLE | transports (HTTP, cache) removed; comparison logic kept |
| §9 verdict preservation | Index equivalence self-check | — | — | MISSING | see above |
| §9 verdict preservation | Restart recovery (job resumes from stored rows; nothing processed twice) | `service_tier/storage/jobs.py`, `service_tier/backend/services/worker.py` | yes — `service_tier/tests/test_e2e_postgres.py::test_restart_resumes_from_stored_rows`, `test_worker.py::test_resumption_scans_only_rows_without_an_outcome` | RUNNABLE | the manuscript's 16-item instance is not reproduced; the mechanism is |
| §5/§9 release gates | Golden-set decision metrics (exact/accepted accuracy, missed/false threats, product and patched-version leakage, CVE recall) | `refimpl/evaluation/golden_metrics.py` | yes | RUNNABLE | scanner injected; store-backed `main` replaced |
| §5/§9 release gates | Promotion gate (floor, no increase in missed threats, tolerance) | `refimpl/evaluation/promote_gate.py` | yes — `tests/test_promote_gate.py` | RUNNABLE | file operations (staging/backup) excluded |
| §5/§9 release gates | Evidence-based golden-set generation from the corpus | — | — | EXCLUDED | requires the production store; the synthetic golden set is hand-written |
| §5.1 outputs | Threat prioritisation (KEV / EPSS / CVSS classes, deterministic ordering) | `refimpl/prioritization.py` | yes — `tests/test_prioritization.py` | RUNNABLE | verbatim; risk signals from the in-memory corpus |
| §5.1 outputs | Remediation proposal; end-of-life support status | — | — | EXCLUDED | post-verdict reporting; the two calls were removed from `refimpl/scanner.py` (verdicts unaffected) |

## Component checklist

| # | Component | Where | Classification |
|---|---|---|---|
| 1 | Model architecture | `refimpl/extraction/architecture.py` | PRESENT — REVIEWER RUNNABLE |
| 2 | Training implementation | `refimpl/training/dataset.py`, `train.py` | PRESENT — REVIEWER RUNNABLE (synthetic data; original corpus restricted) |
| 3 | Inference | `refimpl/extraction/extractor.py`, `architecture.py::predict_batch`; ONNX path `refimpl/export/crf_decode.py::OnnxExtractor` | PRESENT — REVIEWER RUNNABLE (original checkpoint restricted) |
| 4 | CRF decode | `torchcrf` via `architecture.py`; host-side port `refimpl/export/crf_decode.py::viterbi` | PRESENT — REVIEWER RUNNABLE (Go port `compiled_engine/goscan/`) |
| 5 | Preprocessing | `refimpl/training/dataset.py` (tokens, BIO alignment, vocabularies), `architecture.py` (padding, char ids), `disambiguation.py::clean_inventory_name`, `fuzzy/matcher.py::normalize_product_name`, `versioning/parser.py::clean_version_string` | PRESENT — REVIEWER RUNNABLE |
| 6 | Constraint recovery | `refimpl/extraction/constraints.py`, `extractor.py::_extract_version_info` | PRESENT — REVIEWER RUNNABLE (Go port `compiled_engine/goscan/`) |
| 7 | Version comparison | `refimpl/versioning/`, `refimpl/scanner.py` (`_version_verdict`, `_resolve_single_range`) | PRESENT — REVIEWER RUNNABLE |
| 8 | Applicability gates | `refimpl/applicability.py`, `identity.py`, `scanner.py::_apply_gates` | PRESENT — REVIEWER RUNNABLE (Go port `compiled_engine/goscan/`) |
| 9 | Product matching | `refimpl/fuzzy/matcher.py`, `disambiguation.py`, `scanner.py::_match_product` | PRESENT — REVIEWER RUNNABLE (Go port `compiled_engine/goscan/`) |
| 10 | Candidate retrieval | `refimpl/search.py` (production code) over `refimpl/corpus.py` (store semantics reproduced in memory); in-memory index of §9 not in snapshot | PARTIAL |
| 11 | Final decision / verdict | `refimpl/scanner.py` (`_decide`, `_apply_gates`, `_finalize_status`), `policy.py` | PRESENT — REVIEWER RUNNABLE |
| 12 | Inventory reduction | `refimpl/planning/estate_reduction.py::collect` | PRESENT — REVIEWER RUNNABLE |
| 13 | Grouping / scheduling / fan-back | grouping `refimpl/planning/planner.py`; fan-back `estate_reduction.py::fan_back`; worker pool Go `scan.go` (inspectable); job-queue scheduling excluded (service tier) | PRESENT — REVIEWER RUNNABLE (grouping, fan-back); INSPECTABLE (pool) |
| 14 | Reference / sequential engine | `refimpl/scanner.py` is the single-threaded reference implementation; compiled engine `compiled_engine/goscan/` | PRESENT — REVIEWER RUNNABLE (reference); PRESENT — INSPECTABLE (compiled) |
| 15 | Evaluation metrics | `refimpl/evaluation/golden_metrics.py`, `parity.py`, `promote_gate.py`; token P/R/F1 in `training/train.py::evaluate`; decode equivalence in `export/export_onnx.py::verify` | PRESENT — REVIEWER RUNNABLE |
| 16 | Benchmark / timing methodology | `compiled_engine/goscan/timing.go`, `main.go::runBench` (inspectable); repetition, latency-distribution and CPU-counter harnesses not in snapshot | PARTIAL |

## Seam edits (complete list)

* `refimpl/versioning/range_matcher.py` — removed a leftover `# #region agent log … # #endregion` block that appended a JSON line to a developer's local file on every range decision (wrapped in `try/except: pass`; no effect on results).
* `refimpl/scanner.py` — (a) `_model_version_tag` reads `refimpl.engine_identity.model_version()` instead of the service tier; (b) `from refimpl import lifecycle` / `remediation` imports and the two post-verdict enrichment calls in `_decide` removed; (c) `ThreatScanner.__init__` gained `model_path`, passed to the extractor in `load()`. Imports of the store (`_catalog_family`) and extraction cache (`_extract_into`) are the mechanical rewrites.
* `refimpl/extraction/extractor.py` — checkpoint location from `model_dir` or `REFIMPL_MODEL_PATH` instead of the serving directory; registers the checkpoint with `engine_identity`.
* `refimpl/extraction/architecture.py` — checkpoint file name as a local constant; help text.
* `refimpl/training/train.py` — `--data` and `--output` required; store-backed data path removed; layer-size and `--patience` flags added with production defaults; report written next to the checkpoint.
* `refimpl/training/dataset.py` — `load_from_database` removed.
* `refimpl/search.py` — module docstring.
* `refimpl/export/export_onnx.py` — `dynamo=False` passed to `torch.onnx.export` where the keyword exists (torch ≥ 2.9 otherwise selects the dynamo exporter and fails without `onnxscript`); verification texts from a file instead of the store.
* `refimpl/extraction/__init__.py` — no eager import of the extractor (so pure modules import without torch).
* Tests: monkeypatch targets point at `refimpl.store.product_family_names` and `refimpl.evaluation.promote_gate`.
* `service_tier/` (all files): imports rewritten to the package layout (`service_tier.storage`, `service_tier.backend`, `service_tier.config`, `refimpl.fuzzy.matcher`, `refimpl.planning.planner`).
* `service_tier/backend/main.py` — admin router and panel static mount removed; file log handler removed (console only); run instruction updated.
* `service_tier/backend/routers/health.py` — corpus statistics call removed (store module not included); `cve_db_ok` follows the engine's health.
* `service_tier/backend/services/scanner.py` — checkpoint location from `CVE_MODEL_PATH` / `REFIMPL_MODEL_PATH` (`_local_model_path`) instead of the production serving directory; one product name in a comment generalised.
* `service_tier/backend/services/cve_updater.py` — the five concrete feed calls replaced by `register_feed`/`FEEDS`; scheduler unchanged.
* `service_tier/backend/routers/scans.py` — new module holding the three scan-retrieval functions of the production admin router verbatim.
* `service_tier/backend/schemas.py` — one example string (`examples=["Example client"]`).
* `service_tier/deploy/nginx.example.conf` — certificate paths, log names and upstream/zone names replaced by placeholders; management-panel routes removed; limits unchanged.
* `service_tier/config.py`, `compiled_engine/goscan/db.go` — default database name `refimpl` (local demonstration database).
* `service_tier/storage/api_keys.py` — generated keys use the neutral prefix `demo_`.
* `service_tier/tools/loadtest.py` — one example URL replaced; product list replaced by fictional names.
* Tests: `service_tier/tests/test_api.py` and `test_scan_retrieval.py` are the production tests with imports rewritten (and the admin router replaced by `routers/scans.py`); `test_worker.py`, `test_e2e_postgres.py`, the engine-shim tests in `test_api.py` and `tools/engine_shim.py` are new reviewer code.
* Go: module path in `go.mod`; example product names in comments; `goscan/README.md` written for this package (design rationale, parity method and known differences; no inventory-derived measurements).

## Synthetic substitution (deployment-derived content)

In the research code, the curated rule tables, several test fixtures and some code
comments were filled from the deployed system's operation. None of that content is in
this package. The replacements were **designed independently** for this package: they are
not renamings of the original entries. Row counts, product relationships, version numbers
and advisory sentences differ, and no entry corresponds one-to-one to an original one. The
mechanisms, table formats and tested conditions are unchanged.

* **Rule knowledge base** (`refimpl/identity.py` and its Go twin `compiled_engine/goscan/policy.go`):
  `_GENERIC_TOKENS`, `_KNOWN_CROSS_PRODUCT`, `_DISTINCT_SUBPRODUCTS`, the foreign-version
  markers and `_DISTINCT_PRODUCT_PAIRS` contain **fictional** products only (Brindle,
  Quillon, Corvane, Tessary, Mirrowick, Ravenmail, Pinecrest, OrchardSync, Glasswing), and
  are identical in Python and Go. Consequence: on real-world inventories these specific
  deny-lists do not fire; the gates demonstrate the method on the synthetic fixtures.
  Generic lexicons that are public knowledge (operating-system names, common English words,
  Apple built-in app names, public vendor aliases, web-CMS ecosystem names, platform and
  edition suffixes) are kept, because the gates need them.
* **Test fixtures**: `tests/test_false_positives.py`, `tests/test_inventory_names.py`,
  `tests/test_disambiguation.py`, `tests/test_product_coverage.py`, `tests/test_constraints.py`,
  `tests/test_versioning.py`, `compiled_engine/goscan/falsepositive_test.go` and
  `compiled_engine/goscan/match_test.go` use fictional products, versions and advisory
  texts written for this package. Together they reproduce each false-positive class:
  OS-as-product, platform declared unaffected, common-word identity, distinct product
  pairs, cross-product text, foreign version bound, plugin identity, catalog specificity,
  compound product families, build-numbered versions and vendor-equals-product. The
  cross-product and foreign-version tables are tested directly in both engines
  (`TestCaprazUrunMetni`, `TestYabanciSurumSiniri`; Go `TestCaprazUrunVeYabanciSinir`).
* **Synthetic data**: `example_data/generate_synthetic.py` is fictional throughout. Its
  build-numbered case is `Tailspin Relaywire Client 5.2.8.3141` under the bound `<= 5.2.8`.
  The five files are regenerated byte-identically by re-running the script.
* **Comments**: incident narratives (named scans, products, CVE identifiers, threat and
  candidate counts) were replaced by neutral explanations that use the fictional examples
  above. Original source paths were replaced by package paths. Development-time profiling
  figures (call counts, timings) were removed from the comments on 2026-10-31; some comments
  still cite statistics of the public advisory corpus. These are not manuscript results and
  not produced by this package.

## Known engine divergence

The Python reference engine and the Go source differ on at least one rule: the Go snapshot has no
language-binding gate (`compiled_engine/goscan/README.md`, "Known differences at this snapshot"). The two
released engines are therefore **not** in full verdict parity; the parity reported in the
manuscript (Section 9) was measured on the deployed build, not on these two sources. The divergence
is pinned by `compiled_engine/goscan/divergence_test.go` and `tests/test_applicability.py::TestLanguageBinding`
(same input pairs).

## New files (written for this package)

`service_tier/backend/routers/scans.py` (composed from the production admin router), `service_tier/tools/engine_shim.py`,
`service_tier/tests/test_worker.py`, `service_tier/tests/test_e2e_postgres.py`,
`service_tier/docker-compose.example.yml`, `service_tier/env.example`, `service_tier/requirements.txt`;
`refimpl/store.py`, `refimpl/corpus.py`, `refimpl/extraction_cache.py`,
`refimpl/engine_identity.py`, `refimpl/planning/estate_reduction.py::fan_back`,
`refimpl/export/crf_decode.py` (port of `goscan/model.go`), `refimpl/evaluation/parity.py`
(comparison logic of the production parity script), `examples/run_pipeline.py`,
`example_data/*` (synthetic), `tests/helpers.py`, `tests/test_corpus.py`,
`tests/test_engine_synthetic.py`, `tests/test_tagger.py`, `tests/test_planning_and_cache.py`,
`tests/test_evaluation.py`, `tests/test_prioritization.py` (ported pure cases),
`compiled_engine/goscan/divergence_test.go` (2026-10-30; pins the known engine divergence).
