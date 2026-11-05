# Reproducibility report — PeerjNetworkPaper v1.1.1

Record of running the commands in `README.md` (Section 5) in a clean environment, for the
manuscript *Learning-Assisted Exposure Assessment at Estate Scale: Constraint Recovery, Inventory
Redundancy, and Engine Placement in Managed Enterprise Networks* (Kocaoğlu, Bakırcı; PeerJ Computer
Science, CS-2026:09:148327). Date of the runs: 2026-11-05.

## 1. Summary

| Area | Result |
|---|---|
| Dependency installation (fresh virtual environment from PyPI; CPU-only torch) | succeeded |
| Section 4 release checks (`verify_release.py`) | 27 passed, 0 failed, 7 not tested / not reproducible (by design, Section 8) |
| Sensitive-content scan (`scan_sensitive.py`) | 0 findings |
| Synthetic data regeneration | five files rewritten byte-identically |
| Reference implementation tests | 389 passed, 1 skipped (the skipped test needs a trained checkpoint and passes after training: 9 passed) |
| Tagger training, end-to-end pipeline, ONNX decoding equivalence, golden-set metrics | all as documented; 132/132 identical label sequences |
| Service tier tests without / with PostgreSQL | 60 passed, 8 skipped / 68 passed |
| HTTP round trip and 300-item load test | as documented; 300/300 items, 0 errors |
| Go `vet`, `test`, `build` | clean; `ok`; builds |
| Manuscript build | 33 pages |
| Python 3.12 (container): release checks and both test suites | same results as under 3.10 (Section 6) |

Every step of README Section 5 that was executed produced the documented output. Section 7 lists
the deviations found while preparing this report and how they were resolved. Section 8 lists what
was not executed and why.

## 2. What was tested

- **Tested archive:** `git archive` of the v1.1.1 candidate commit
  (`PeerjNetworkPaper-1.1.1/`, 236 entries, SHA-256
  `7bb10dce7afb9933a2c83ed7c1f03ed57a5623b5a542bf94929888df4f4fa07a`).
- **Final archive** (`PeerjNetworkPaper_v1.1.1.zip`). Compared with the tested archive, it adds
  this report, corrects one sentence of `RELEASE_NOTES.md` (which new commands v1.1.1 adds), and
  changes only the wording of `README.md`: measured quantities (virtual-environment
  size, training time, end-to-end duration, peak memory, tested Python versions) and statements of
  status (the archive is "supplied" to PeerJ, the verification scope, and Table 19 being recomputable
  by hand). No command, path, option or expected output changed. The final archive was then put
  through the same full procedure (Sections 4–5, CPU-only torch) and gave the same results as in
  Section 5. The authors keep that run's log with the release records. The checks of Section 9 were
  also run on it.
- **Code identity with v1.1.0:** no source, test, data, configuration or licence file changed
  relative to v1.1.0. Only README section numbers in one docstring or comment each of three Python
  files changed (`RELEASE_NOTES.md`). The results below therefore also hold for v1.1.0's code.

## 3. Environment and toolchain

| Item | Version |
|---|---|
| Operating system | Ubuntu 22.04.5 LTS, Linux 5.15 (aarch64) |
| CPU / memory / GPU | 12 cores, 61 GB RAM; no GPU used (CPU-only torch) |
| Python | CPython 3.10.12 (system interpreter, `python3 -m venv`); additionally CPython 3.12.16 in a container (Section 6) |
| Python packages (resolved by pip from the requirement files) | torch 2.14.1+cpu, numpy 1.26.4, pytorch-crf 0.7.2, snowballstemmer 3.1.1, onnx 1.23.2, onnxruntime 1.23.2, pytest 9.2.0, fastapi 0.162.0, uvicorn 0.54.0, pydantic 2.14.3, psycopg2-binary 2.9.13, httpx 0.28.1, openpyxl 3.1.5, matplotlib 3.8.4 |
| Go | go1.25.0 linux/arm64 (`GOTOOLCHAIN=local`, empty module cache; modules downloaded from the public Go proxy) |
| PostgreSQL | `postgres:17` image from `reference_implementation/service_tier/docker-compose.example.yml` |
| Docker | 29.4.2, Compose v5.1.3 |
| TeX | TinyTeX, latexmk 4.88, pdfTeX 1.40.29 |

## 4. Procedure

1. The archive was extracted into an empty directory.
2. Every command ran under `env -i`, with a new empty `HOME`, `PATH` limited to the virtual
   environment, the Go toolchain and the system directories, and an empty Go module and build
   cache.
3. The virtual environment was created from scratch, and every package was downloaded from PyPI or
   the PyTorch CPU index.
4. Commands were copied from the README verbatim, in README order. Each command's output was saved
   to its own log, together with its exit code and duration.
5. Before the service-tier demo, the script checked that the ports used (8390, 18000, 55432) were
   free. It used its own PostgreSQL container, which was removed at the end. The `docker compose`
   commands were run with an added project name (`-p peerjcleanroom`) so that they could not touch
   any other container on the host. The engine shim was stopped with `kill <pid>` instead of the
   README's `kill %1`, which is equivalent: `kill %1` was checked separately in `bash`.

## 5. Results by step (expected = README; observed = this run)

| # | README | Command | Expected | Observed | Exit | Time |
|---|---|---|---|---|---|---|
| 1 | 5.2 | `python3 -m venv .venv` … `pip install torch --index-url https://download.pytorch.org/whl/cpu` … `pip install -r … -r … -r …` | installs | installed; `.venv` 1.1 GB | 0 | 73 s |
| 2 | 5.6 | `python verify_release.py` | `OK: 0 check(s) failed, 27 passed, 7 not tested / not reproducible` | identical | 0 | 6 s |
| 3 | 5.6 | `python scan_sensitive.py` | `0 finding(s)` | `0 finding(s)` | 0 | 1 s |
| 4 | 5.6 | `python reproduce_figures.py --out out/figures` | Figure 1, Figure 6, Figure 7(b) partial (PDF + PNG) | the six files written | 0 | 3 s |
| 5 | 5.6 | `python analysis/estate_structure.py --dir example_data --out out/` | Tables 2–5 and Figure 1 curve on the synthetic input (5 endpoints, 12 live rows, 11 scannable rows, 8 items, 7 products) | as expected; CSVs written | 0 | 1 s |
| 6 | 5.6 | `python analysis/lexical_features.py --dir example_data --out out/` | Table 6 on the synthetic input | written | 0 | <1 s |
| 7 | 5.6 | `python analysis/cpe_route.py --dir example_data --cpe-dictionary … --advisory-corpus … --out out/` | Table 7 tiers on the synthetic input | four tiers + stage 2 printed (e.g. "Resolved and version-bounded name= 42.9% row= 54.5%") | 0 | <1 s |
| 8 | 3.3 | `python example_data/generate_synthetic.py` | five files rewritten byte-identically | `diff -r` against the shipped files: no difference | 0 | <1 s |
| 9 | 5.3 | `python -m pytest` | 389 passed, 1 skipped | 389 passed, 1 skipped; peak memory 0.3 GB | 0 | 6 s |
| 10 | 5.3 (b) | `python -m refimpl.training.train …` | ends with "Test — precision … \| recall … \| F1 …" | "Test — precision 1.0000 \| recall 1.0000 \| F1 1.0000 (221 varlık)"; peak memory 0.4 GB | 0 | 116 s |
| 11 | 5.3 (c) | `python examples/run_pipeline.py --model example_data/tiny_model --out out/` | stage lines 1, 2, 3, 5, 6, 7 as printed in the README; `{'THREAT': 9, 'SAFE': 4, 'NOT_FOUND': 3}`; 22 endpoint exposures | identical lines | 0 | 3 s |
| 12 | 5.3 (c), "Modify the inputs" | the two `Acme Ledgerly Server 2.3.9` rows set to `2.4.1`, then `run_pipeline.py --inventory <edited copy>` | `{'THREAT': 8, 'SAFE': 5, 'NOT_FOUND': 3}` | 2 rows changed; `{'THREAT': 8, 'SAFE': 5, 'NOT_FOUND': 3}`; still 16 items and 22 exposures | 0 | 4 s |
| 13 | 5.3 (d) | `python -m refimpl.export.export_onnx --checkpoint … --out … --verify-texts …` | "132/132 cümlede etiket dizisi AYNI" for ONNX and host-side Viterbi | "132/132 cümlede etiket dizisi AYNI (0 token farkı / 1823)"; "Host-side Viterbi (Go port): 132/132 cümlede torchcrf ile AYNI" | 0 | 4 s |
| 14 | 5.3 (e) | `python -m refimpl.evaluation.golden_metrics …` | metrics printed | confusion all on the diagonal (THREAT 4, SAFE 2, UNCERTAIN 1, NOT_FOUND 1); false THREAT 0; expected CVE recall 100 % | 0 | 2 s |
| 15 | 5.3 (e) | `REFIMPL_MODEL_PATH=example_data/tiny_model python -m pytest tests/test_tagger.py` | 9 passed | 9 passed | 0 | 4 s |
| 16 | 5.4 | `python -m pytest service_tier/tests` | 60 passed, 8 skipped | 60 passed, 8 skipped | 0 | 6 s |
| 17 | 5.4 | engine shim + `curl -X POST localhost:8390/scan …` | 2.3.9 → THREAT `CVE-2099-0001` "Version 2.3.9 < 2.4.1 (exclusive)"; 2.4.1 → SAFE; "Notes" → UNCERTAIN; unknown → NOT_FOUND; empty product → 422 | all five as expected (HTTP 200, 200, 200, 200, 422) | 0 | 2 s |
| 18 | 5.4 | `docker compose -f service_tier/docker-compose.example.yml up -d` | PostgreSQL ready | ready | 0 | 3 s |
| 19 | 5.4 | `SERVICE_TIER_E2E=1 python -m pytest service_tier/tests` | 68 passed | 68 passed | 0 | 7 s |
| 20 | 5.4 | shim + `uvicorn …` + the `curl` sequence + `loadtest.py --items 300` | health `"status":"ok","database":true`; 202 with `job_id`; job `"status":"DONE","completed":3`; duplicate item `"cached": true`; findings page; load test completes | as expected (fresh database: items 0 and 2 computed, item 1, the duplicate, `cached: true`); load test 300/300, 0 errors, all four verdicts present, "Toplam süre 5.0 sn" = the tool's 5 s polling interval (README 5.4) | 0 | 11 s |
| 21 | 5.4 | `docker compose … down -v` | container removed | removed | 0 | 1 s |
| 22 | 5.5 | `go vet ./... && go test ./...` | vet clean; `ok  reference-implementation/compiled-engine` | identical (15 test functions; 30 test runs including subtests) | 0 | 21 s |
| 23 | 5.5 | `go build -o goscan .` | builds | 14.4 MB binary | 0 | 3 s |
| 24 | 5.7 | `latexmk -pdf main.tex` | 33 pages | 33 pages, 0 LaTeX warnings | 0 | 5 s |

On the verification host, port 8000 was used by an unrelated service. Step 20 therefore started
the API on port 18000 (`--port 18000`) and sent every `curl` and `loadtest.py --url` request to that
port. This is the procedure in the README troubleshooting table; nothing else was changed.

## 6. Additional checks

- **Default PyPI torch (without the CPU-only line).** A separate clean run on the unchanged v1.1.0
  code (`main` before v1.1.1) installed torch 2.14.1 from PyPI. On Linux/aarch64 this pulls the CUDA
  runtime packages (`nvidia-*`, `triton`), and `.venv` grew to 5.5 GB. Steps 2–11 and 13–19 of Section 5 (step 12,
  "Modify the inputs", was not part of that run) gave the same results as above: 389 passed / 1 skipped; pipeline identical; 132/132; 9 passed; 60 / 8; 68
  passed. Training took 246 s. torch printed a harmless "CUDA initialization … driver too old"
  warning at import. This is why the README now recommends the CPU-only line and lists the
  warning in its troubleshooting table.
- **Python 3.12.** The tested archive was extracted in a fresh `python:3.12-slim` container
  (CPython 3.12.16, Linux/aarch64). The CPU-only torch and the three requirement files were
  installed exactly as in README 5.2, and pip resolved torch 2.15.0+cpu and onnxruntime 1.31.1.
  Results: `verify_release.py` reported 27 passed, 0 failed, 7 not tested / not reproducible;
  `python -m pytest` gave 389 passed, 1 skipped; `python -m pytest service_tier/tests` gave 60
  passed, 8 skipped. Training, the examples, PostgreSQL, Go and LaTeX were not repeated under 3.12.

## 7. Deviations found and how they were resolved

| Finding | Root cause | Resolution |
|---|---|---|
| The v1.1.0 README was not organised under the README items requested by PeerJ, and `reproducibility/README.md` described a section structure that the root README no longer had | The README was extended over several releases without being restructured | README rewritten under the nine items; `reproducibility/README.md` corrected |
| Installing exactly as documented in v1.1.0 put about 4 GB of unused CUDA libraries into the environment | The default PyPI torch wheel for Linux bundles CUDA | CPU-only installation line added, with its measured size; both variants tested (Section 6) |
| The first attempt at step 20 failed: the API could not bind port 8000, and the demo requests went to the unrelated service on that port, which answered "404 Not Found". The run was stopped before the load test, and no request created anything | Port conflict on the verification host; the v1.1.0 demo did not check whether the API had started | Repeated on port 18000 with a pre-flight port check; troubleshooting row added to the README ("address already in use") |
| The v1.1.0 documents described the v1.1.0 version DOI as "assigned by Zenodo on publication" after it had been assigned | Documents were not updated after the Zenodo deposit | DOI 10.5281/zenodo.23840722 written into `CITATION.cff`, `CODE_AVAILABILITY.md`, `DATA_AVAILABILITY.md`, `RELEASE_NOTES.md` and the README |
| The README gave the training time as "about 2 min" | Measured: 116 s with the CPU-only torch, 246 s with the default PyPI torch | README now says 2–4 minutes |
| A truncated log line did not show which items of the HTTP demo were marked `cached` | The verification script cut the response at 1,500 characters | Repeated on a fresh database with the full response (step 20) |

No test failed. Nothing in the algorithms, tests or data needed to change.

## 8. Not executed, and intentionally non-reproducible

**Not executed for this release:**

- macOS, Windows and x86-64 Linux. Only Linux/aarch64 was run. The dependencies publish wheels
  for those platforms, but no run took place there.
- Running the compiled `goscan` binary. It needs a populated PostgreSQL advisory store and a
  trained model, and neither is released. The binary was built, and its unit tests pass without a
  database.
- `cpe_route.py` against the real NVD CPE dictionary. That dictionary is not bundled; the script
  was run on the synthetic dictionary only.
- Go's automatic toolchain download (`GOTOOLCHAIN=auto`, README 5.5). The Go 1.25.0 toolchain was
  installed beforehand and the run used `GOTOOLCHAIN=local`.
- `verify_release.py --operator-exports`. It needs the confidential study exports; the
  corresponding checks report `NOT TESTED`.

**Not reproducible from public materials (by design; README Section 10):**

- Tables 2–6, Figure 1 and the §4.1 aggregates. The values are released, and `verify_release.py`
  checks their internal consistency, but recomputing them needs the eight confidential inventory
  exports.
- Table 7. It needs the confidential exports, the production product dictionary as of 3 August
  2026, and the original measurement code.
- Tables 8–18, Figures 2–5, Figure 7(a) and every timing, throughput, latency, footprint, end-to-end
  and parity value of Sections 5–9. These were measured on the deployed system, which uses the
  unreleased 8.8M-parameter model, advisory-corpus snapshot, inventories, in-memory index build
  and measurement harnesses.
- Figure 6 and the Figure 7(b) medians can only be redrawn from the released summary values.
- The tagger trained here (about 28k parameters, synthetic data) and every output above are
  illustrative only, not manuscript values. The Python and Go engines released here are not in
  full verdict parity: the Go source lacks the language-binding gate, and
  `compiled_engine/goscan/divergence_test.go` pins this.

## 9. Final archive checks

The final archive `PeerjNetworkPaper_v1.1.1.zip` was extracted into an empty directory and checked
with the Python environment of Section 3:

| Check | Result |
|---|---|
| `diff -r` between the tested and the final tree | differs only in `README.md` and `RELEASE_NOTES.md` (the wording changes of Section 2) and the added `REPRODUCIBILITY_REPORT.md` |
| `README.md` in the archive versus the standalone `README.md` supplied to PeerJ | byte-identical (same SHA-256) |
| `python verify_release.py` | `OK: 0 check(s) failed, 27 passed, 7 not tested / not reproducible` |
| `python scan_sensitive.py` | `0 finding(s)` |
| `python -m pytest` in `reference_implementation/` | 389 passed, 1 skipped |

The SHA-256 checksums of the final archive and of the standalone files are distributed with the
PeerJ submission files (`SHA256SUMS.txt`).

## 10. Files changed in v1.1.1 and why

See `RELEASE_NOTES.md` (v1.1.1). In short: `README.md` (restructured for PeerJ), this report
(new), `CITATION.cff` (version and DOIs), `CODE_AVAILABILITY.md` and `DATA_AVAILABILITY.md` (v1.1.0
DOI, pointers), `RELEASE_NOTES.md`, `reproducibility/README.md` (description of the README
corrected), `paper/` (manuscript revision M43: two sentences added to Data Availability, AI
declaration updated), and README section numbers updated in `MAPPING.md`,
`compiled_engine/goscan/README.md`, `CLAIM_TO_CODE_MATRIX.md`, `reproducibility/docs/release_checklist.md`
and in one comment or docstring each of three Python files.

## 11. Generative AI use in this verification

This verification was run, and this report written, with the help of Claude Code (Anthropic;
command-line tool, version 2.1.318). As with all AI-assisted material in this package, the
authors are responsible for reviewing it (README Section 13).
