# Release notes

## v1.1.1 — documentation release (PeerJ second technical check)

Version DOI: assigned by Zenodo when this version is archived; the concept DOI
https://doi.org/10.5281/zenodo.23122100 resolves to the latest archived version.
Supersedes v1.1.0 as the package accompanying the manuscript. No code, data or scientific
result changed. Under `reference_implementation/` and `reproducibility/`, only documentation
and comment text changed: `reproducibility/README.md`, `reproducibility/docs/release_checklist.md`,
`reference_implementation/MAPPING.md`, `reference_implementation/compiled_engine/goscan/README.md`,
and the README section numbers cited in one docstring or comment each of
`reproducibility/analysis/estate_structure.py`, `reproducibility/verify_release.py` and
`reference_implementation/service_tier/__init__.py`. Every other file there is byte-identical
to v1.1.0.

Why: PeerJ's technical check of the resubmission reported "README file is INCOMPLETE" and asked
for a README with Title, Description, Dataset Information, Code Information, Usage
Instructions, Requirements, Methodology, Citations, and License & Contribution Guidelines.

Changed
- `README.md` reorganised under those nine items (numbered Sections 1–9, with an index at the
  top); added dataset schemas, a module-by-module code description, mandatory versus optional
  requirements, configuration variables, a CPU-only installation option, a copy-and-paste
  end-to-end example, troubleshooting, and a methodology section per pipeline stage. Commands
  and expected outputs are those of v1.1.0, plus three new commands (the optional CPU-only
  `torch` installation, backgrounding and stopping the engine shim, and removing the PostgreSQL
  container); all were re-executed.
- `REPRODUCIBILITY_REPORT.md` added: clean-environment execution of every README command
  (environment, commands, results, expected versus observed, limitations).
- `CITATION.cff`: version 1.1.1; v1.1.0 version DOI (10.5281/zenodo.23840722) and release URL
  added.
- `CODE_AVAILABILITY.md`, `DATA_AVAILABILITY.md`: v1.1.0 version DOI filled in (it was
  "assigned on publication"); pointers to the README sections and the report.
- `reproducibility/README.md`: the description of the repository README's section structure
  corrected (it described the v1.0.0 README).
- `paper/`: manuscript revision M43 — the Data Availability statement now points to the
  README and `REPRODUCIBILITY_REPORT.md` and names release v1.1.1; the Declaration of
  Generative AI Use names the tool version of this revision. No scientific content, value,
  table or figure changed.

## v1.1.0 — research reference implementation (PeerJ resubmission)

Published 2026-10-31 (commit `106eee0`). Version DOI: 10.5281/zenodo.23840722
(https://doi.org/10.5281/zenodo.23840722). README section numbers in this entry refer to the
v1.1.0 README (§14 = now Section 9, §8–9 = now Section 10).

Added
- `reference_implementation/`: the authors' research code of Sections 5–7 from the
  research snapshot of 1 August 2026 — Python reference engine with the BiLSTM-CRF tagger
  (training, ONNX export, host-side decoding), Go source of the compiled engine, and the
  Section 7 service tier — with tests, synthetic data and a deterministic generator.
  Origin and every code edit: `reference_implementation/MAPPING.md`.
- `CLAIM_TO_CODE_MATRIX.md`: each Sections 5–9 claim mapped to code, tests and
  reproducibility status.

Changed
- `paper/`: revised manuscript (33 pages); Figures 1, 4, 6 and 7 re-written without hidden
  page content; visible content and plotted data unchanged.
- Documentation (README, CODE_AVAILABILITY, DATA_AVAILABILITY, CITATION.cff) updated.

Licences
- `reference_implementation/`: PolyForm Noncommercial License 1.0.0 (`LICENSE`, `NOTICE`
  in that directory). Noncommercial use, including review, research and teaching, is
  permitted; commercial use requires a licence from the copyright holder.
- Everything else: MIT, unchanged from v1.0.0. The MIT licence files are kept exactly as
  published; their copyright line names the holder as "Rakort Bilgi Teknoloji A.Ş.", whose
  correct legal name is Rakort Bilgi ve İletişim Teknolojileri Ltd. Şti. (README §14).
- `paper/`: not covered by either software licence.

Not included: raw inventories, the trained production weights, the deployed engine build,
post-snapshot service features, measurement harnesses and deployment configuration. The
Sections 8–9 measurements cannot be regenerated from this release (README §8–9).

## v1.0.0 — published 2026-10-03

GitHub release: https://github.com/RakortAcademy/PeerjNetworkPaper/releases/tag/v1.0.0
(commit `b51f048`). Archived by Zenodo: https://zenodo.org/records/23122101,
DOI 10.5281/zenodo.23122101 (https://doi.org/10.5281/zenodo.23122101).

First public release of the reproducibility package for *Learning-Assisted Exposure
Assessment at Estate Scale: Constraint Recovery, Inventory Redundancy, and Engine
Placement in Managed Enterprise Networks* (Ramazan Kocaoğlu, Basma Bakırcı; PeerJ
Computer Science, AI Application, under review).

Contents
- Manuscript PDF and LaTeX source as submitted (`paper/`), unchanged.
- Section 4 analysis scripts (`reproducibility/analysis/`): export reader and reduction,
  Tables 2–5 and the Figure 1 curve file, Table 6, Table 7 four-tier CPE route.
- Released values of Tables 2–6 and the Figure 1 curve file, generated by these scripts
  from the eight study exports on 2026-10-03 (`aggregate_data/`, `figure_data/`); Table 7
  values as published; Figure 6 and 7 plotted values.
- `reproduce_figures.py` (Figures 1 and 6; partial Figure 7b), `verify_release.py`
  (release checks), synthetic example inputs, documentation.

What this release does not contain
- Raw inventory exports, endpoint-level data, the production assessment service, model
  weights, advisory/applicability corpora, the production product dictionary. See
  `CODE_AVAILABILITY.md` and `DATA_AVAILABILITY.md`.

Known limitations
- Tables 2–6 and Figure 1 can be regenerated only from the restricted exports; the
  public check is internal consistency plus a synthetic pipeline run.
- Table 7 is not reproducible publicly (restricted exports, historical dictionary state
  and measurement code unavailable).
- Figure 7 is not reproducible (unreleased per-request observations); Figure 7(b) is
  drawn from released medians only.

Generative AI: the repository tooling and documentation were prepared with Claude Code
(Anthropic) assistance; see README, "Generative AI Use".

Citation: see `CITATION.cff`. Software DOI: 10.5281/zenodo.23122101.
