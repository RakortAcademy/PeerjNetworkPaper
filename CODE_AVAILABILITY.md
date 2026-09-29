# Code Availability

**Manuscript:** *Learning-Assisted Exposure Assessment at Estate Scale: Constraint
Recovery, Inventory Redundancy, and Engine Placement in Managed Enterprise Networks*
**Authors:** Ramazan Kocaoğlu, Basma Bakırcı

PeerJ's pre-review technical check flagged "Computer Code Required" and asked that
code be made available for reviewers and the Academic Editor to inspect. This
document states precisely what code is, and is not, included with this submission,
and maps each supplied script to the manuscript claim it supports, so that boundary
does not have to be reverse-engineered from the archive.

## What is publicly supplied

Four Python scripts are provided under `reproducibility/analysis/` (MIT-licensed,
see `LICENSE`):

| Script | Reproduces | Manuscript section |
|---|---|---|
| `common.py` | Shared export reader and the Section 4.1 row-level reduction (drop deleted / unnamed / versionless rows; merge on normalised product+version). Imported by the three scripts below; not run directly. | §4.1 |
| `estate_structure.py` | Table 2 (version coverage), Table 3 (two-level redundancy), Table 4 (version spread), Table 5 (fan-out distribution), Figure 1 (fan-out concentration curves) | §4.2–§4.5 |
| `lexical_features.py` | Table 6 (lexical-feature prevalence) | §4.6 |
| `cpe_route.py` | Table 7 (CPE-dictionary resolution route, four normalisation tiers, plus the optional version-bounded stage-2 check) | §4.7 |

These four scripts, together with the aggregate CSVs already checked into
`reproducibility/aggregate_data/` and `reproducibility/figure_data/`, are **all and
only** the code behind the Section 4 estate-structure measurement study. They do not
require, and were not run against, the confidential raw exports; see
`DATA_AVAILABILITY.md` for what an operator would need to run them against their own
inventory.

## What the manuscript describes but does not publicly supply code for

Sections 5–9 describe a production assessment service — the system the Section 4
measurements motivate, and the subject of the Section 8–9 performance results. Its
components, as named in the manuscript, include: the learned sequence tagger
(bidirectional recurrent network with a conditional-random-field output layer and a
character-level sub-encoder, 8.8M parameters), the constraint-extraction and
applicability-gate logic, the normalised-name index and full-text candidate
retrieval, the interval-comparison decision logic, the compiled concurrent decision
engine (the "reference implementation" it replaced, and the engine that succeeded
it), the in-memory candidate index, the ONNX-exported inference/CRF-decoding path,
and the service tier (job queue, quota, caching, feed maintenance).

**None of this production system's source code, model weights, or configuration is
included in this submission.** It is a proprietary system, developed and operated
by the authors' company (acknowledged in the manuscript's Acknowledgements) inside
customer networks, and is not open-source. The Section 8–9 performance results
(engine comparisons, scaling curves, latency distributions, the end-to-end scan) were
measured against that deployed system directly, not derived from the four scripts
above, and cannot be regenerated from this package. This is stated in the
manuscript's Data Availability section and in `reproducibility/README.md` and
`reproducibility/analysis/README.md`.

No sanitised or reference re-implementation of the production engine or tagger
exists anywhere in the materials reviewed for this submission. None is fabricated
here to appear to satisfy the "Computer Code Required" checkbox: doing so would
misrepresent what the paper's optimisation and placement results were measured
against. Resolving this gap (releasing a sanitised equivalent, or receiving editorial
acceptance that the analysis code above is the appropriate and sufficient release for
a systems paper of this kind) requires a decision by the authors and/or the handling
editor, and remains an open item.

## PeerJ data/code availability compliance

The restriction on the raw customer inventories and on the proprietary
engine/service/tagger falls under PeerJ's data-availability policy exception for
confidential third-party data and proprietary commercial code. It does not extend to
the four Section 4 analysis scripts, which are released in full under an MIT
licence, or to the aggregate/figure CSVs derived from them.
