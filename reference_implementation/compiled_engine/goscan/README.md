# goscan — compiled concurrent decision engine (source snapshot)

This is the Go source of the compiled engine at the research snapshot. It is included
for inspection and unit testing. The single-threaded Python implementation
(`refimpl/scanner.py`) is the **reference**; the parity comparator
(`refimpl/evaluation/parity.py`) reports where the two disagree.

## Why a compiled engine

The Python engine cannot use more than one core for its decision work because of the
interpreter lock; the manuscript (§9.3, §9.5, Table 15) reports the historical
measurements that motivated the compiled engine. Those measurements were taken on the
deployed system and are **not** reproducible from this package.

## Where the model sits

Model inference depends on the advisory **text**, not on the queried version. It is
computed once per advisory and cached under a digest of the text plus the model
identifier, so in steady state almost every candidate's extraction is already cached.
The boundary between the two implementations is therefore drawn at the model, not at
the store:

```
Go     → everything that touches the store: candidate retrieval, structured
         bounds, CPE data, cached extractions, version decision, product
         matching, vendor gate, KEV/EPSS/CVSS prioritisation
Python → only the model: advisories whose extraction is not yet cached
```

A boundary at the store would leave half of the work behind the interpreter lock
(manuscript §9.5) and add serialisation per product. The `needs_model` field of a
response lists the advisory identifiers without a cached extraction; the caller passes
them to the model service, which writes the cache, and the next scan completes
entirely in Go.

## Building and testing

```bash
go vet ./... && go test ./...      # pure-function tests; no database, no ONNX runtime
```

The tests use only fictional product names (the same synthetic false-positive classes
as `tests/test_false_positives.py`), plus public operating-system names, which the
gates' vocabulary needs.

Running the engine needs a populated PostgreSQL corpus (connection from the usual
`PGHOST` / `PGPORT` / `PGUSER` / `PGPASSWORD` / `PGDATABASE` variables, no defaults
beyond localhost), and, for extraction, the ONNX Runtime shared library and an
exported model directory. Neither is part of this package.

```bash
go build -o goscan .
MODEL_VERSION=<digest of the model checkpoint> ./goscan -serve -addr 127.0.0.1:8397 -workers 8

curl -X POST http://127.0.0.1:8397/scan -H 'Content-Type: application/json' -d '{
  "items": [{"product":"Tailspin Relaywire Client","version":"5.2.8.3141",
             "vendor":"Tailspin","operating_system":"Windows"}],
  "workers": 8
}'
```

The connection pool must be larger than the number of goroutines, otherwise
parallelism turns into waiting for connections; without `-max-conn` the engine uses
`workers + 4`.

## Equivalence with the Python reference

Silent divergence of the two implementations is the main risk of this architecture.
The parity comparator feeds the same inventory items to both engines and reports
**separately** the threats the reference found and the engine missed (exposure left
open) and the threats the engine found and the reference did not (trust eroded); any
difference gives exit code 1, so it can gate a release. Rules are ported in both
directions and locked by the same test cases on both sides.

Two porting pitfalls illustrate why the rules are tested on both sides:

* Normalisation (`fuzzy/matcher.py`) and identity extraction (`disambiguation.py`)
  use **different** token sets in Python, the second much wider. Mixing them reduces
  "Microsoft Visual C++ 2015-2022 Redistributable" to "microsoft visual", which then
  matches an unrelated product (`TestNormalizeKeepsDistinguishingTokens`).
* `CoversProduct` is **directed**: the advisory's identity tokens must be a subset of
  the inventory's. A symmetric version lets `{edge}` ⊆ `{fabrikam, edge, hmi}` match
  "Fabrikam Edge HMI" with "Orbital Edge" (`TestKnownFalseMatches`).

### Known differences at this snapshot

| Difference | Status |
|---|---|
| Language-binding gate (`refimpl/applicability.py`, `is_language_binding_mismatch`): Perl/Python/Ruby binding advisories vs the underlying library | **absent** in this snapshot; pinned by `divergence_test.go` (e.g. `Net::SSLeay` vs OpenSSL passes `ApplyGates`, Python rejects it) |
| Remediation proposal and support status | not part of this package's Python engine (post-verdict reporting) |
| Model inference (ONNX + Viterbi) | falls back to Python through `needs_model` |

Because of these differences the two released engines are **not** in full verdict
parity, and the Python engine is the reference. The parity reported in the
manuscript (§9) was measured on the deployed build, which post-dates this snapshot
and is not released (repository `README.md`, Section 10, "Restricted components").

## When changing a rule

Every rule in `version.go` and `match.go` addresses a class of wrong decision (commit
hashes as bounds, `<` versus `<=`, adjacent product names, build-numbered versions,
update packages). Change the Python side together with the Go side and run the parity
comparator; otherwise the two engines diverge silently.
