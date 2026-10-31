"""Research implementation of the assessment engine described in Sections 5–9.

This package is a sanitised copy of the authors' research/production source tree:
the decision procedure, the learned sequence tagger and its training code, the
constraint-recovery rules, the version algebra, the applicability gates, the
product-matching rules, the two-level planner and the evaluation tooling.

Production couplings (PostgreSQL corpus store, HTTP service tier, job queue,
result cache, admin API) are replaced by in-process providers with the same call
shape (`refimpl.store` → `refimpl.corpus`, `refimpl.extraction_cache`,
`refimpl.engine_identity`). MAPPING.md lists, file by file, what was copied
verbatim, what was patched at a seam, and what is not included.

Nothing is imported eagerly here so that the pure modules (version algebra,
gates, constraint rules) can be used and tested without torch installed.
"""
