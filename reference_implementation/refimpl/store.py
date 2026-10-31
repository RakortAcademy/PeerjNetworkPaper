"""Corpus store facade — the seam between the engine and its data.

In production the engine read the advisory corpus from PostgreSQL through
`storage.cve_repo` (functions `search`, `search_by_description`, `bounds_for`,
`cpe_bounds_for`, `product_family_names`, `risk_for`). The engine modules in this
package import *this* module under the same name (`from refimpl import store as
cve_repo`) and call the same functions with the same arguments and return shapes,
so the decision code is unchanged. The functions delegate to the active
`refimpl.corpus.InMemoryCorpus`, which reproduces the store's query semantics over
an in-memory record set loaded from JSONL.

Reviewer note: this is the only place where the data source is chosen. Tests may
monkeypatch these functions (the production tests did the same with
`storage.cve_repo`).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

_active: Optional["InMemoryCorpus"] = None  # type: ignore[name-defined]


def use_corpus(corpus) -> None:
    """Make `corpus` the store the engine reads from."""
    global _active
    _active = corpus


def get_corpus():
    if _active is None:
        raise RuntimeError(
            "No corpus loaded. Call refimpl.store.use_corpus(InMemoryCorpus.load(path)) first."
        )
    return _active


# --- the cve_repo read interface -------------------------------------------------

def search(product_norm: str, vendor: str = "", limit: int = 25000) -> List[Dict[str, Any]]:
    return get_corpus().search(product_norm, vendor=vendor, limit=limit)


def search_by_description(product_norm: str, limit: int = 5000) -> List[Dict[str, Any]]:
    return get_corpus().search_by_description(product_norm, limit=limit)


def bounds_for(cve_ids: Sequence[str], product_norm: str = "",
               max_ranges_per_cve: int = 200) -> Dict[str, List[Dict[str, str]]]:
    return get_corpus().bounds_for(cve_ids, product_norm, max_ranges_per_cve)


def cpe_bounds_for(cve_ids: Sequence[str], product_norm: str = "",
                   max_ranges_per_cve: int = 60) -> Dict[str, List[Dict[str, str]]]:
    return get_corpus().cpe_bounds_for(cve_ids, product_norm, max_ranges_per_cve)


def product_family_names(product_norm: str, limit: int = 6) -> List[str]:
    return get_corpus().product_family_names(product_norm, limit)


def risk_for(cve_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    return get_corpus().risk_for(cve_ids)
