"""Per-advisory extraction cache — in-process replacement for `storage.extractions`.

Manuscript Section 7 ("Cache Coherence Across Changes"): extractions are stored
"under a digest of the advisory text together with the model identifier". The
production table `cve_extractions(cve_id, model_version, description_hash,
payload)` is replaced here by a dictionary with the same key discipline:

* `description_hash` is the SHA-256 of the advisory text, first 16 hex chars —
  identical to the production function, so an edited advisory misses the cache;
* a hit requires the same `cve_id`, the same `model_version` and an equal hash;
* `store` upserts on (cve_id, model_version).

The cache lives for the process only (production: PostgreSQL, persistent).
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Sequence, Tuple

_rows: Dict[str, Dict[str, Tuple[str, Dict[str, Any]]]] = {}  # model_version -> cve_id -> (hash, payload)


def description_hash(description: str) -> str:
    """Açıklamanın kısa özeti — CVE revize edilirse önbellek geçersiz olsun."""
    return hashlib.sha256((description or "").encode("utf-8")).hexdigest()[:16]


def fetch(pairs: Sequence[Tuple[str, str]], model_version: str) -> Dict[str, Dict[str, Any]]:
    """Return cached extractions {cve_id: payload} whose text digest still matches."""
    if not pairs:
        return {}
    wanted = {cid: description_hash(desc) for cid, desc in pairs}
    table = _rows.get(model_version, {})
    out: Dict[str, Dict[str, Any]] = {}
    for cid, digest in wanted.items():
        hit = table.get(cid)
        if hit and hit[0] == digest:
            out[cid] = hit[1]
    return out


def store(entries: Sequence[Tuple[str, str, Dict[str, Any]]], model_version: str) -> int:
    """Upsert (cve_id, description, payload) rows under `model_version`."""
    if not entries:
        return 0
    table = _rows.setdefault(model_version, {})
    for cid, desc, payload in entries:
        table[cid] = (description_hash(desc), payload)
    return len(entries)


def stats() -> Dict[str, Any]:
    by_model = {mv: len(t) for mv, t in _rows.items()}
    return {"total": sum(by_model.values()), "by_model": by_model}


def clear() -> None:
    _rows.clear()
