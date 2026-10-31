"""In-memory advisory corpus reproducing the production store's read queries.

The production engine read its corpus from PostgreSQL (store module not included):
tables `cves` (one row per advisory), `cve_affected` (CNA affected-product rows
with structural bounds), `cve_cpe` (NVD applicability rows) and the risk tables.
This class loads the same record shape from a JSONL file and answers the same
five read functions with the same selection, ordering and capping rules. The
original SQL is quoted in each method's docstring so a reviewer can compare.

Record shape (one JSON object per line):

    {"cve_id": "CVE-2099-0001",
     "description": "...advisory prose...",
     "published_at": "2099-01-01", "cvss_score": 7.5, "cvss_severity": "HIGH",
     "affected": [ {"product": "...", "vendor": "...", "version": "",
                    "less_than": "", "less_than_or_equal": "", "greater_equal": "",
                    "default_status": ""} , ... ],
     "cpe":      [ {"product": "...", "vendor": "...", "version": "",
                    "less_than": "", "less_than_or_equal": "", "greater_equal": "",
                    "greater_than": ""} , ... ],
     "risk":     {"kev": false, "epss": 0.0, "cvss": 7.5, ...}            # optional
    }

`product_norm` is derived at load time exactly as the ingest step did
(`normalize_product_name(product) or product.lower()`), and row ids are assigned
in load order (the SQL tie-breaker `a.id`).

Known approximation (documented, not hidden): the description arm uses
PostgreSQL's `to_tsvector('english') @@ to_tsquery('english', ...)`. Here the
`english` configuration is approximated with the Snowball English stemmer
(`snowballstemmer`, the same algorithm PostgreSQL's `english_stem` uses), the
standard English stop-word list, and a simplified tokeniser. Differences at the
margin of the text-search parser are possible; everything downstream of the
record set (acceptance filter, ranking, decision) is the production code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from refimpl.fuzzy.matcher import normalize_product_name

try:  # the same algorithm as PostgreSQL's english_stem (Snowball "english")
    import snowballstemmer

    _STEMMER = snowballstemmer.stemmer("english")
except ImportError as exc:  # pragma: no cover - dependency documented in requirements.txt
    raise ImportError(
        "refimpl.corpus needs the 'snowballstemmer' package for the description "
        "full-text arm (pip install snowballstemmer)."
    ) from exc

# --- constants copied from the production corpus store ----------------------------------

_PRODUCT_LIMIT = 25000
_TEXT_LIMIT = 5000

# Ürünü diğerlerinden ayırmayan satıcı/dolgu kelimeleri — çekirdek token seçilirken atlanır.
_VENDOR_FILLER = {
    "apache", "microsoft", "oracle", "google", "ibm", "cisco", "adobe", "mozilla",
    "red", "hat", "redhat", "the", "inc", "ltd", "corp", "corporation", "gmbh",
    "foundation", "software", "project", "org", "team", "and", "for", "server",
    "client", "core", "edition", "suite", "platform",
}

#: Tam sürüm gibi görünen `version` değeri: en az bir nokta şart (cve_repo._EXACT_VERSION_SQL).
_EXACT_VERSION_RE = re.compile(r"^[vV]?[0-9]+(\.[0-9]+)+[A-Za-z0-9.\-+_:]*$")

# PostgreSQL english.stop (the Snowball English stop-word list shipped with PostgreSQL).
_ENGLISH_STOP = frozenset("""
i me my myself we our ours ourselves you your yours yourself yourselves he him his
himself she her hers herself it its itself they them their theirs themselves what
which who whom this that these those am is are was were be been being have has had
having do does did doing a an the and but if or because as until while of at by for
with about against between into through during before after above below to from up
down in out on off over under again further then once here there when where why how
all any both each few more most other some such no nor not only own same so than too
very s t can will just don should now
""".split())

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-.][a-z0-9]+)*")


def _anchor_token(product_norm: str) -> str:
    """Sorgunun ayırt edici çekirdek tokenı ("apache log4j2" → "log4j") — cve_repo._anchor_token."""
    candidates = [
        re.sub(r"\d+$", "", t)
        for t in (product_norm or "").split()
        if t not in _VENDOR_FILLER
    ]
    candidates = [re.sub(r"[^a-z0-9]", "", t) for t in candidates]
    candidates = [t for t in candidates if len(t) >= 4]
    return max(candidates, key=len) if candidates else ""


def _lexemes(text: str) -> List[str]:
    """Approximation of to_tsvector('english', text): tokens, stop words removed,
    alphabetic words stemmed, tokens with digits kept verbatim (PostgreSQL maps
    numword/version tokens to the `simple` dictionary)."""
    out: List[str] = []
    for tok in _TOKEN_RE.findall((text or "").lower()):
        parts = [tok] + (re.split(r"[-.]", tok) if ("-" in tok or "." in tok) else [])
        for p in parts:
            if not p:
                continue
            if p.isalpha():
                if p in _ENGLISH_STOP:
                    continue
                out.append(_STEMMER.stemWord(p))
            else:
                out.append(p)
    return out


class _Affected:
    __slots__ = ("id", "cve_id", "product", "product_norm", "vendor", "version",
                 "less_than", "less_than_or_equal", "greater_equal", "default_status")

    def __init__(self, id_: int, cve_id: str, row: Dict[str, Any]) -> None:
        self.id = id_
        self.cve_id = cve_id
        self.product = (row.get("product") or "").strip()
        self.product_norm = normalize_product_name(self.product) or self.product.lower()
        self.vendor = (row.get("vendor") or "").strip()
        self.version = (row.get("version") or "").strip()
        self.less_than = (row.get("less_than") or "").strip()
        self.less_than_or_equal = (row.get("less_than_or_equal") or "").strip()
        self.greater_equal = (row.get("greater_equal") or "").strip()
        self.default_status = (row.get("default_status") or "").strip()

    @property
    def has_bounds(self) -> bool:
        return bool(self.less_than or self.less_than_or_equal or self.greater_equal)


class _CPE:
    __slots__ = ("id", "cve_id", "product", "product_norm", "vendor", "version",
                 "less_than", "less_than_or_equal", "greater_equal", "greater_than")

    def __init__(self, id_: int, cve_id: str, row: Dict[str, Any]) -> None:
        self.id = id_
        self.cve_id = cve_id
        self.product = (row.get("product") or "").strip()
        self.product_norm = (row.get("product_norm") or normalize_product_name(self.product)
                             or self.product.lower())
        self.vendor = (row.get("vendor") or "").strip()
        self.version = (row.get("version") or "").strip()
        self.less_than = (row.get("less_than") or "").strip()
        self.less_than_or_equal = (row.get("less_than_or_equal") or "").strip()
        self.greater_equal = (row.get("greater_equal") or "").strip()
        self.greater_than = (row.get("greater_than") or "").strip()


class InMemoryCorpus:
    """Advisory corpus with the production store's read semantics."""

    def __init__(self, records: Iterable[Dict[str, Any]]) -> None:
        self.cves: Dict[str, Dict[str, Any]] = {}
        self.affected: List[_Affected] = []
        self.cpe: List[_CPE] = []
        self._lexemes: Dict[str, frozenset] = {}
        next_id = 1
        next_cpe_id = 1
        for rec in records:
            cve_id = str(rec["cve_id"]).upper()
            self.cves[cve_id] = {
                "cve_id": cve_id,
                "description": rec.get("description") or "",
                "published_at": rec.get("published_at"),
                "cvss_score": rec.get("cvss_score"),
                "cvss_severity": rec.get("cvss_severity") or "",
                "risk": rec.get("risk") or {},
            }
            self._lexemes[cve_id] = frozenset(_lexemes(rec.get("description") or ""))
            for row in rec.get("affected") or []:
                self.affected.append(_Affected(next_id, cve_id, row))
                next_id += 1
            for row in rec.get("cpe") or []:
                self.cpe.append(_CPE(next_cpe_id, cve_id, row))
                next_cpe_id += 1

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path) -> "InMemoryCorpus":
        records = []
        with open(Path(path), "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return cls(records)

    def stats(self) -> Dict[str, int]:
        return {"cves": len(self.cves), "affected_rows": len(self.affected), "cpe_rows": len(self.cpe)}

    # ------------------------------------------------------------------ helpers
    def _record(self, a: Optional[_Affected], cve_id: str) -> Dict[str, Any]:
        c = self.cves[cve_id]
        return {
            "cve_id": cve_id,
            "product": a.product if a else None,
            "vendor": a.vendor if a else None,
            "version": a.version if a else None,
            "less_than": a.less_than if a else None,
            "less_than_or_equal": a.less_than_or_equal if a else None,
            "greater_equal": a.greater_equal if a else None,
            "description": c["description"],
            "published_at": c["published_at"],
            "cvss_score": c["cvss_score"],
            "cvss_severity": c["cvss_severity"],
        }

    # ------------------------------------------------------------------ queries
    def search(self, product_norm: str, vendor: str = "", limit: int = _PRODUCT_LIMIT) -> List[Dict[str, Any]]:
        """Arm 1 — structural product/vendor fields.  Original SQL::

            SELECT DISTINCT ON (a.cve_id) a.cve_id, a.product, a.vendor, a.version,
                   a.less_than, a.less_than_or_equal, a.greater_equal,
                   c.description, c.published_at, c.cvss_score, c.cvss_severity
              FROM cve_affected a JOIN cves c ON c.cve_id = a.cve_id
             WHERE a.product_norm = %(q)s
                OR a.product_norm LIKE %(like)s                      -- '%q%'
                OR %(q)s LIKE '%' || a.product_norm || '%'
                OR (%(anchor)s <> '' AND a.product_norm ~ %(anchor_re)s)  -- '\\m<anchor>'
                OR (%(vendor)s <> '' AND lower(a.vendor) = %(vendor)s)
             ORDER BY a.cve_id, (a.product_norm = %(q)s) DESC,
                      (a.less_than <> '' OR a.less_than_or_equal <> '' OR a.greater_equal <> '') DESC,
                      a.id
             LIMIT %(limit)s
        """
        q = product_norm or ""
        if not q:
            return []
        vendor_l = (vendor or "").strip().lower()
        anchor = _anchor_token(q)
        anchor_re = re.compile(r"\b" + re.escape(anchor)) if anchor else None

        best: Dict[str, _Affected] = {}
        for a in self.affected:
            hit = (
                a.product_norm == q
                or q in a.product_norm
                or a.product_norm in q
                or (anchor_re is not None and anchor_re.search(a.product_norm) is not None)
                or (vendor_l != "" and a.vendor.lower() == vendor_l)
            )
            if not hit:
                continue
            cur = best.get(a.cve_id)
            if cur is None or self._row_key(a, q) < self._row_key(cur, q):
                best[a.cve_id] = a
        rows = [self._record(best[cid], cid) for cid in sorted(best)]
        return rows[:limit]

    @staticmethod
    def _row_key(a: _Affected, q: str):
        # ORDER BY (product_norm = q) DESC, has_bounds DESC, id ASC
        return (0 if a.product_norm == q else 1, 0 if a.has_bounds else 1, a.id)

    def search_by_description(self, product_norm: str, limit: int = _TEXT_LIMIT) -> List[Dict[str, Any]]:
        """Arm 2 — full-text search over advisory prose.  Original SQL::

            SELECT DISTINCT ON (c.cve_id) c.cve_id, a.product, a.vendor, a.version,
                   a.less_than, a.less_than_or_equal, a.greater_equal,
                   c.description, c.published_at, c.cvss_score, c.cvss_severity
              FROM cves c LEFT JOIN cve_affected a ON a.cve_id = c.cve_id
             WHERE to_tsvector('english', c.description) @@ to_tsquery('english', %(q)s)
             ORDER BY c.cve_id,
                      (a.less_than <> '' OR a.less_than_or_equal <> '' OR a.greater_equal <> '') DESC,
                      a.id
             LIMIT %(limit)s

        where %(q)s is the product tokens longer than two characters joined by ' & '.
        """
        tokens = [t for t in (product_norm or "").split() if len(t) > 2]
        if not tokens:
            return []
        query_lexemes: List[str] = []
        for t in tokens:
            query_lexemes.extend(_lexemes(t))
        if not query_lexemes:
            return []  # PostgreSQL: query contains only stop words → matches nothing
        want = set(query_lexemes)

        by_cve: Dict[str, Optional[_Affected]] = {}
        for cve_id, lex in self._lexemes.items():
            if want <= lex:
                by_cve[cve_id] = None
        if not by_cve:
            return []
        for a in self.affected:
            if a.cve_id not in by_cve:
                continue
            cur = by_cve[a.cve_id]
            if cur is None or (0 if a.has_bounds else 1, a.id) < (0 if cur.has_bounds else 1, cur.id):
                by_cve[a.cve_id] = a
        rows = [self._record(by_cve[cid], cid) for cid in sorted(by_cve)]
        return rows[:limit]

    def bounds_for(self, cve_ids: Sequence[str], product_norm: str = "",
                   max_ranges_per_cve: int = 200) -> Dict[str, List[Dict[str, str]]]:
        """CNA structural bounds, all ranges per CVE.  Original SQL::

            SELECT a.cve_id, a.product, a.vendor, a.version, a.default_status,
                   a.less_than, a.less_than_or_equal, a.greater_equal,
                   (bounds non-empty) AS has_bounds, left(c.description, 600) AS description
              FROM cve_affected a JOIN cves c ON c.cve_id = a.cve_id
             WHERE a.cve_id = ANY(%(ids)s)
               AND (bounds non-empty OR a.version ~ %(exact)s)
             ORDER BY a.cve_id, (a.product_norm = %(q)s) DESC, has_bounds DESC, a.id
        """
        ids = {str(c).upper() for c in cve_ids if c}
        if not ids:
            return {}
        q = product_norm or ""
        rows = [a for a in self.affected
                if a.cve_id in ids and (a.has_bounds or _EXACT_VERSION_RE.match(a.version))]
        rows.sort(key=lambda a: (a.cve_id, 0 if a.product_norm == q else 1, 0 if a.has_bounds else 1, a.id))
        out: Dict[str, List[Dict[str, str]]] = {}
        for a in rows:
            ranges = out.setdefault(a.cve_id, [])
            if len(ranges) >= max_ranges_per_cve:
                continue
            ranges.append({
                "less_than": a.less_than or "",
                "less_than_or_equal": a.less_than_or_equal or "",
                "greater_equal": a.greater_equal or "",
                "version": "" if a.has_bounds else (a.version or ""),
                "default_status": a.default_status or "",
                "product": a.product or "",
                "vendor": a.vendor or "",
                "text": (self.cves[a.cve_id]["description"] or "")[:600],
            })
        return out

    def cpe_bounds_for(self, cve_ids: Sequence[str], product_norm: str = "",
                       max_ranges_per_cve: int = 60) -> Dict[str, List[Dict[str, str]]]:
        """NVD CPE applicability ranges (appended after CNA rows by the caller).  Original SQL::

            SELECT cve_id, product, product_norm, vendor, version,
                   less_than, less_than_or_equal, greater_equal, greater_than
              FROM cve_cpe WHERE cve_id = ANY(%(ids)s)
             ORDER BY cve_id, (product_norm = %(q)s) DESC, id

        followed by the Python filter `covers_product(row.product_norm, product_norm)`.
        """
        ids = {str(c).upper() for c in cve_ids if c}
        if not ids:
            return {}
        from refimpl.disambiguation import covers_product

        q = product_norm or ""
        rows = [r for r in self.cpe if r.cve_id in ids]
        rows.sort(key=lambda r: (r.cve_id, 0 if r.product_norm == q else 1, r.id))
        out: Dict[str, List[Dict[str, str]]] = {}
        for r in rows:
            if q and not covers_product(r.product_norm, q):
                continue
            ranges = out.setdefault(r.cve_id, [])
            if len(ranges) >= max_ranges_per_cve:
                continue
            ranges.append({
                "less_than": r.less_than or "",
                "less_than_or_equal": r.less_than_or_equal or "",
                "greater_equal": r.greater_equal or "",
                "greater_than": r.greater_than or "",
                "version": r.version or "",
                "product": r.product or "",
                "vendor": r.vendor or "",
                "source": "nvd-cpe",
                "default_status": "",
                "text": "",
            })
        return out

    def product_family_names(self, product_norm: str, limit: int = 6) -> List[str]:
        """Original SQL::

            SELECT DISTINCT product_norm FROM cve_affected
             WHERE product_norm = %(q)s OR product_norm LIKE %(prefix)s   -- 'q %'
             ORDER BY product_norm LIMIT %(limit)s
        """
        q = (product_norm or "").strip()
        if not q:
            return []
        names = sorted({a.product_norm for a in self.affected
                        if a.product_norm == q or a.product_norm.startswith(q + " ")})
        return names[:limit]

    def risk_for(self, cve_ids: Sequence[str]) -> Dict[str, Dict[str, Any]]:
        """Risk signals per CVE (KEV / EPSS / CVSS / CWE / exploit flag), same keys as
        `cve_repo.risk_for`. Every known CVE gets an entry (LEFT JOIN semantics)."""
        out: Dict[str, Dict[str, Any]] = {}
        for raw in cve_ids:
            cid = str(raw or "").upper()
            c = self.cves.get(cid)
            if not c:
                continue
            r = c["risk"] or {}
            out[cid] = {
                "kev": bool(r.get("kev")),
                "kev_due_date": r.get("kev_due_date"),
                "kev_added": r.get("kev_added"),
                "ransomware": bool(r.get("ransomware")),
                "kev_action": r.get("kev_action") or "",
                "epss": float(r["epss"]) if r.get("epss") is not None else None,
                "epss_percentile": (float(r["epss_percentile"])
                                    if r.get("epss_percentile") is not None else None),
                "epss_date": r.get("epss_date"),
                "cvss": (float(r["cvss"]) if r.get("cvss") is not None
                         else (float(c["cvss_score"]) if c["cvss_score"] is not None else None)),
                "cvss_severity": r.get("cvss_severity") or c["cvss_severity"] or "",
                "cvss_vector": r.get("cvss_vector") or "",
                "cwes": list(r.get("cwes") or []),
                "exploit_known": bool(r.get("exploit_known")),
            }
        return out
