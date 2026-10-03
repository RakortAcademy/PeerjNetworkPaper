#!/usr/bin/env python3
"""
Shared readers and normalisation helpers for the Section 4 ("Estate Structure:
A Measurement Study") analysis scripts.

Input format
------------
A NAC installed-application export in the platform's native tabular format
(``.xlsx`` or ``.csv``), one file per estate, carrying at minimum:

    endpoint identifier, product display name, version string, deletion flag

and, where the exporting platform provides them:

    vendor string, architecture marker, operating-system family

Column names are resolved by a set of recognised header aliases (see
``COLUMN_ALIASES``) rather than by position, because exporters differ in
column order and in which optional columns they carry at all.

Reduction
---------
``reduce_estate`` applies the reduction the manuscript describes in
Section 4.1: rows flagged deleted are dropped; rows without a product name
are dropped; rows without a version are dropped as unscannable, and counted,
because a verdict is a version comparison and a row lacking one can only
abstain. Remaining rows are merged on (product name, version) after
whitespace and case normalisation.

One deviation from the deployed exporter is intentional and is stated in the
paper: the deployed exporter's merge key additionally includes the endpoint's
operating-system family, because the same display name on different
platforms is not the same installation. These exports carry no reliable
operating-system join in general, so the OS component is folded in only when
the column is present; omitting it can only *merge* groups that the deployed
exporter would keep separate, so the reduction and fan-out figures this
script reports are upper bounds on what the deployed exporter achieves, as
stated in Section 4.1.
"""
from __future__ import annotations

import csv
import os
import re
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import openpyxl
except ImportError:  # pragma: no cover - only needed for .xlsx input
    openpyxl = None


# Recognised header aliases per logical column. Matching is case-insensitive
# and whitespace-normalised (see _clean_header). The first alias to match a
# header in the file wins.
COLUMN_ALIASES: Dict[str, Tuple[str, ...]] = {
    "endpoint_id": ("endpoint_id", "endpoint", "endpointid", "asset_id",
                     "assetid", "device_id", "deviceid", "host_id", "hostid"),
    "name": ("name", "product", "product_name", "productname", "application",
              "app_name", "appname", "display_name", "displayname"),
    "version": ("version", "product_version", "productversion", "app_version",
                 "appversion"),
    "vendor": ("vendor", "publisher", "manufacturer"),
    "architecture": ("architecture", "arch"),
    "client_deleted": ("client_deleted", "clientdeleted", "deleted",
                         "is_deleted", "isdeleted", "removed"),
    "os_family": ("os_family", "osfamily", "os", "operating_system",
                   "operatingsystem", "platform"),
}
REQUIRED = ("endpoint_id", "name", "version")

# A handful of exports are unreadable rather than merely empty: a database
# error serialised into every cell rather than an absent file. The paper's
# Section 4.1 records exactly this for one of the nine source exports. This
# is a compatibility heuristic, not a general corruption detector: it exists
# to keep a corrupt file from silently contributing zeros to the aggregate,
# and it is deliberately conservative (matches only unambiguous stack-trace
# / driver-error text) so it does not mistake unusual-but-real product names
# for corruption.
_CORRUPT_MARKERS = (
    "failed to load", "stacktrace", "connection refused",
    "org.postgresql", "com.microsoft.sqlserver", "traceback (most recent",
)


def norm(value: Any) -> str:
    """Collapse whitespace and case, matching the exporter's merge key."""
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).strip()).lower()


def display(value: Any) -> str:
    """Collapse whitespace only; preserves case for display/matching."""
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).strip())


def _clean_header(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"[^a-z0-9]", "", str(value).strip().lower())


def _resolve_columns(header: List[Any]) -> Dict[str, int]:
    cleaned = [_clean_header(h) for h in header]
    resolved: Dict[str, int] = {}
    for field, aliases in COLUMN_ALIASES.items():
        alias_set = {a.replace("_", "") for a in aliases}
        for position, key in enumerate(cleaned):
            if key in alias_set:
                resolved[field] = position
                break
    return resolved


def _looks_corrupt(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(marker in lowered for marker in _CORRUPT_MARKERS)


def _rows_from_xlsx(path: str):
    if openpyxl is None:
        sys.exit("openpyxl required for .xlsx input:  pip install openpyxl")
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    try:
        for row in ws.iter_rows(values_only=True):
            yield row
    finally:
        wb.close()


def _rows_from_csv(path: str):
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.reader(f):
            yield row


def read_export(path: str) -> Optional[List[Dict[str, Any]]]:
    """Read one estate export. Returns ``None`` if the file is unreadable.

    A file that is present but carries a serialised error in place of every
    row (see ``_CORRUPT_MARKERS``) is treated the same as an unreadable file:
    excluded, and the caller is expected to report the exclusion rather than
    silently treat it as an empty estate.
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xlsx":
        row_iter = _rows_from_xlsx(path)
    elif ext == ".csv":
        row_iter = _rows_from_csv(path)
    else:
        sys.exit(f"unsupported export format: {path} (expected .xlsx or .csv)")

    try:
        header = next(row_iter)
    except StopIteration:
        return None

    index = _resolve_columns(list(header))
    if not all(field in index for field in REQUIRED):
        return None

    records: List[Dict[str, Any]] = []
    corrupt = 0
    for row in row_iter:
        if row is None:
            continue
        row = list(row)

        def cell(field: str) -> Any:
            position = index.get(field)
            if position is None or position >= len(row):
                return None
            return row[position]

        raw_name = cell("name")
        if _looks_corrupt(raw_name):
            corrupt += 1
            continue

        deleted_raw = cell("client_deleted")
        record = {
            "endpoint_id": cell("endpoint_id"),
            "name": raw_name,
            "version": cell("version"),
            "vendor": cell("vendor"),
            "architecture": cell("architecture"),
            "os_family": cell("os_family"),
            "client_deleted": _coerce_bool(deleted_raw),
        }
        records.append(record)

    if corrupt and not records:
        return None
    return records


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    text = str(value).strip().lower()
    return text in ("true", "1", "yes", "t", "y")


def percentile(values_ascending: List[int], q: float) -> float:
    """Linear-interpolated percentile over an ascending list of values."""
    if not values_ascending:
        return 0.0
    position = q * (len(values_ascending) - 1)
    low = int(position)
    high = min(low + 1, len(values_ascending) - 1)
    weight = position - low
    return values_ascending[low] * (1 - weight) + values_ascending[high] * weight


class Estate:
    """The reduced structure of one estate export.

    ``items`` keys on (product, version) after normalisation, per Section 4.1
    (folded further by ``os_family`` when that column is present, matching
    the deployed exporter's merge key). ``products`` groups items by product
    alone, which is the unit of shared preparation (Section 4.3).
    """

    def __init__(self) -> None:
        self.raw_rows = 0
        self.dropped_deleted = 0
        self.dropped_noname = 0
        self.dropped_noversion = 0
        self.endpoints: Set[Any] = set()
        # (product_norm, version_norm, os_norm) -> entry
        self.items: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        # product_norm -> {"display": str, "versions": set(version_norm), "rows": int}
        self.products: Dict[str, Dict[str, Any]] = {}
        # product_norm -> first display string seen among *live, named* rows
        # (includes versionless rows). The lexical study (Table 6) does NOT use
        # this: it measures the scannable product population, i.e. ``products``.
        self.names_seen: Dict[str, str] = {}

    @property
    def live_rows(self) -> int:
        return self.raw_rows - self.dropped_deleted - self.dropped_noname

    @property
    def scannable_rows(self) -> int:
        return sum(e["rows"] for e in self.items.values())

    @property
    def unique_items(self) -> int:
        return len(self.items)

    @property
    def product_groups(self) -> int:
        return len(self.products)

    @property
    def no_version_pct(self) -> float:
        live = self.live_rows
        return (100.0 * self.dropped_noversion / live) if live else 0.0

    @property
    def rho_item(self) -> float:
        u = self.unique_items
        return (self.scannable_rows / u) if u else 0.0

    @property
    def rho_group(self) -> float:
        g = self.product_groups
        return (self.unique_items / g) if g else 0.0

    @property
    def reduction_pct(self) -> float:
        r = self.scannable_rows
        return (100.0 * (1 - self.unique_items / r)) if r else 0.0

    def fanout_counts(self) -> List[int]:
        """Fan-out per scan item, descending: the number of inventory rows
        merged into each (product, version) item.

        This is the quantity behind Table 5 and Figure 1 (the original study
        analysis counted rows per item, not distinct endpoints), so an item
        installed more than once on the same endpoint counts once per row;
        the manuscript notes exactly this for the largest E3 item, whose
        fan-out exceeds the estate's endpoint count. ``endpoint_fanout_counts``
        gives the distinct-endpoint variant, which no manuscript table uses.
        """
        return sorted((e["rows"] for e in self.items.values()), reverse=True)

    def endpoint_fanout_counts(self) -> List[int]:
        """Distinct endpoints per scan item, descending (not used by any
        manuscript table; kept for operators who want the endpoint view)."""
        return sorted((len(e["endpoints"]) for e in self.items.values()), reverse=True)

    def versions_per_product(self) -> List[int]:
        return sorted((len(p["versions"]) for p in self.products.values()), reverse=True)


def reduce_estate(records: List[Dict[str, Any]]) -> Estate:
    estate = Estate()
    estate.raw_rows = len(records)

    for record in records:
        if record.get("client_deleted"):
            estate.dropped_deleted += 1
            continue

        product = display(record.get("name"))
        if not product:
            estate.dropped_noname += 1
            continue

        product_key = norm(product)
        if product_key not in estate.names_seen:
            estate.names_seen[product_key] = product

        version = display(record.get("version"))
        if not version:
            estate.dropped_noversion += 1
            continue

        endpoint = record.get("endpoint_id")
        if endpoint is not None:
            estate.endpoints.add(endpoint)

        os_key = norm(record.get("os_family")) if record.get("os_family") else ""
        key = (product_key, norm(version), os_key)
        entry = estate.items.get(key)
        if entry is None:
            entry = {"product": product, "version": version, "endpoints": set(), "rows": 0}
            estate.items[key] = entry
        entry["rows"] += 1
        if endpoint is not None:
            entry["endpoints"].add(endpoint)

        group = estate.products.get(product_key)
        if group is None:
            group = {"display": product, "versions": set(), "rows": 0}
            estate.products[product_key] = group
        group["versions"].add(norm(version))
        group["rows"] += 1

    return estate


def label_for(path: str, fallback_index: int) -> str:
    """Estate label from the export's filename: a trailing number N in the
    file stem gives the label EN (``estate3.xlsx`` -> ``E3``), matching the
    arbitrary estate labels used in the manuscript; falls back to sequential
    numbering for exports whose stem does not end in a number.
    """
    stem = os.path.splitext(os.path.basename(path))[0]
    m = re.search(r"(\d+)$", stem)
    return "E" + m.group(1) if m else f"E{fallback_index}"


def discover_exports(paths: Optional[List[str]], directory: Optional[str]) -> List[str]:
    found: List[str] = list(paths or [])
    if directory:
        for f in sorted(os.listdir(directory)):
            if f.lower().endswith((".xlsx", ".csv")):
                found.append(os.path.join(directory, f))
    if not found:
        sys.exit("no exports given: pass --export (repeatable) or --dir")
    return found
