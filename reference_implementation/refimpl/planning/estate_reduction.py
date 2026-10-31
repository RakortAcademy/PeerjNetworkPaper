"""Estate-level reduction and fan-back (manuscript Section 6.1).

The production exporter read the NAC platform's
installed-application table over a database connection and reduced the
per-endpoint rows to unique scan items. The database access is not included
here; the reduction itself — `os_family`, `clean`, `collect` — is the exporter's
code verbatim, operating on already-fetched rows of the shape the query
returned:

    (endpoint_id, name, version, vendor, architecture, os_text, os_type)

Merge key = (product, version, operating-system family); vendor is deliberately
NOT in the key (most frequent non-empty vendor is adopted per group); each item
keeps the sorted list of contributing endpoints so one verdict can be fanned
back to every endpoint (`fan_back`).
"""
from __future__ import annotations

import re
from collections import Counter, OrderedDict
from typing import Any, Dict, List, Optional, Tuple

# İşletim sistemi metninden aile çıkarımı. Metin birincil kaynak: müşteri
# ajanları "Microsoft Windows 11 Pro", "macOS 26.5", "Ubuntu 22.04" gibi
# okunabilir değerler yazıyor ve bu her kurulumda aynı biçimde çalışıyor.
_OS_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (r"\bwindows\s+server\b", "Windows Server"),
    (r"\bwindows\b|\bmicrosoft\s+windows\b", "Windows"),
    (r"\bmac\s?os\b|\bmacos\b|\bos\s?x\b|\bdarwin\b", "macOS"),
    (r"\bios\b|\bipados\b", "iOS"),
    (r"\bandroid\b", "Android"),
    (r"\bubuntu\b|\bdebian\b|\bcentos\b|\brhel\b|\bred\s?hat\b|\bfedora\b"
     r"|\bsuse\b|\balma\b|\brocky\b|\bkali\b|\bmint\b|\blinux\b", "Linux"),
)

# `os` metni boşsa geriye kalan tek ipucu `os_type`. Yalnızca canlı veride
# GÖRÜLEN iki değer eşlenir; kalanı tahmin olurdu ve yanlış platform kapısı
# gerçek tehdidi eler. Bilinmeyen tür → işletim sistemi boş bırakılır, tarayıcı
# da platform kapısını uygulamaz.
_OS_TYPE_MAP: Dict[int, str] = {1: "Windows", 3: "macOS"}


def os_family(os_text: Optional[str], os_type: Optional[int]) -> Optional[str]:
    text = (os_text or "").strip().lower()
    for pattern, family in _OS_PATTERNS:
        if re.search(pattern, text):
            return family
    if os_type is not None:
        return _OS_TYPE_MAP.get(int(os_type))
    return None


def clean(value: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def collect(rows: List[tuple], keep_versionless: bool) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Uç nokta başına satırları tekil tarama kalemlerine indirger."""
    groups: "OrderedDict[Tuple[str, str, str], Dict[str, Any]]" = OrderedDict()
    skipped_noname = 0
    skipped_noversion = 0

    for endpoint_id, name, version, vendor, arch, os_text, os_type in rows:
        product = clean(name)
        if not product:
            skipped_noname += 1
            continue

        ver = clean(version)
        if not ver:
            skipped_noversion += 1
            if not keep_versionless:
                # Sürümsüz kalem taranamaz: CVE kararı sürüm karşılaştırmasıdır,
                # sürüm yoksa sonuç her zaman UNCERTAIN olur ve gürültü yaratır.
                continue

        family = os_family(os_text, os_type)
        key = (product.lower(), ver.lower(), (family or "").lower())

        group = groups.get(key)
        if group is None:
            group = {
                "product": product,
                "version": ver,
                "operating_system": family,
                "_vendors": Counter(),
                "_arch": Counter(),
                "endpoints": [],
            }
            groups[key] = group

        v = clean(vendor)
        if v:
            group["_vendors"][v] += 1
        a = clean(arch)
        if a:
            group["_arch"][a] += 1
        if endpoint_id is not None:
            group["endpoints"].append(int(endpoint_id))

    items: List[Dict[str, Any]] = []
    for group in groups.values():
        vendors: Counter = group.pop("_vendors")
        arches: Counter = group.pop("_arch")
        endpoints = sorted(set(group["endpoints"]))

        item: Dict[str, Any] = {
            "product": group["product"],
            "version": group["version"],
        }
        if vendors:
            # Aynı ürünü bazı ajanlar satıcısız bildiriyor; en sık görülen boş
            # olmayan değer alınır. Satıcı jenerik adları çözdüğü için
            # ("Calendar" tek başına onlarca satıcıda var) elde varsa gönderilir.
            item["vendor"] = vendors.most_common(1)[0][0]
        if group["operating_system"]:
            item["operating_system"] = group["operating_system"]

        item["endpoint_count"] = len(endpoints)
        item["endpoints"] = endpoints
        if arches:
            item["architecture"] = arches.most_common(1)[0][0]
        items.append(item)

    items.sort(key=lambda it: (-it["endpoint_count"], it["product"].lower(), it["version"]))

    stats = {
        "app_rows": len(rows),
        "unique_items": len(items),
        "skipped_no_name": skipped_noname,
        "skipped_no_version": 0 if keep_versionless else skipped_noversion,
        "versionless_rows": skipped_noversion,
    }
    return items, stats


def fan_back(items: List[Dict[str, Any]], results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Propagate one verdict per item back to every contributing endpoint.

    Reviewer wrapper (not production code): production performed this join in
    the NAC console using the `endpoints` list each item carries. The scan
    computes U verdicts; the output here has one row per (endpoint, item), i.e.
    the R endpoint-level exposures of Section 6.1 — `len(output) == sum(endpoint_count)`.
    """
    if len(items) != len(results):
        raise ValueError("items and results must align one-to-one")
    rows: List[Dict[str, Any]] = []
    for item, result in zip(items, results):
        for endpoint in item.get("endpoints") or []:
            rows.append({
                "endpoint_id": endpoint,
                "product": item["product"],
                "version": item["version"],
                "operating_system": item.get("operating_system"),
                "status": result.get("status"),
                "threat_count": len(result.get("threats") or []),
                "threat_cve_ids": [t.get("cve_id") for t in (result.get("threats") or [])],
                "computed": True if endpoint == (item.get("endpoints") or [None])[0] else False,
            })
    return rows
