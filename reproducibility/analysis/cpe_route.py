#!/usr/bin/env python3
"""
Regenerate Table 7 ("The CPE-dictionary route on the eight estates",
Section 4.7) from NAC installed-application exports and the published CPE
dictionary.

What this measures
-------------------
How far the standard inventory-matching pipeline -- resolve the display
string to a canonical CPE product identifier, then check whether the
resolved product has a version-bounded advisory -- gets *without* the
full-text/normalisation matching this work otherwise argues for. It is a
baseline for the approach, not a benchmark of any vendor's scanner: a
network-probing scanner is excluded by construction, since it cannot observe
a locally installed application at all.

Resolution is measured in four cumulative tiers against the dictionary:

    1. case folding and punctuation collapse only (an unassisted lookup)
    2. + architecture markers and packaging vocabulary stripped
    3. + locale, edition and year qualifiers stripped
    4. + embedded version numerals stripped

Tiers 3-4 exceed what a CPE-based scanner would normally attempt -- tier 4 in
particular is actively unsafe in production, since it destroys identity for
products whose numeral is part of the name (Section 4.6) -- so a string that
resolves under none of the four tiers has not merely been matched carelessly.

A second stage checks, among names resolved at tier 4, whether the resolved
product also carries a version-bounded advisory in a supplied applicability
corpus; this stage is skipped (and reported as such) if no corpus is given,
since the advisory corpus is not part of this public package (see
``DATA_AVAILABILITY.md`` item 2).

Inputs
------
--cpe-dictionary  Official NVD CPE dictionary, as either:
                    * the official XML (``official-cpe-dictionary_v2.3.xml``
                      from https://nvd.nist.gov/products/cpe), or
                    * a flat CSV/TSV with columns ``cpe23uri,title[,part]``
                  where ``part`` is one of a/o/h (application/OS/hardware);
                  entries without a part column are treated as applications.
--advisory-corpus (optional) CSV with columns ``cpe_product,version_bounded``
                  where ``cpe_product`` is a resolved CPE product identifier
                  (vendor:product, or a full CPE URI/name -- only the vendor
                  and product components are used) and ``version_bounded``
                  is a boolean flag ("true"/"false", "1"/"0", ...).

Usage
-----
    python3 cpe_route.py --export estate1.xlsx --dir path/to/exports \\
        --cpe-dictionary official-cpe-dictionary_v2.3.xml --out out/
    python3 cpe_route.py --dir path/to/exports \\
        --cpe-dictionary dictionary.csv --advisory-corpus corpus.csv --out out/
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import discover_exports, label_for, norm, read_export, reduce_estate  # noqa: E402


_ARCH_PACKAGING = re.compile(
    r"\b(x86|x64|amd64|win32|win64|32[- ]?bit|64[- ]?bit|"
    r"setup|installer|redistributable|runtime|update|hotfix|"
    r"service pack|sp[123]|package|component|click-to-run|msi)\b", re.I)
_LOCALE_EDITION_YEAR = re.compile(
    r"\b(mui|turkish|t[uü]rk[cç]e|english|deutsch|fran[cç]ais|espa[nñ]ol|"
    r"italiano|portugu[eê]s|nederlands|polski|[a-z]{2}-[A-Z]{2}|"
    r"professional|enterprise|standard|home|pro|ultimate|community|express|"
    r"edition|premium|basic|(19|20)\d{2})\b", re.I)
_EMBEDDED_VERSION = re.compile(r"\b\d+([.\-]\d+){1,}\w*\b")
_PUNCTUATION = re.compile(r"[^a-z0-9 ]")


def tier1(name: str) -> str:
    """Case folding and punctuation collapse only."""
    text = _PUNCTUATION.sub(" ", name.lower())
    return re.sub(r"\s+", " ", text).strip()


def tier2(name: str) -> str:
    text = _ARCH_PACKAGING.sub(" ", name)
    return tier1(text)


def tier3(name: str) -> str:
    text = _LOCALE_EDITION_YEAR.sub(" ", name)
    return tier2(text)


def tier4(name: str) -> str:
    text = _EMBEDDED_VERSION.sub(" ", name)
    return tier3(text)


TIERS: Tuple[Tuple[str, str], ...] = (
    ("Case and punctuation only", "tier1"),
    ("+ architecture and packaging", "tier2"),
    ("+ locale and edition and year", "tier3"),
    ("+ embedded version stripped", "tier4"),
)
TIER_FUNCS = {"tier1": tier1, "tier2": tier2, "tier3": tier3, "tier4": tier4}


def _product_of(cpe_text: str) -> Tuple[str, str]:
    """Extract (vendor, product) and the dictionary title's normalised form
    from either a CPE 2.3 formatted string URI (``cpe:2.3:a:vendor:product:...``)
    or a legacy CPE 2.2 URI (``cpe:/a:vendor:product:...``)."""
    parts = re.split(r"[:/]", cpe_text)
    parts = [p for p in parts if p]
    # parts[0] == "cpe", parts[1] == schema version marker ("2.3") or the
    # part component itself for 2.2 URIs; normalise by locating the part
    # letter (a/o/h) and reading the two components after it.
    for i, p in enumerate(parts):
        if p in ("a", "o", "h") and i + 2 < len(parts):
            return parts[i + 1], parts[i + 2]
    return "", ""


def load_dictionary(path: str, include_os: bool, include_hardware: bool) -> List[Dict[str, str]]:
    """Load CPE dictionary entries as [{"vendor", "product", "title"}]."""
    ext = os.path.splitext(path)[1].lower()
    entries: List[Dict[str, str]] = []
    allowed_parts = {"a"} | ({"o"} if include_os else set()) | ({"h"} if include_hardware else set())

    if ext == ".xml":
        # The official NVD CPE dictionary schema: <cpe-list><cpe-item name="cpe:/a:...">
        # <title xml:lang="en-US">...</title> ... <cpe-23:cpe23-item name="cpe:2.3:a:..."/>
        ns = {"cpe": "http://cpe.mitre.org/dictionary/2.0",
              "cpe23": "http://scap.nist.gov/schema/cpe-extension/2.3"}
        for _, elem in ET.iterparse(path, events=("end",)):
            tag = elem.tag.rsplit("}", 1)[-1]
            if tag != "cpe-item":
                continue
            if elem.get("deprecated") == "true":
                elem.clear()
                continue
            cpe22_name = elem.get("name", "")
            cpe23 = elem.find("cpe23:cpe23-item", ns)
            cpe_name = cpe23.get("name") if cpe23 is not None else cpe22_name
            vendor, product = _product_of(cpe_name)
            part = ""
            m = re.search(r"cpe(?::2\.3)?:/?a?o?h?:?", cpe_name)
            m2 = re.match(r"cpe(?::2\.3)?:/?([aoh])", cpe_name)
            part = m2.group(1) if m2 else "a"
            if part not in allowed_parts:
                elem.clear()
                continue
            title_elem = elem.find("cpe:title[@xml:lang='en-US']",
                                    {"cpe": "http://cpe.mitre.org/dictionary/2.0",
                                     "xml": "http://www.w3.org/XML/1998/namespace"})
            title = title_elem.text if title_elem is not None else product
            if vendor and product:
                entries.append({"vendor": vendor, "product": product, "title": title or product})
            elem.clear()
        return entries

    if ext in (".csv", ".tsv"):
        delimiter = "\t" if ext == ".tsv" else ","
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f, delimiter=delimiter)
            for row in reader:
                part = (row.get("part") or "a").strip().lower() or "a"
                if part not in allowed_parts:
                    continue
                cpe_text = row.get("cpe23uri") or row.get("cpe_name") or ""
                vendor, product = _product_of(cpe_text)
                title = row.get("title") or product
                if vendor and product:
                    entries.append({"vendor": vendor, "product": product, "title": title})
        return entries

    sys.exit(f"unsupported CPE dictionary format: {path} (expected .xml, .csv or .tsv)")


def build_tier_index(entries: List[Dict[str, str]], tier_func) -> Dict[str, Set[str]]:
    """Map normalised title -> set of "vendor:product" identifiers, at one
    normalisation tier. Building one index per tier (rather than normalising
    on every lookup) keeps a full CPE dictionary (order 10^5-10^6 entries)
    tractable against an estate's product-name population."""
    index: Dict[str, Set[str]] = {}
    for entry in entries:
        key = tier_func(entry["title"])
        if not key:
            continue
        index.setdefault(key, set()).add(f"{entry['vendor']}:{entry['product']}")
        # Also index the raw product component: many titles differ from the
        # product token, and a scanner's baseline lookup routinely tries both.
        key2 = tier_func(entry["product"].replace("_", " "))
        if key2:
            index.setdefault(key2, set()).add(f"{entry['vendor']}:{entry['product']}")
    return index


def load_advisory_corpus(path: str) -> Set[str]:
    """CPE products (``vendor:product``) with at least one version-bounded
    applicability row."""
    bounded: Set[str] = set()
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            flag = str(row.get("version_bounded", "")).strip().lower()
            if flag not in ("true", "1", "yes", "t", "y"):
                continue
            raw = row.get("cpe_product", "")
            if ":" in raw and raw.count(":") >= 3:
                vendor, product = _product_of(raw)
            else:
                vendor, product = (raw.split(":", 1) + [""])[:2]
            if vendor and product:
                bounded.add(f"{vendor}:{product}")
    return bounded


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", action="append", metavar="PATH")
    parser.add_argument("--dir", metavar="DIR")
    parser.add_argument("--cpe-dictionary", required=True, metavar="PATH",
                         help="official CPE dictionary (.xml) or a flat cpe23uri,title[,part] table (.csv/.tsv)")
    parser.add_argument("--advisory-corpus", metavar="PATH",
                         help="optional cpe_product,version_bounded CSV for the stage-2 check; "
                              "omit to report resolution tiers only")
    parser.add_argument("--include-os", action="store_true",
                         help="admit CPE operating-system entries (invariance check, Section 4.7)")
    parser.add_argument("--include-hardware", action="store_true",
                         help="admit CPE hardware entries (invariance check, Section 4.7)")
    parser.add_argument("--out", required=True, metavar="DIR")
    args = parser.parse_args()

    paths = discover_exports(args.export, args.dir)
    os.makedirs(args.out, exist_ok=True)

    print(f"loading CPE dictionary from {args.cpe_dictionary} ...")
    entries = load_dictionary(args.cpe_dictionary, args.include_os, args.include_hardware)
    if not entries:
        sys.exit("no usable entries loaded from the CPE dictionary")
    print(f"  {len(entries):,} dictionary keys admitted")

    tier_indexes = {key: build_tier_index(entries, TIER_FUNCS[key]) for _, key in TIERS}

    bounded_products: Optional[Set[str]] = None
    if args.advisory_corpus:
        bounded_products = load_advisory_corpus(args.advisory_corpus)
        print(f"  {len(bounded_products):,} version-bounded products in the advisory corpus")

    # Pool scannable product names (with row weight) across every estate,
    # matching Table 3's pooled-not-deduplicated convention: a product present
    # in five estates is five preparation units and is weighted five times.
    total_names = 0
    total_rows = 0
    resolved_names = {key: 0 for _, key in TIERS}
    resolved_rows = {key: 0 for _, key in TIERS}
    bounded_names = 0
    bounded_rows = 0
    skipped: List[str] = []

    for index, path in enumerate(paths, start=1):
        label = label_for(path, index)
        records = read_export(path)
        if not records:
            skipped.append(label)  # label only: the export file name is not part of the public output
            continue
        estate = reduce_estate(records)
        for product_key, group in estate.products.items():
            total_names += 1
            total_rows += group["rows"]

            resolved_ids: Optional[Set[str]] = None
            already_resolved = False
            for _, tier_key in TIERS:
                if not already_resolved:
                    lookup_key = TIER_FUNCS[tier_key](group["display"])
                    ids = tier_indexes[tier_key].get(lookup_key)
                    if ids:
                        already_resolved = True
                        resolved_ids = ids
                if already_resolved:
                    resolved_names[tier_key] += 1
                    resolved_rows[tier_key] += group["rows"]

            if already_resolved and bounded_products is not None and resolved_ids:
                if resolved_ids & bounded_products:
                    bounded_names += 1
                    bounded_rows += group["rows"]

    if not total_names:
        sys.exit("no scannable products found across the given exports")

    rows = []
    for tier_label, tier_key in TIERS:
        rows.append([tier_label,
                     round(100.0 * resolved_names[tier_key] / total_names, 1),
                     round(100.0 * resolved_rows[tier_key] / total_rows, 1)])
    if bounded_products is not None:
        rows.append(["Resolved and version-bounded",
                     round(100.0 * bounded_names / total_names, 1),
                     round(100.0 * bounded_rows / total_rows, 1)])

    out_path = os.path.join(args.out, "table7_cpe_route.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        f.write("# Table 7: CPE-dictionary route on the given estates (Section 4.7)\n")
        f.write("# Share of scannable product strings and rows that resolve at each tier\n")
        f.write("# Resolution tiers are cumulative\n")
        if bounded_products is None:
            f.write("# Stage 2 (resolved and version-bounded) skipped: no --advisory-corpus given\n")
        if skipped:
            f.write(f"# Excluded (unreadable): {', '.join(skipped)}\n")
        writer = csv.writer(f)
        writer.writerow(["stage", "by_name_pct", "by_row_pct"])
        for row in rows:
            writer.writerow(row)
    print(f"wrote {out_path}")

    print(f"\n{total_names:,} products, {total_rows:,} scannable rows, "
          f"{len(paths) - len(skipped)} estates:")
    for stage, by_name, by_row in rows:
        print(f"  {stage:32s} name={by_name:5.1f}%  row={by_row:5.1f}%")
    if bounded_products is None:
        print("\n  (stage 2 skipped: pass --advisory-corpus to include it)")
    if skipped:
        print(f"\nexcluded (unreadable): {', '.join(skipped)}")


if __name__ == "__main__":
    main()
