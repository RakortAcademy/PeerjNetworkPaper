#!/usr/bin/env python3
"""
Regenerate Table 6 ("Lexical features of inventory product strings",
Section 4.6) from NAC installed-application exports.

Method
------
Each lexical class is a transformation that normalisation must undo before an
inventory name can be compared with an advisory product name. Classes are not
mutually exclusive; a single string routinely exhibits several.

Prevalence is computed per distinct product *name*, not per row, and summed
across estates without cross-estate de-duplication -- so that a single widely
deployed application does not dominate the figure, and so that the pooled
denominator matches Table 3's pooled product-group count (Section 4.6 states
this explicitly: 13,424 strings summed over the eight estates, 7,604 distinct
after cross-estate de-duplication).

Usage
-----
    python3 lexical_features.py --export customer1.xlsx --export customer3.xlsx \\
        --out out/
    python3 lexical_features.py --dir path/to/exports --out out/
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import Counter
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import discover_exports, label_for, read_export, reduce_estate  # noqa: E402


# Lexical noise classes, in the order reported in Table 6 (descending measured
# prevalence in the manuscript's eight estates; a new export may reorder
# these, which is why the script sorts by measured share before writing).
NOISE: Dict[str, re.Pattern] = {
    "Vendor prefix": re.compile(
        r"^(microsoft|google|adobe|oracle|apache|mozilla|intel|nvidia|amd|hp|"
        r"dell|lenovo|vmware|sap|autodesk|cisco|citrix)\b", re.I),
    "Embedded version": re.compile(r"\b\d+(\.\d+){1,}\b"),
    "Architecture marker": re.compile(
        r"\b(x86|x64|amd64|win32|win64|32[- ]?bit|64[- ]?bit|\(x8[64]\))\b", re.I),
    "Year designator": re.compile(r"\b(19|20)\d{2}\b"),
    "Packaging vocabulary": re.compile(
        r"\b(setup|installer|redistributable|runtime|update|hotfix|"
        r"service pack|sp[123]|package|component|click-to-run|msi)\b", re.I),
    "Non-ASCII characters": re.compile(r"[^\x00-\x7F]"),
    "Locale qualifier": re.compile(
        r"\b(mui|turkish|t[uü]rk[cç]e|english|deutsch|fran[cç]ais|espa[nñ]ol|"
        r"italiano|portugu[eê]s|русский|日本語|中文|nederlands|polski|"
        r"[a-z]{2}-[A-Z]{2})\b", re.I),
    "Edition qualifier": re.compile(
        r"\b(professional|enterprise|standard|home|pro|ultimate|community|"
        r"express|edition|premium|basic)\b", re.I),
}

# Illustrative fragments for the table's second column; these are the ones
# quoted in the manuscript and are display text, not part of the matching
# logic above.
EXAMPLES: Dict[str, str] = {
    "Vendor prefix": "Microsoft...; Google...",
    "Embedded version": "...14.40.33810",
    "Architecture marker": "(x64); 32-bit",
    "Year designator": "...2016",
    "Packaging vocabulary": "Redistributable; Click-to-Run",
    "Non-ASCII characters": "Çalışma Zamanı",
    "Locale qualifier": "MUI (Turkish); Deutsch",
    "Edition qualifier": "Professional; Enterprise",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", action="append", metavar="PATH",
                         help="an estate export (.xlsx or .csv); repeatable")
    parser.add_argument("--dir", metavar="DIR", help="directory of estate exports")
    parser.add_argument("--out", required=True, metavar="DIR", help="output directory")
    args = parser.parse_args()

    paths = discover_exports(args.export, args.dir)
    os.makedirs(args.out, exist_ok=True)

    noise_counts = Counter()
    total_names = 0
    skipped: List[str] = []

    for index, path in enumerate(paths, start=1):
        label = label_for(path, index)
        records = read_export(path)
        if not records:
            skipped.append(f"{os.path.basename(path)} ({label})")
            continue
        estate = reduce_estate(records)
        # names_seen holds one display string per distinct normalised product
        # name in this estate -- the per-estate distinct-name population the
        # classes are measured over, matching Table 6's denominator.
        for display_name in estate.names_seen.values():
            total_names += 1
            for feature, pattern in NOISE.items():
                if pattern.search(display_name):
                    noise_counts[feature] += 1

    if not total_names:
        sys.exit("no scannable product names found across the given exports")

    ranked = sorted(noise_counts.items(), key=lambda kv: -kv[1])
    rows = [[feature, EXAMPLES.get(feature, ""), round(100.0 * count / total_names, 1)]
            for feature, count in ranked]

    out_path = os.path.join(args.out, "table6_lexical_features.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        f.write("# Table 6: Lexical features of inventory product strings (Section 4.6)\n")
        f.write(f"# Over {total_names:,} product strings summed across the given estates "
                "(classes are not mutually exclusive)\n")
        if skipped:
            f.write(f"# Excluded (unreadable): {', '.join(skipped)}\n")
        writer = csv.writer(f)
        writer.writerow(["feature", "example_fragment", "share_pct"])
        for row in rows:
            writer.writerow(row)
    print(f"wrote {out_path}")

    print(f"\n{total_names:,} distinct product names, {len(paths) - len(skipped)} estates:")
    for feature, count in ranked:
        print(f"  {feature:22s} {count:7,}  {100.0 * count / total_names:5.1f}%")
    if skipped:
        print(f"\nexcluded (unreadable): {', '.join(skipped)}")


if __name__ == "__main__":
    main()
