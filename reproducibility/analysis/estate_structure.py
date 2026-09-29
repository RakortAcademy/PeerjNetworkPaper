#!/usr/bin/env python3
"""
Regenerate Tables 2-5 and Figure 1 of Section 4 ("Estate Structure: A
Measurement Study") from NAC installed-application exports.

What this reproduces
---------------------
  Table 2  version coverage of live application rows           (Section 4.2)
  Table 3  two-level redundancy (R, U, G, rho_item, rho_group)  (Section 4.3)
  Table 4  version spread within products                      (Section 4.4)
  Table 5  fan-out distribution                                 (Section 4.5)
  Figure 1 fan-out concentration curves                         (Section 4.5)

Table 6 (lexical features) and Table 7 (CPE-dictionary route) are produced by
the sibling scripts ``lexical_features.py`` and ``cpe_route.py`` in this same
directory; see ``docs/reproduction.md``.

An export that is present but unreadable (see ``common._CORRUPT_MARKERS``) is
excluded and the exclusion is printed and written into every output file's
header comment, matching the manuscript's own account in Section 4.1 of one
such excluded export among the nine held.

Usage
-----
    python3 estate_structure.py --export customer1.xlsx --export customer3.xlsx \\
        --out out/
    python3 estate_structure.py --dir path/to/exports --out out/
    python3 estate_structure.py --dir path/to/exports --out out/ \\
        --curve-estates E3,E6,E8,E7
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Estate, discover_exports, label_for, percentile, read_export, reduce_estate  # noqa: E402


def head_share(counts_desc: List[int], fraction: float) -> float:
    """Share of scannable rows covered by the largest `fraction` of items."""
    total = sum(counts_desc)
    n = len(counts_desc)
    if not total or not n:
        return 0.0
    k = max(1, int(round(n * fraction)))
    return 100.0 * sum(counts_desc[:k]) / total


def fanout_table(estate: Estate) -> Dict[str, float]:
    counts = estate.fanout_counts()
    ascending = sorted(counts)
    singletons = sum(1 for c in counts if c == 1)
    return {
        "p50": percentile(ascending, 0.50),
        "p90": percentile(ascending, 0.90),
        "p99": percentile(ascending, 0.99),
        "max": counts[0] if counts else 0,
        "top1pct": head_share(counts, 0.01),
        "top5pct": head_share(counts, 0.05),
        "top10pct": head_share(counts, 0.10),
        "singletons_pct": (100.0 * singletons / len(counts)) if counts else 0.0,
    }


def concentration_points(counts_desc: List[int], samples: int = 60) -> List[Tuple[float, float]]:
    """Sampled (items_consumed_pct, rows_covered_pct) curve, descending
    fan-out order. Sampling rather than one point per item keeps the curve
    file small; ``samples`` points plus the two endpoints suffice to
    reconstruct the plotted shape.
    """
    total = sum(counts_desc)
    n = len(counts_desc)
    if not total or not n:
        return []
    points = [(0.0, 0.0)]
    running = 0
    step = max(1, n // samples)
    for index in range(n):
        running += counts_desc[index]
        if index % step == 0 or index == n - 1:
            points.append((100.0 * (index + 1) / n, 100.0 * running / total))
    return points


def pick_curve_estates(labels: List[str], estates: Dict[str, Estate], k: int = 4) -> List[str]:
    """Auto-select estates spanning the observed concentration range, mirroring
    the manuscript's choice of E3/E7 as the extremes plus two middles
    (Section 4.5): plotting every estate makes the figure unreadable, so a
    representative subset is chosen by top-1% concentration share.
    """
    if len(labels) <= k:
        return labels
    ranked = sorted(labels, key=lambda l: head_share(estates[l].fanout_counts(), 0.01))
    chosen = {ranked[0], ranked[-1]}
    remaining = [l for l in ranked if l not in chosen]
    step = max(1, len(remaining) // (k - 2))
    for i in range(0, len(remaining), step):
        if len(chosen) >= k:
            break
        chosen.add(remaining[i])
    # Order: most concentrated first, least concentrated last (paper's order).
    return sorted(chosen, key=lambda l: -head_share(estates[l].fanout_counts(), 0.01))


def write_csv(path: str, header_comment: List[str], columns: List[str], rows: List[List[object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        for line in header_comment:
            f.write(f"# {line}\n")
        writer = csv.writer(f)
        writer.writerow(columns)
        for row in rows:
            writer.writerow(row)
    print(f"wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--export", action="append", metavar="PATH",
                         help="an estate export (.xlsx or .csv); repeatable")
    parser.add_argument("--dir", metavar="DIR",
                         help="directory of estate exports (all .xlsx/.csv files)")
    parser.add_argument("--out", required=True, metavar="DIR", help="output directory")
    parser.add_argument("--curve-estates", metavar="E1,E2,...",
                         help="comma-separated estate labels to plot in Figure 1 "
                              "(default: auto-selected to span the observed range)")
    parser.add_argument("--curve-samples", type=int, default=60,
                         help="points sampled per concentration curve (default: 60)")
    args = parser.parse_args()

    paths = discover_exports(args.export, args.dir)
    os.makedirs(args.out, exist_ok=True)

    estates: Dict[str, Estate] = {}
    skipped: List[str] = []
    for index, path in enumerate(paths, start=1):
        label = label_for(path, index)
        records = read_export(path)
        if not records:
            skipped.append(f"{os.path.basename(path)} ({label})")
            print(f"{label:6s} SKIPPED  {path}  (unreadable or empty export)")
            continue
        estates[label] = reduce_estate(records)

    if not estates:
        sys.exit("no readable exports; nothing to do")

    labels = sorted(estates, key=lambda l: int(l[1:]) if l[1:].isdigit() else 0)
    header_note = [f"Excluded (unreadable): {s}" for s in skipped] if skipped else []

    # ---- Table 2: version coverage --------------------------------------
    rows2 = []
    pooled_live = pooled_noversion = pooled_endpoints = 0
    for label in labels:
        e = estates[label]
        rows2.append([label, len(e.endpoints), e.live_rows, round(e.no_version_pct, 1)])
        pooled_live += e.live_rows
        pooled_noversion += e.dropped_noversion
        pooled_endpoints += len(e.endpoints)
    pooled_no_version_pct = (100.0 * pooled_noversion / pooled_live) if pooled_live else 0.0
    rows2.append(["Pooled", pooled_endpoints, pooled_live, round(pooled_no_version_pct, 1)])
    write_csv(os.path.join(args.out, "table2_version_coverage.csv"),
              ["Table 2: Version coverage of live application rows (Section 4.2)"] + header_note,
              ["estate", "endpoints", "live_rows", "no_version_pct"], rows2)

    # ---- Table 3: two-level redundancy (estate_structure.csv) -----------
    rows3 = []
    pooled_R = pooled_U = pooled_G = 0
    for label in labels:
        e = estates[label]
        rows3.append([label, len(e.endpoints), e.live_rows, round(e.no_version_pct, 1),
                       e.scannable_rows, e.unique_items, e.product_groups,
                       round(e.rho_item, 1), round(e.rho_group, 2), round(e.reduction_pct, 1)])
        pooled_R += e.scannable_rows
        pooled_U += e.unique_items
        pooled_G += e.product_groups
    pooled_rho_item = (pooled_R / pooled_U) if pooled_U else 0.0
    pooled_rho_group = (pooled_U / pooled_G) if pooled_G else 0.0
    pooled_reduction = (100.0 * (1 - pooled_U / pooled_R)) if pooled_R else 0.0
    rows3.append(["Pooled", pooled_endpoints, pooled_live, round(pooled_no_version_pct, 1),
                   pooled_R, pooled_U, pooled_G, round(pooled_rho_item, 1),
                   round(pooled_rho_group, 2), round(pooled_reduction, 1)])
    write_csv(os.path.join(args.out, "estate_structure.csv"),
              ["Table 3: Two-level redundancy in production estates (Section 4.3)"] + header_note,
              ["estate", "endpoints", "live_rows", "no_version_pct", "R_scannable",
               "U_items", "G_products", "rho_item", "rho_group", "reduction_pct"], rows3)

    # ---- Table 4: version spread ------------------------------------------
    rows4 = []
    for label in labels:
        e = estates[label]
        spread = e.versions_per_product()
        multi = sum(1 for n in spread if n > 1)
        g = e.product_groups
        rows4.append([label, g, multi, round(100.0 * multi / g, 1) if g else 0.0,
                       spread[0] if spread else 0])
    write_csv(os.path.join(args.out, "table4_version_spread.csv"),
              ["Table 4: Version spread - products present at multiple versions (Section 4.4)"] + header_note,
              ["estate", "products_G", "multi_version_count", "multi_version_pct", "widest_spread"], rows4)

    # ---- Table 5: fan-out distribution -------------------------------------
    rows5 = []
    for label in labels:
        f = fanout_table(estates[label])
        rows5.append([label, round(f["p50"], 1), round(f["p90"], 1), round(f["p99"], 1), f["max"],
                       round(f["top1pct"], 1), round(f["top5pct"], 1),
                       round(f["top10pct"], 1), round(f["singletons_pct"], 1)])
    write_csv(os.path.join(args.out, "table5_fanout_distribution.csv"),
              ["Table 5: Fan-out distribution - how many endpoints share a scan item (Section 4.5)"] + header_note,
              ["estate", "p50", "p90", "p99", "max", "top1pct", "top5pct", "top10pct", "singletons_pct"], rows5)

    # ---- Figure 1: concentration curves -----------------------------------
    if args.curve_estates:
        curve_labels = [l.strip() for l in args.curve_estates.split(",") if l.strip()]
        missing = [l for l in curve_labels if l not in estates]
        if missing:
            sys.exit(f"--curve-estates names not found among read exports: {missing}")
    else:
        curve_labels = pick_curve_estates(labels, estates)

    rowsF = []
    for label in curve_labels:
        for x, y in concentration_points(estates[label].fanout_counts(), args.curve_samples):
            rowsF.append([label, round(x, 2), round(y, 2)])
    write_csv(os.path.join(args.out, "figure1_fanout.csv"),
              [f"Figure 1: Fan-out concentration curves for {', '.join(curve_labels)} (Section 4.5)",
               "X-axis: items consumed (% of U, descending fan-out)",
               "Y-axis: rows covered (% of R)"] + header_note,
              ["estate", "items_consumed_pct", "rows_covered_pct"], rowsF)

    # ---- console summary ---------------------------------------------------
    print()
    print(f"{'Estate':6s} {'endpoints':>9s} {'live':>8s} {'noVer%':>7s} {'R':>7s} "
          f"{'U':>6s} {'G':>6s} {'rho_i':>6s} {'rho_g':>6s} {'reduct%':>8s}")
    for label in labels:
        e = estates[label]
        print(f"{label:6s} {len(e.endpoints):9,} {e.live_rows:8,} {e.no_version_pct:7.1f} "
              f"{e.scannable_rows:7,} {e.unique_items:6,} {e.product_groups:6,} "
              f"{e.rho_item:6.1f} {e.rho_group:6.2f} {e.reduction_pct:8.1f}")
    print("-" * 80)
    print(f"{'Pooled':6s} {pooled_endpoints:9,} {pooled_live:8,} {pooled_no_version_pct:7.1f} "
          f"{pooled_R:7,} {pooled_U:6,} {pooled_G:6,} {pooled_rho_item:6.1f} "
          f"{pooled_rho_group:6.2f} {pooled_reduction:8.1f}")
    if skipped:
        print(f"\nexcluded (unreadable): {', '.join(skipped)}")


if __name__ == "__main__":
    main()
