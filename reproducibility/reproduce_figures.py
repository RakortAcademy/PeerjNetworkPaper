#!/usr/bin/env python3
"""
Regenerate the manuscript figures whose plotted datapoints are released in
``figure_data/`` -- the PUBLIC-reproduction path (no customer export needed).

What this script can and cannot regenerate
------------------------------------------
Figure 1  fan-out concentration curves (Section 4.5)        REGENERATED
          from ``figure_data/figure1_fanout.csv``. The released file is
          the output of ``analysis/estate_structure.py`` on the study exports:
          a 60-sample curve per estate plus exact points at the Table 5 head
          shares (1 %, 5 % and 10 % of items). An operator running
          ``analysis/estate_structure.py`` on their own export obtains a denser
          curve file (``--curve-samples``, default 60 points) in the same
          format, which this script plots identically.

Figure 6  appliance core-count scaling (Section 9.6)         REGENERATED
          from ``figure_data/figure6_speedup.csv`` (median speed-up per core
          count; all six plotted points are released).

Figure 7  per-item latency (Section 9.10)                    NOT REGENERATED
          Panel (a) is the empirical distribution of 200 individual request
          latencies; only the summary percentiles of Table 18 are released, so
          the curve cannot be drawn without inventing the 200 observations.
          Panel (b) plots a median per finding-count bucket with the bucket
          population; the medians and populations are released but the
          per-bucket spread drawn as whiskers in the manuscript is not. This
          script therefore writes ``figure7b_partial`` -- the released medians
          and populations only, without whiskers -- and labels it as partial.
          It does not write a Figure 7(a).

Nothing here reads a customer export, contacts a network service, or depends on
any proprietary component. Output is deterministic for a given matplotlib
version (fixed styling, no timestamps embedded in the PDF metadata).

Usage
-----
    python3 reproduce_figures.py --out out/figures
    python3 reproduce_figures.py --figure 1 --figure 6 --out out/figures
    python3 reproduce_figures.py --figure1-data out/figure1_fanout.csv --out out/figures
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from typing import Dict, List, Tuple

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:  # pragma: no cover
    sys.exit("matplotlib is required: pip install -r environment/requirements.txt")

HERE = os.path.dirname(os.path.abspath(__file__))
FIGURE_DATA = os.path.join(HERE, "figure_data")

# Line styles in the order the manuscript draws the four estates (most to
# least concentrated). A curve file from a different export may name other
# estates; styles are then assigned in file order.
_STYLES = ["-", "--", ":", "-."]


def _rc() -> None:
    plt.rcParams.update({
        "font.size": 9,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "lines.linewidth": 1.2,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linewidth": 0.5,
        "pdf.fonttype": 42,
        "savefig.bbox": "tight",
    })


def _data_rows(path: str) -> List[List[str]]:
    """Rows of a figure_data CSV, with ``#`` comment lines and blank lines dropped."""
    with open(path, newline="", encoding="utf-8") as f:
        return [row for row in csv.reader(f)
                if row and row[0].strip() and not row[0].lstrip().startswith("#")]


def _save(fig, out_dir: str, stem: str) -> List[str]:
    written = []
    for ext in ("pdf", "png"):
        path = os.path.join(out_dir, f"{stem}.{ext}")
        if ext == "pdf":
            fig.savefig(path, metadata={"CreationDate": None, "Producer": None, "Creator": None})
        else:
            fig.savefig(path, dpi=200, metadata={"Software": None})
        written.append(path)
        print(f"wrote {path}")
    plt.close(fig)
    return written


# ---------------------------------------------------------------- Figure 1 --
def read_figure1(path: str) -> Tuple[List[str], Dict[str, List[Tuple[float, float]]]]:
    rows = _data_rows(path)
    header = [h.strip() for h in rows[0]]
    expected = ["estate", "items_consumed_pct", "rows_covered_pct"]
    if header != expected:
        sys.exit(f"{path}: expected columns {expected}, found {header}")
    order: List[str] = []
    curves: Dict[str, List[Tuple[float, float]]] = {}
    for estate, x, y in rows[1:]:
        if estate not in curves:
            curves[estate] = []
            order.append(estate)
        curves[estate].append((float(x), float(y)))
    for estate in order:
        curves[estate].sort()
    return order, curves


def figure1(path: str, out_dir: str) -> List[str]:
    order, curves = read_figure1(path)
    fig, ax = plt.subplots(figsize=(3.6, 2.9))
    for i, estate in enumerate(order):
        xs, ys = zip(*curves[estate])
        label = estate
        if len(order) > 1 and i == 0:
            label += " (most concentrated)"
        elif len(order) > 1 and i == len(order) - 1:
            label += " (least concentrated)"
        ax.plot(xs, ys, _STYLES[i % len(_STYLES)], color="black", label=label)
    ax.plot([0, 100], [0, 100], "-", color="0.55", linewidth=0.9, label="uniform reference")
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.set_xlabel("items consumed (% of $U$, descending fan-out)")
    ax.set_ylabel("rows covered (% of $R$)")
    ax.legend(loc="lower right", frameon=True)
    return _save(fig, out_dir, "figure1_fanout")


# ---------------------------------------------------------------- Figure 6 --
def read_figure6(path: str) -> List[Tuple[int, float]]:
    rows = _data_rows(path)
    header = [h.strip() for h in rows[0]]
    if header != ["cores", "speedup"]:
        sys.exit(f"{path}: expected columns ['cores', 'speedup'], found {header}")
    return sorted((int(c), float(s)) for c, s in rows[1:])


def figure6(path: str, out_dir: str) -> List[str]:
    points = read_figure6(path)
    cores = [c for c, _ in points]
    speed = [s for _, s in points]
    fig, ax = plt.subplots(figsize=(3.6, 2.6))
    top = max(cores)
    ax.plot([1, top], [1, top], "--", color="0.6", linewidth=0.9)
    ax.plot(cores, speed, "-o", color="black", markersize=3.5)
    ax.text(top * 0.72, top * 0.72, "linear", color="0.45", rotation=45,
            ha="center", va="bottom", fontsize=8)
    # "no further gain" marks the plateau: the span from the first core count at
    # which the maximum speed-up is reached to the largest core count measured.
    best = max(speed)
    first_best = min(c for c, s in points if s == best)
    if first_best < top:
        ax.annotate("", xy=(top, best), xytext=(first_best, best),
                    arrowprops=dict(arrowstyle="-", color="0.5", linestyle=":", linewidth=0.8))
        ax.text((first_best + top) / 2, best - 0.9, "no further gain",
                ha="center", va="top", fontsize=8, color="0.3")
    ax.set_xticks(cores)
    ax.set_yticks(sorted(set([1, 2, 4, 6, 8, 12] + [top])))
    ax.set_xlim(0.5, top + 0.5)
    ax.set_ylim(0.5, top + 0.5)
    ax.set_xlabel("cores made available to the runtime")
    ax.set_ylabel("speed-up")
    return _save(fig, out_dir, "figure6_speedup")


# ------------------------------------------------------------ Figure 7 (b) --
def read_figure7b(path: str) -> List[Tuple[str, int, float]]:
    """The second table in ``figure7_latency.csv`` (bucket, n, median)."""
    rows = _data_rows(path)
    try:
        start = next(i for i, r in enumerate(rows)
                     if [h.strip() for h in r] == ["finding_bucket", "n", "median_latency_s"])
    except StopIteration:
        sys.exit(f"{path}: 'finding_bucket,n,median_latency_s' table not found")
    out = []
    for r in rows[start + 1:]:
        if len(r) != 3:
            break
        out.append((r[0].strip(), int(r[1]), float(r[2])))
    return out


def figure7b_partial(path: str, out_dir: str) -> List[str]:
    buckets = read_figure7b(path)
    labels = [b for b, _, _ in buckets]
    labels = ["$\\geq$1000" if b == ">=1000" else b for b in labels]
    ns = [n for _, n, _ in buckets]
    med = [m for _, _, m in buckets]
    xs = list(range(len(buckets)))
    fig, ax = plt.subplots(figsize=(3.6, 2.6))
    ax.plot(xs, med, "o", color="black", markersize=4)
    for x, n, m in zip(xs, ns, med):
        ax.annotate(f"$n$={n}", (x, m), textcoords="offset points", xytext=(0, 7),
                    ha="center", fontsize=7)
    ax.set_yscale("log")
    ax.set_xticks(xs)
    ax.set_xticklabels(labels)
    ax.set_xlabel("findings adjudicated for the item")
    ax.set_ylabel("median latency (s)")
    ax.set_title("Figure 7(b), PARTIAL: released medians only, no spread", fontsize=7, color="0.3")
    return _save(fig, out_dir, "figure7b_partial")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", required=True, metavar="DIR", help="output directory for PDF+PNG")
    parser.add_argument("--figure", action="append", choices=["1", "6", "7b"],
                         help="which figure(s) to draw (default: 1, 6 and the partial 7b)")
    parser.add_argument("--figure1-data", default=os.path.join(FIGURE_DATA, "figure1_fanout.csv"),
                         metavar="CSV", help="curve file (default: released figure_data/figure1_fanout.csv; "
                                             "or the figure1_fanout.csv written by analysis/estate_structure.py)")
    parser.add_argument("--figure6-data", default=os.path.join(FIGURE_DATA, "figure6_speedup.csv"), metavar="CSV")
    parser.add_argument("--figure7-data", default=os.path.join(FIGURE_DATA, "figure7_latency.csv"), metavar="CSV")
    args = parser.parse_args()

    wanted = args.figure or ["1", "6", "7b"]
    os.makedirs(args.out, exist_ok=True)
    _rc()
    if "1" in wanted:
        figure1(args.figure1_data, args.out)
    if "6" in wanted:
        figure6(args.figure6_data, args.out)
    if "7b" in wanted:
        figure7b_partial(args.figure7_data, args.out)
        print("note: Figure 7(a) is NOT regenerated -- the 200 individual request latencies "
              "behind it are not released (only the Table 18 percentiles are); Figure 7(b) is "
              "drawn without its per-bucket spread, which is likewise not released.")


if __name__ == "__main__":
    main()
