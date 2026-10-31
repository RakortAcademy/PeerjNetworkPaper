"""Reviewer end-to-end example: the Section 5–6 pipeline on synthetic data, with
every intermediate stage written out.

    python examples/run_pipeline.py --model example_data/tiny_model --out out/

Stages (each a JSON file under --out and a short console summary):

  1. estate_reduction.json   per-endpoint rows → unique scan items with endpoint lists
                             (Section 6.1 — refimpl.planning.estate_reduction.collect)
  2. plan.json               request-level grouping: assignment + product groups
                             (Section 6.2 — refimpl.planning.planner.build_plan)
  3. prepare_<group>.json    version-invariant preparation per product group: cleaned
                             name, resolved vendor, candidate retrieval (both arms),
                             relevance scores, structural bounds, catalog family
                             (Section 5.1 — ThreatScanner._prepare)
  4. extraction.json         tagger output per advisory (labels, spans) and the
                             constraints recovered by rule, with the merge result
                             (Section 5.1 — extractor + constraints)
  5. decisions.json          per (group, version): every candidate's trace —
                             product match, gate, structural override, verdict row
                             (Section 5.1 — ThreatScanner._decide / _apply_gates)
  6. results.json            the engine results in submitted order (copied results
                             marked `copied: true`, as the service response did)
  7. fan_back.json           one row per (endpoint, item): R endpoint exposures from U verdicts

The tagger checkpoint under --model is a SMALL model trained on synthetic
sentences by `python -m refimpl.training.train`; it is not the manuscript's
8.8M-parameter model and its extractions are illustrative only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from refimpl import extraction_cache, store  # noqa: E402
from refimpl.corpus import InMemoryCorpus  # noqa: E402
from refimpl.planning.estate_reduction import collect, fan_back  # noqa: E402
from refimpl.planning.planner import build_plan  # noqa: E402
from refimpl.scanner import ThreatScanner  # noqa: E402
from refimpl.search import score_cve_relevance  # noqa: E402


class _Item:
    """Minimal item object with the attributes the planner reads."""

    def __init__(self, d):
        self.product = d.get("product")
        self.version = d.get("version")
        self.vendor = d.get("vendor")
        self.operating_system = d.get("operating_system")
        self.platform = d.get("platform")
        self.raw = d


def dump(out: Path, name: str, obj) -> None:
    (out / name).write_text(json.dumps(obj, ensure_ascii=False, indent=1, default=str), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(ROOT / "example_data/synthetic_corpus.jsonl"))
    ap.add_argument("--inventory", default=str(ROOT / "example_data/synthetic_inventory_rows.json"))
    ap.add_argument("--model", required=True, help="tagger checkpoint (.pth) or its directory")
    ap.add_argument("--out", default=str(ROOT / "out"))
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- corpus
    corpus = InMemoryCorpus.load(args.corpus)
    store.use_corpus(corpus)
    print(f"[corpus] {corpus.stats()}")

    # ------------------------------------------------- 1. estate-level reduction
    rows = json.loads(Path(args.inventory).read_text(encoding="utf-8"))["rows"]
    items, stats = collect([tuple(r) for r in rows], keep_versionless=False)
    dump(out, "estate_reduction.json", {"stats": stats, "items": items})
    print(f"[1 estate reduction] {stats['app_rows']} rows -> {stats['unique_items']} items "
          f"(rho_item={stats['app_rows']/max(1,stats['unique_items']):.2f}); "
          f"dropped: no version {stats['skipped_no_version']}, no name {stats['skipped_no_name']}")

    # ------------------------------------------------- 2. request-level grouping
    plan = build_plan([_Item(i) for i in items])
    dump(out, "plan.json", {
        "summary": plan.summary(),
        "assignment": plan.assignment,
        "groups": [{"sample_index": g.sample_index, "versions": g.versions, "targets": g.targets}
                   for g in plan.groups],
    })
    print(f"[2 planner] {plan.summary()}")

    # --------------------------------------------------- 3–5. scan per group
    scanner = ThreatScanner(model_path=args.model)
    scanner.load()
    unique_results = [None] * len(plan.unique_items)
    extraction_dump = {}
    decisions_dump = []
    for gi, group in enumerate(plan.groups):
        sample = plan.unique_items[group.sample_index]
        ctx = scanner._prepare(sample.product, sample.platform, sample.vendor, sample.operating_system)
        prep = {
            "product": ctx.product, "clean_product": ctx.clean_product,
            "product_normalized": ctx.product_normalized, "platform": ctx.platform,
            "customer_vendor": ctx.customer_vendor, "generic_unresolved": ctx.generic_unresolved,
            "update_package": ctx.update_package, "relevance_rejected": ctx.relevance_rejected,
            "top_score": ctx.top_score, "sole_family": ctx.sole_family, "exact_catalog": ctx.exact_catalog,
            "candidates": [{"cve_id": c.cve_id, "catalog_product": c.product, "catalog_vendor": c.vendor,
                            "version_hint": c.version_hint,
                            "relevance": round(score_cve_relevance(c, ctx.product_normalized), 2)}
                           for c in ctx.ranked],
            "structural_bounds": ctx.bounds_map,
        }
        dump(out, f"prepare_{gi:02d}.json", prep)
        print(f"[3 prepare] group {gi:02d} {sample.product!r} vendor={ctx.customer_vendor!r} "
              f"-> {len(ctx.ranked)} candidate(s), top relevance {ctx.top_score:.1f}"
              + (" GENERIC-UNRESOLVED" if ctx.generic_unresolved else "")
              + (" UPDATE-PACKAGE" if ctx.update_package else ""))
        for vi, version in enumerate(group.versions):
            result = scanner._decide(ctx, version)
            unique_results[group.targets[vi]] = result
            decisions_dump.append({
                "group": gi, "product": sample.product, "version": version, "status": result["status"],
                "safety_score": result["safety_score"], "outcome_histogram": result["outcome_histogram"],
                "threats": result["threats"], "safe_reasons": result["safe_reasons"],
                "uncertain_items": result["uncertain_items"], "n_ignored": result["n_ignored"],
                "decision_summary": result["decision_summary"],
            })
            print(f"[5 decide ] group {gi:02d} {sample.product!r} {version!r}: {result['status']} "
                  f"threats={len(result['threats'])} safe={result['n_safe']} "
                  f"uncertain={result['n_uncertain']} ignored={result['n_ignored']}")
        for cve_id, info in ctx.extracted.items():
            extraction_dump[cve_id] = info
        if ctx.ranked:
            print(f"[4 extract] group {gi:02d}: tagger ran for {ctx.model_calls} advisor(ies), "
                  f"{ctx.reused_extractions} served from the extraction cache")
    dump(out, "extraction.json", extraction_dump)
    dump(out, "decisions.json", decisions_dump)

    # --------------------------------------------------------------- 6. results
    results = []
    for position, unique_idx in enumerate(plan.assignment):
        r = dict(unique_results[unique_idx])
        r["copied"] = plan.assignment.index(unique_idx) != position
        results.append(r)
    dump(out, "results.json", results)
    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    print(f"[6 results] {len(results)} items in submitted order: {by_status}; "
          f"extraction cache: {extraction_cache.stats()}")

    # --------------------------------------------------------------- 7. fan-back
    exposures = fan_back(items, results)
    dump(out, "fan_back.json", exposures)
    print(f"[7 fan-back] {len(results)} verdicts -> {len(exposures)} endpoint exposures "
          f"(= sum of endpoint_count = {sum(i['endpoint_count'] for i in items)})")
    print(f"\nintermediate outputs written to {out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
