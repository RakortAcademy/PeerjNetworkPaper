"""Golden-set decision metrics (manuscript Sections 5 and 9: release gates).

This is the production golden-set evaluator with one change: the scanner is passed in instead
of being fetched from the process-wide singleton, and `main` loads the
in-memory corpus and a checkpoint instead of opening the database. Metrics:

* exact_accuracy       status == expected_status
* accepted_accuracy    status in accept_statuses ∪ {expected_status}
* missed_threats       expected THREAT, actual not in {THREAT, UNCERTAIN}
* false_threats        expected SAFE, actual THREAT
* precision_violations forbidden product names appearing in threat rows
* forbidden_cve_violations  a CVE the case says is patched reported as threat
* expected_cve_recall  expected CVE ids found among threats or scanned ids

Golden set line format (JSONL): see `load_golden` docstring. The example golden
set shipped here is SYNTHETIC and only exercises the metric code.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# THREAT'i kaçırmak (false negative) müşteriye açık bırakır; SAFE'i THREAT sanmak
# (false positive) gereksiz iş yaratır. İkisi ayrı raporlanır.
_RISKY_MISS = {"THREAT"}


def load_golden(path: Path) -> List[Dict[str, Any]]:
    """Altın küme satırı:
        {"product": ..., "version": ..., "expected_status": "THREAT",
         "accept_statuses": [...], "expected_cve_ids": [...], "forbidden_cve_ids": [...],
         "forbidden_products": [...], "vendor": ..., "operating_system": ..., "category": ...}
    """
    cases = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                case = json.loads(line)
            except json.JSONDecodeError:
                continue
            if case.get("product") and case.get("version"):
                cases.append(case)
    return cases


def evaluate(cases: List[Dict[str, Any]], scanner) -> Dict[str, Any]:
    scanner.load()

    exact = accepted = 0
    missed_threats = false_threats = 0
    cve_hits = cve_expected = 0
    precision_violations = 0
    forbidden_cve_violations = 0
    confusion: Counter = Counter()
    rows: List[Dict[str, Any]] = []
    started = time.perf_counter()

    for case in cases:
        product, version = case["product"], case["version"]
        expected = str(case.get("expected_status") or "").upper()
        accept = {s.upper() for s in case.get("accept_statuses") or []} | {expected}

        result = scanner.check(
            product,
            version,
            case.get("platform"),
            vendor=case.get("vendor"),
            operating_system=case.get("operating_system"),
        )
        status = result["status"]

        is_exact = status == expected
        is_accepted = status in accept
        exact += is_exact
        accepted += is_accepted
        confusion[f"{expected}->{status}"] += 1

        if expected in _RISKY_MISS and status not in ("THREAT", "UNCERTAIN"):
            missed_threats += 1
        if expected == "SAFE" and status == "THREAT":
            false_threats += 1

        found_ids = set(result.get("scanned_cve_ids") or [])
        threat_ids = {t.get("cve_id") for t in result.get("threats") or []}
        wanted = set(case.get("expected_cve_ids") or [])
        if wanted:
            cve_expected += len(wanted)
            cve_hits += len(wanted & (threat_ids | found_ids))

        forbidden = case.get("forbidden_products") or []
        leaked = sorted({
            f
            for f in forbidden
            for t in (result.get("threats") or [])
            if f.lower() in str(t.get("affected_product") or "").lower()
        })
        if leaked:
            precision_violations += 1

        forbidden_cves = {c.upper() for c in (case.get("forbidden_cve_ids") or [])}
        leaked_cves = sorted(forbidden_cves & {str(t).upper() for t in threat_ids if t})
        if leaked_cves:
            forbidden_cve_violations += 1

        rows.append({
            "product": product,
            "version": version,
            "expected": expected,
            "actual": status,
            "exact": is_exact,
            "accepted": is_accepted,
            "threats": len(result.get("threats") or []),
            "scanned": result.get("scanned_cves", 0),
            "missing_cves": sorted(wanted - (threat_ids | found_ids)),
            "leaked_products": leaked,
            "leaked_cves": leaked_cves,
            "category": case.get("category", ""),
            "notes": case.get("notes") or case.get("evidence", ""),
        })

    total = len(cases) or 1
    elapsed = time.perf_counter() - started
    return {
        "total": len(cases),
        "exact_accuracy": round(exact / total, 4),
        "accepted_accuracy": round(accepted / total, 4),
        "missed_threats": missed_threats,
        "false_threats": false_threats,
        "precision_violations": precision_violations,
        "forbidden_cve_violations": forbidden_cve_violations,
        "expected_cve_recall": round(cve_hits / cve_expected, 4) if cve_expected else None,
        "seconds": round(elapsed, 1),
        "seconds_per_item": round(elapsed / total, 3),
        "confusion": dict(confusion.most_common()),
        "rows": rows,
    }


def print_report(report: Dict[str, Any]) -> None:
    print()
    print(f"  cases               : {report['total']}")
    print(f"  exact accuracy      : {report['exact_accuracy']:.1%}")
    print(f"  accepted accuracy   : {report['accepted_accuracy']:.1%}")
    print(f"  missed THREAT       : {report['missed_threats']}")
    print(f"  false THREAT        : {report['false_threats']}")
    print(f"  product leakage     : {report['precision_violations']}")
    print(f"  patched-version leak: {report['forbidden_cve_violations']}")
    if report["expected_cve_recall"] is not None:
        print(f"  expected CVE recall : {report['expected_cve_recall']:.1%}")
    print(f"  time                : {report['seconds']}s ({report['seconds_per_item']}s/item)")
    print("\n  confusion (expected -> actual):")
    for key, count in report["confusion"].items():
        print(f"    {key:28s} {count}")
    failures = [r for r in report["rows"] if not r["accepted"]]
    if failures:
        print(f"\n  not accepted ({len(failures)}):")
        for r in failures[:25]:
            print(f"    [{(r.get('category') or '-')[:16]:16s}] {r['product'][:28]:29s} "
                  f"{r['version'][:13]:14s} {r['expected']:9s} -> {r['actual']:9s}")
    print()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Golden-set decision metrics (in-memory corpus)")
    parser.add_argument("--golden", required=True)
    parser.add_argument("--corpus", required=True, help="JSONL advisory corpus")
    parser.add_argument("--model", required=True, help="tagger checkpoint (.pth or directory)")
    parser.add_argument("--out", help="write the JSON report here")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

    from refimpl import store
    from refimpl.corpus import InMemoryCorpus
    from refimpl.scanner import ThreatScanner

    store.use_corpus(InMemoryCorpus.load(args.corpus))
    cases = load_golden(Path(args.golden))
    if not cases:
        raise SystemExit(f"no cases in {args.golden}")
    report = evaluate(cases, ThreatScanner(model_path=args.model))
    print_report(report)
    if args.out:
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  report: {args.out}\n")


if __name__ == "__main__":
    main()
