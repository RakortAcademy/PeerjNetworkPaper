"""Engine parity comparison (manuscript Section 9, "Verdict Preservation — Engine parity").

The authors' original parity script fed the same inventory items to the compiled engine
(over HTTP) and to the reference implementation (through the service cache) and
compared, per item, the status and the set of threat CVE ids. Missed threats
(reference found, compiled did not) and invented threats (compiled found,
reference did not) are reported SEPARATELY because they mean different things
operationally. This module is the comparison logic of that script, decoupled
from both transports: it takes two result lists already in hand.

    python -m refimpl.evaluation.parity --a results_a.json --b results_b.json

where each file is a JSON list of engine results in the same item order (each
with "status" and "threats": [{"cve_id": ...}]). Exit status is 1 when any
threat differs, so it can gate a release.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Sequence


def compare(results_a: Sequence[Dict[str, Any]], results_b: Sequence[Dict[str, Any]],
            label_a: str = "A", label_b: str = "B") -> Dict[str, Any]:
    if len(results_a) != len(results_b):
        raise ValueError("result lists must have the same length and order")
    agree = 0
    missed_total = 0     # A buldu, B bulamadı
    invented_total = 0   # B buldu, A bulamadı
    diffs: List[Dict[str, Any]] = []
    for a, b in zip(results_a, results_b):
        a_cves = {t["cve_id"] for t in (a.get("threats") or [])}
        b_cves = {t["cve_id"] for t in (b.get("threats") or [])}
        missed = a_cves - b_cves
        invented = b_cves - a_cves
        missed_total += len(missed)
        invented_total += len(invented)
        same = a.get("status") == b.get("status")
        agree += same
        if not same or missed or invented:
            diffs.append({
                "product": a.get("product"), "version": a.get("version"),
                f"{label_a}_status": a.get("status"), f"{label_b}_status": b.get("status"),
                "missed": sorted(missed), "invented": sorted(invented),
            })
    return {
        "items": len(results_a),
        "status_agreement": agree,
        "missed_threats": missed_total,
        "invented_threats": invented_total,
        "identical": missed_total == 0 and invented_total == 0 and agree == len(results_a),
        "diffs": diffs,
    }


def print_report(rep: Dict[str, Any], label_a: str = "A", label_b: str = "B") -> None:
    print(f"status agreement : {rep['status_agreement']}/{rep['items']}")
    print(f"missed by {label_b:<7}: {rep['missed_threats']} threat(s)   ({label_a} found, {label_b} did not)")
    print(f"extra in {label_b:<8}: {rep['invented_threats']} threat(s)   ({label_b} found, {label_a} did not)")
    for d in rep["diffs"]:
        print(f"  {d['product']} {d['version']}: {d[f'{label_a}_status']} vs {d[f'{label_b}_status']}"
              f"  missed={d['missed']} extra={d['invented']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Compare two engines' results on the same items")
    ap.add_argument("--a", required=True, help="JSON list of results (reference)")
    ap.add_argument("--b", required=True, help="JSON list of results (candidate)")
    args = ap.parse_args(argv)
    with open(args.a, encoding="utf-8") as f:
        ra = json.load(f)
    with open(args.b, encoding="utf-8") as f:
        rb = json.load(f)
    rep = compare(ra, rb)
    print_report(rep)
    return 0 if rep["identical"] else 1


if __name__ == "__main__":
    sys.exit(main())
