"""Golden-set metrics and parity comparison on synthetic data."""
from __future__ import annotations

from pathlib import Path

from refimpl.evaluation import parity
from refimpl.evaluation.golden_metrics import evaluate, load_golden
from refimpl.scanner import ThreatScanner
from tests.helpers import NoModelExtractor, load_synthetic_corpus

ROOT = Path(__file__).resolve().parents[1]


def test_golden_metrics_on_synthetic_set():
    load_synthetic_corpus()
    cases = load_golden(ROOT / "example_data/synthetic_golden.jsonl")
    assert len(cases) == 8
    rep = evaluate(cases, ThreatScanner(extractor=NoModelExtractor()))
    assert rep["total"] == 8
    assert rep["missed_threats"] == 0 and rep["false_threats"] == 0
    assert rep["forbidden_cve_violations"] == 0
    assert rep["expected_cve_recall"] == 1.0
    assert rep["accepted_accuracy"] == 1.0
    assert set(rep["confusion"]) >= {"THREAT->THREAT", "UNCERTAIN->UNCERTAIN", "NOT_FOUND->NOT_FOUND"}


def test_parity_reports_missed_and_invented_separately():
    a = [{"product": "p", "version": "1", "status": "THREAT", "threats": [{"cve_id": "CVE-1"}, {"cve_id": "CVE-2"}]},
         {"product": "q", "version": "2", "status": "SAFE", "threats": []}]
    b = [{"product": "p", "version": "1", "status": "THREAT", "threats": [{"cve_id": "CVE-2"}, {"cve_id": "CVE-9"}]},
         {"product": "q", "version": "2", "status": "UNCERTAIN", "threats": []}]
    rep = parity.compare(a, b)
    assert rep["status_agreement"] == 1 and rep["missed_threats"] == 1 and rep["invented_threats"] == 1
    assert not rep["identical"] and len(rep["diffs"]) == 2
    assert parity.compare(a, a)["identical"]


def test_engine_is_self_consistent_under_parity(tmp_path):
    """Two independent scanner instances over the same corpus must agree exactly
    (the determinism property the manuscript treats as something to test)."""
    load_synthetic_corpus()
    items = [("Acme Ledgerly Server", "2.3.9", "Acme", None), ("Orbital Browser", "109.0.1", "Stellar Software", "Windows"),
             ("ZetaDB", "4.0.3", "Zeta Labs", None), ("Notes", "4.13", None, None)]
    def run():
        s = ThreatScanner(extractor=NoModelExtractor())
        return [s.check(p, v, vendor=ven, operating_system=os_) for p, v, ven, os_ in items]
    assert parity.compare(run(), run())["identical"]
