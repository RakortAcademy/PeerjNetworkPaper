"""Threat prioritisation (ordering of the threat list; the manuscript's "ranking is a
correctness requirement of the transport design"). Ported from the production tests;
the risk source is the in-memory store instead of the database."""
from __future__ import annotations

import pytest

from refimpl import prioritization


def risk(**kw):
    base = {"kev": False, "ransomware": False, "epss": None, "cvss": None, "exploit_known": False}
    base.update(kw)
    return base


class TestPriority:
    def test_kev_is_always_urgent(self):
        assert prioritization.priority_for(risk(kev=True, cvss=3.1, epss=0.001)) == "acil"

    def test_high_epss_without_kev(self):
        assert prioritization.priority_for(risk(epss=0.42, cvss=4.3)) == "yüksek"

    def test_critical_cvss_without_epss(self):
        assert prioritization.priority_for(risk(cvss=9.8)) == "yüksek"

    def test_moderate_signals(self):
        assert prioritization.priority_for(risk(cvss=7.5)) == "orta"
        assert prioritization.priority_for(risk(epss=0.02)) == "orta"

    def test_low_when_nothing_stands_out(self):
        assert prioritization.priority_for(risk(cvss=5.0, epss=0.001)) == "düşük"

    def test_missing_signals_are_not_treated_as_severe(self):
        assert prioritization.priority_for(risk()) == "düşük"
        assert prioritization.priority_for(None) == "düşük"

    @pytest.mark.parametrize("epss,expected", [(0.0999, "orta"), (0.10, "yüksek")])
    def test_epss_threshold_is_exact(self, epss, expected):
        assert prioritization.priority_for(risk(epss=epss)) == expected


class TestAttach:
    def test_threats_are_sorted_by_priority_then_epss_then_id(self, monkeypatch):
        risks = {"CVE-2020-0": risk(cvss=5.0), "CVE-2020-1": risk(kev=True), "CVE-2020-2": risk(epss=0.5),
                 "CVE-2020-3": risk(epss=0.5)}
        monkeypatch.setattr("refimpl.store.risk_for", lambda ids: {i: risks[i] for i in ids})
        threats = [{"cve_id": f"CVE-2020-{i}"} for i in range(4)]
        counts = prioritization.attach(threats)
        assert [t["cve_id"] for t in threats] == ["CVE-2020-1", "CVE-2020-2", "CVE-2020-3", "CVE-2020-0"]
        assert counts == {"acil": 1, "yüksek": 2, "düşük": 1}
        assert threats[0]["risk"]["priority"] == "acil"

    def test_store_failure_does_not_break_the_scan(self, monkeypatch):
        def boom(ids):
            raise RuntimeError("no store")
        monkeypatch.setattr("refimpl.store.risk_for", boom)
        threats = [{"cve_id": "CVE-2020-0"}]
        assert prioritization.attach(threats) == {"düşük": 1}

    def test_empty_input(self):
        assert prioritization.attach([]) == {}


class TestSummary:
    def test_kev_summary_names_the_cves(self):
        threats = [{"cve_id": "CVE-1", "risk": risk(kev=True, kev_due_date="2099-02-01")},
                   {"cve_id": "CVE-2", "risk": risk(cvss=5.0)}]
        s = prioritization.summarize(threats, {"acil": 1, "düşük": 1})
        assert s["kev"] == 1 and s["earliest_due_date"] == "2099-02-01" and "CVE-1" in s["summary_tr"]

    def test_no_threats_no_summary(self):
        assert prioritization.summarize([], {}) == {}
