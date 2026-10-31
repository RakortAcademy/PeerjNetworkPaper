"""End-to-end decision procedure on the synthetic corpus (no checkpoint needed).

The tagger is replaced by `NoModelExtractor` (see tests/helpers.py); every other
stage — candidate retrieval, relevance, structural bounds, product matching,
constraint recovery by rule, version algebra, applicability gates, structural
override, policy, final verdict — is the production code.
"""
from __future__ import annotations

import pytest

from refimpl.scanner import ThreatScanner
from tests.helpers import NoModelExtractor, load_synthetic_corpus


@pytest.fixture()
def scanner():
    load_synthetic_corpus()
    return ThreatScanner(extractor=NoModelExtractor())


def threat_ids(result):
    return sorted(t["cve_id"] for t in result["threats"])


class TestStructuredBounds:
    def test_range_covers_version(self, scanner):
        r = scanner.check("Acme Ledgerly Server", "2.3.9", vendor="Acme")
        assert r["status"] == "THREAT"
        assert "CVE-2099-0001" in threat_ids(r)
        row = next(t for t in r["threats"] if t["cve_id"] == "CVE-2099-0001")
        assert row["decision_source"] in ("structured_bounds", "range_matcher")
        assert row["constraint_type"] in ("range", "lt")

    def test_fixed_version_is_safe_for_that_advisory(self, scanner):
        r = scanner.check("Acme Ledgerly Server", "2.4.1", vendor="Acme")
        assert "CVE-2099-0001" not in threat_ids(r)
        assert any(s["cve_id"] == "CVE-2099-0001" for s in r["safe_reasons"])

    def test_multi_branch_ranges(self, scanner):
        assert "CVE-2099-0002" in threat_ids(scanner.check("Acme Ledgerly Server", "3.1.4", vendor="Acme"))
        assert "CVE-2099-0002" not in threat_ids(scanner.check("Acme Ledgerly Server", "3.1.7", vendor="Acme"))
        assert "CVE-2099-0002" not in threat_ids(scanner.check("Acme Ledgerly Server", "2.8.0", vendor="Acme"))

    def test_other_vendor_same_name_is_gated(self, scanner):
        r = scanner.check("Acme Ledgerly Server", "2.1", vendor="Acme")
        assert "CVE-2099-0009" not in threat_ids(r)

    def test_exact_version_list_and_default_status(self, scanner):
        hit = scanner.check("Contoso Photolens Viewer", "1.2.3", vendor="Contoso")
        assert "CVE-2099-0005" in threat_ids(hit)
        miss = scanner.check("Contoso Photolens Viewer", "1.2.4", vendor="Contoso")
        assert "CVE-2099-0005" not in threat_ids(miss)
        row = next(s for s in miss["safe_reasons"] if s["cve_id"] == "CVE-2099-0005")
        assert row["constraint_type"] == "neq"

    def test_build_number_is_inside_inclusive_upper_bound(self, scanner):
        r = scanner.check("Tailspin Relaywire Client", "5.2.8.3141", vendor="Tailspin")
        assert "CVE-2099-0012" in threat_ids(r)

    def test_nvd_cpe_rows_decide_when_cna_has_no_bounds(self, scanner):
        r = scanner.check("ZetaDB", "4.0.3", vendor="Zeta Labs")
        assert "CVE-2099-0011" in threat_ids(r)
        assert "CVE-2099-0011" not in threat_ids(scanner.check("ZetaDB", "4.0.5", vendor="Zeta Labs"))

    def test_commit_hash_bounds_are_not_versions(self, scanner):
        r = scanner.check("ZetaDB", "4.0.3", vendor="Zeta Labs")
        assert "CVE-2099-0010" not in threat_ids(r)


class TestTextRecoveredConstraints:
    def test_prior_to_from_prose(self, scanner):
        r = scanner.check("Northwind Mailflow Gateway", "5.1.0", vendor="Northwind")
        assert "CVE-2099-0003" in threat_ids(r)
        row = next(t for t in r["threats"] if t["cve_id"] == "CVE-2099-0003")
        assert row["decision_source"] == "range_matcher" and row["constraint_type"] == "lt"

    def test_and_earlier_is_inclusive(self, scanner):
        assert "CVE-2099-0004" in threat_ids(scanner.check("Northwind Mailflow Gateway", "5.4.2", vendor="Northwind"))
        r = scanner.check("Northwind Mailflow Gateway", "5.5.0", vendor="Northwind")
        assert "CVE-2099-0004" not in threat_ids(r) and "CVE-2099-0003" not in threat_ids(r)


class TestApplicabilityGates:
    def test_os_specific_advisory_is_not_applicable_on_other_platform(self, scanner):
        r = scanner.check("Orbital Browser", "109.0.1", vendor="Stellar Software", operating_system="Windows")
        assert "CVE-2099-0007" in threat_ids(r)
        assert "CVE-2099-0006" not in threat_ids(r)
        gated = next(s for s in r["safe_reasons"] if s["cve_id"] == "CVE-2099-0006")
        assert gated["decision_source"] == "applicability_os" and gated["not_applicable"] is True

    def test_same_advisory_applies_when_platform_matches(self, scanner):
        r = scanner.check("Orbital Browser", "109.0.1", vendor="Stellar Software", operating_system="Android")
        assert "CVE-2099-0006" in threat_ids(r)

    def test_web_plugin_gate(self, scanner):
        r = scanner.check("Contoso Photolens Viewer", "1.2.4", vendor="Contoso")
        assert "CVE-2099-0008" not in threat_ids(r)


class TestFinalStatus:
    def test_generic_name_without_vendor_is_uncertain(self, scanner):
        r = scanner.check("Notes", "4.13")
        assert r["status"] == "UNCERTAIN" and r.get("ambiguous_product") is True and r["scanned_cves"] == 0

    def test_update_package_is_not_a_product(self, scanner):
        r = scanner.check("Security Update for Windows (KB5099999)", "1.0", vendor="Microsoft")
        assert r["status"] == "NOT_FOUND" and r.get("update_package") is True

    def test_unknown_product_is_not_found(self, scanner):
        r = scanner.check("Hypothetical Unknown App", "1.0.0", vendor="Nobody")
        assert r["status"] == "NOT_FOUND"

    def test_result_shape(self, scanner):
        r = scanner.check("Acme Ledgerly Server", "2.3.9", vendor="Acme")
        for key in ("status", "threats", "safe_reasons", "uncertain_items", "scanned_cves",
                    "scanned_cve_ids", "safety_score", "outcome_histogram", "decision_summary"):
            assert key in r
        assert r["safety_score"] == 0
        assert r["decision_summary"]["summary"]


class TestPreparationIsSharedAcrossVersions:
    def test_check_many_runs_extraction_once(self):
        load_synthetic_corpus()
        ex = NoModelExtractor()
        s = ThreatScanner(extractor=ex)
        results = s.check_many("Acme Ledgerly Server", ["2.3.9", "2.4.1", "3.1.4"], vendor="Acme")
        assert [r["status"] for r in results] == ["THREAT", "SAFE", "THREAT"]
        # extraction depends on the advisory text only: it ran once per candidate, not once per version
        n_candidates = results[0]["cve_candidates_total"]
        assert ex.calls == n_candidates

    def test_results_are_deterministic(self, scanner):
        a = scanner.check("Orbital Browser", "109.0.1", vendor="Stellar Software", operating_system="Windows")
        b = scanner.check("Orbital Browser", "109.0.1", vendor="Stellar Software", operating_system="Windows")
        assert a == b
