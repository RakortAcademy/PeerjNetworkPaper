"""The in-memory corpus reproduces the store's selection, ordering and capping rules."""
from __future__ import annotations

from refimpl.corpus import InMemoryCorpus, _anchor_token, _lexemes
from tests.helpers import load_synthetic_corpus


def test_load_and_stats():
    c = load_synthetic_corpus()
    s = c.stats()
    assert s["cves"] == 12 and s["affected_rows"] >= 12 and s["cpe_rows"] == 1


def test_anchor_token_drops_vendor_filler_and_trailing_digits():
    assert _anchor_token("apache log4j2") == "log4j"
    assert _anchor_token("acme ledgerly server") == "ledgerly"   # "server" is filler
    assert _anchor_token("the inc") == ""


def test_search_arm1_exact_product_row_preferred_and_one_row_per_cve():
    c = load_synthetic_corpus()
    rows = c.search("ledgerly server", vendor="acme")
    ids = [r["cve_id"] for r in rows]
    assert ids == sorted(ids) and len(ids) == len(set(ids))
    # CVE-2099-0002 has two affected rows; the one with lower id wins the tie
    two = next(r for r in rows if r["cve_id"] == "CVE-2099-0002")
    assert two["less_than"] == "3.1.7"
    # the Fabrikam row is pulled in by the product-name predicate (same name, other vendor)
    assert "CVE-2099-0009" in ids


def test_search_arm1_vendor_predicate_alone_matches():
    c = load_synthetic_corpus()
    rows = c.search("something unrelated zzz", vendor="contoso")
    assert {r["cve_id"] for r in rows} == {"CVE-2099-0005"}


def test_search_arm2_full_text_requires_every_lexeme():
    c = load_synthetic_corpus()
    ids = {r["cve_id"] for r in c.search_by_description("orbital browser")}
    assert ids == {"CVE-2099-0006", "CVE-2099-0007"}
    assert c.search_by_description("orbital nonexistentword") == []
    # tokens of length <= 2 are dropped before the query is built
    assert c.search_by_description("ab") == []


def test_lexemes_stem_and_drop_stop_words():
    lex = _lexemes("Versions before the gateway were affected")
    assert "version" in lex and "gateway" in lex and "the" not in lex and "before" not in lex


def test_bounds_for_filters_unbounded_rows_and_blanks_version_when_bounded():
    c = load_synthetic_corpus()
    b = c.bounds_for(["CVE-2099-0001", "CVE-2099-0003", "CVE-2099-0005"], "ledgerly server")
    assert "CVE-2099-0003" not in b                       # no bounds, no exact version
    assert b["CVE-2099-0001"][0]["version"] == ""         # bounded → version blanked
    assert b["CVE-2099-0001"][0]["text"].startswith("Acme Ledgerly Server before 2.4.1")
    exact = b["CVE-2099-0005"]
    assert [r["version"] for r in exact] == ["1.2.3", "1.2.2"] and exact[0]["default_status"] == "unaffected"


def test_bounds_for_cap_and_ordering():
    c = load_synthetic_corpus()
    b = c.bounds_for(["CVE-2099-0002"], "ledgerly server", max_ranges_per_cve=1)
    assert len(b["CVE-2099-0002"]) == 1 and b["CVE-2099-0002"][0]["less_than"] == "3.1.7"


def test_cpe_bounds_for_filters_by_product_coverage():
    c = load_synthetic_corpus()
    assert c.cpe_bounds_for(["CVE-2099-0011"], "zetadb")["CVE-2099-0011"][0]["source"] == "nvd-cpe"
    assert c.cpe_bounds_for(["CVE-2099-0011"], "ledgerly server") == {}


def test_product_family_names_prefix_semantics():
    c = load_synthetic_corpus()
    assert c.product_family_names("photolens viewer") == ["photolens viewer", "photolens viewer gallery"]
    assert c.product_family_names("photo") == []   # 'photo %' would need a space boundary
    assert c.product_family_names("") == []


def test_risk_for_left_join_semantics():
    c = load_synthetic_corpus()
    r = c.risk_for(["cve-2099-0001", "CVE-2099-0003", "CVE-0000-0000"])
    assert r["CVE-2099-0001"]["kev"] is True and r["CVE-2099-0001"]["epss"] == 0.42
    assert r["CVE-2099-0003"]["kev"] is False and r["CVE-2099-0003"]["cvss"] == 5.3
    assert "CVE-0000-0000" not in r
