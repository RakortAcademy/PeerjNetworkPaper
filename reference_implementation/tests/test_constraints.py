"""CVE açıklamasından sürüm kısıtı çıkarımı.

Ölçüm: 'kesin değil' kalan kararların %65'i "açıklamadan kısıt çıkarılamadı"
diyordu. Bu vakaların yarısında açıklamada hiç sürüm numarası yok (kurtarılamaz),
kalanı ise tanınmayan ifade kalıplarıydı — düzeltme dili ("fixed in", "upgrade to")
ve eşdeğer üst sınır ifadeleri ("or earlier").
"""
from __future__ import annotations

import pytest

from refimpl.extraction.constraints import (
    merge_constraints_into_cve_info,
    parse_description_constraints,
    parse_jsonl_version_field,
    parse_version_expression,
    parse_version_field,
)


class TestVersionExpression:
    """Aralığı `version` metninin içine yazan CNA biçimleri.

    Ayrıştırılmadığında aralığın tamamı TAM SÜRÜM sanılır ve etkilenen
    sürüm SAFE görünür.
    """

    @pytest.mark.parametrize(
        "raw,expected",
        [
            (">= 0.2.0, < 0.39.0", {"greater_equal": "0.2.0", "less_than": "0.39.0"}),
            (">= 2.2.0, <= 2.2.3", {"greater_equal": "2.2.0", "less_than_or_equal": "2.2.3"}),
            ("< 2.1.4", {"less_than": "2.1.4"}),
            ("<= 3.0", {"less_than_or_equal": "3.0"}),
            ("< 9", {"less_than": "9"}),
            # "V" ön eki ve serbest metin: "All versions < V4.1.4"
            ("All versions < V4.1.4", {"less_than": "4.1.4"}),
        ],
    )
    def test_operator_forms(self, raw, expected):
        assert parse_version_expression(raw) == expected

    @pytest.mark.parametrize("raw", ["9.0.40", "1.0.4 and earlier", "", None, "n/a"])
    def test_without_operators_returns_nothing(self, raw):
        # Operatör yoksa çağıran metni tam sürüm olarak değerlendirmeye devam eder.
        assert parse_version_expression(raw) == {}

    def test_strict_greater_is_ignored(self):
        # '>' için alan yok; alt sınır olarak saklamak müşteriyi aralığın içinde
        # gösterirdi (yanlış tehdit).
        assert "greater_equal" not in parse_version_expression("> 1.0")

    def test_range_beats_exact_hint_in_jsonl_field(self):
        out = parse_jsonl_version_field(">= 0.2.0, < 0.39.0")
        assert out == {"greater_equal": "0.2.0", "less_than": "0.39.0"}
        assert "jsonl_hint_version" not in out

    def test_plain_version_still_a_hint(self):
        assert parse_jsonl_version_field("9.0.40") == {"jsonl_hint_version": "9.0.40"}


class TestClassicPhrasings:
    @pytest.mark.parametrize(
        "text,key,value",
        [
            ("affects versions before 4.2.1", "less_than", "4.2.1"),
            ("versions prior to 2.0.0 are affected", "less_than", "2.0.0"),
            ("this affects 1.2.3 and earlier", "less_than_or_equal", "1.2.3"),
            ("affected through 9.0.5", "less_than_or_equal", "9.0.5"),
            ("up to 3.1", "less_than_or_equal", "3.1"),
            ("versions >= 2.5 are affected", "greater_equal", "2.5"),
        ],
    )
    def test_known_forms(self, text, key, value):
        assert parse_description_constraints(text).get(key) == value


class TestRemediationLanguage:
    """Düzeltmenin GELDİĞİ sürüm — öncesi etkilenir."""

    @pytest.mark.parametrize(
        "text,expected",
        [
            ("The issue is fixed in 4.2.1.", "4.2.1"),
            ("This has been fixed in version 10.0.3.", "10.0.3"),
            ("The flaw is patched in 3.9.2.", "3.9.2"),
            ("The problem is resolved in version 2.14.1.", "2.14.1"),
            ("Users should upgrade to 5.6.0.", "5.6.0"),
            ("Please update to version 1.4.2 to remediate.", "1.4.2"),
        ],
    )
    def test_fix_version_becomes_upper_bound(self, text, expected):
        assert parse_description_constraints(text).get("less_than") == expected


class TestEquivalentUpperBounds:
    @pytest.mark.parametrize(
        "text,key,value",
        [
            ("affects 7.4.1 or earlier", "less_than_or_equal", "7.4.1"),
            ("versions 2.0 or below are affected", "less_than_or_equal", "2.0"),
            ("versions older than 3.0.1", "less_than", "3.0.1"),
            ("releases earlier than 6.2", "less_than", "6.2"),
        ],
    )
    def test_forms(self, text, key, value):
        assert parse_description_constraints(text).get(key) == value


class TestVendorSpecificForms:
    """Gerçek CVE metinlerinde sık geçen ama tanınmayan biçimler."""

    def test_openssl_dash_range(self):
        text = (
            "The function can be made to read memory. Fixed in OpenSSL 1.1.1l "
            "(Affected 1.1.1-1.1.1k)."
        )
        out = parse_description_constraints(text)
        assert out["greater_equal"] == "1.1.1"
        assert out["less_than_or_equal"] == "1.1.1k"

    def test_fix_sentence_with_product_name_between(self):
        # "fixed in <ÜRÜN> <sürüm>" — sürüm ifadeyi doğrudan izlemiyor.
        out = parse_description_constraints("This issue is Fixed in OpenSSL 3.0.3.")
        assert out["less_than"] == "3.0.3"

    def test_fix_sentence_with_multiword_product(self):
        out = parse_description_constraints("Fixed in Apache Tomcat 11.0.21.")
        assert out["less_than"] == "11.0.21"

    def test_dash_range_wins_over_fix_sentence(self):
        # Aralık daha kesin bilgidir; düzeltme sürümü yalnızca üst sınır verir.
        text = "Fixed in OpenSSL 3.0.3 (Affected 3.0.0-3.0.2)."
        out = parse_description_constraints(text)
        assert out["greater_equal"] == "3.0.0"
        assert out["less_than_or_equal"] == "3.0.2"


class TestPrecedence:
    def test_explicit_range_wins_over_fix_language(self):
        # "before 3.0" kesin bilgi; "upgrade to 4.0" tavsiye. Kısıt kesin olandan.
        text = "Affects versions before 3.0. Users should upgrade to 4.0."
        assert parse_description_constraints(text).get("less_than") == "3.0"

    def test_branch_match_prefers_customer_major(self):
        text = "affects 9.x before 9.0.50 and 10.x before 10.1.5"
        assert parse_description_constraints(text, customer_major=9)["less_than"] == "9.0.50"
        assert parse_description_constraints(text, customer_major=10)["less_than"] == "10.1.5"


class TestNoFalsePositives:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "A flaw allows remote attackers to cause a denial of service.",
            "Improper input validation in the parser component.",
        ],
    )
    def test_descriptions_without_versions_yield_nothing(self, text):
        assert parse_description_constraints(text) == {}

    def test_cve_identifiers_are_not_mistaken_for_versions(self):
        out = parse_description_constraints("See CVE-2024-1234 for details.")
        assert not any(v for k, v in out.items() if k != "constraint_source")


class TestMerge:
    def test_existing_bounds_are_not_overwritten(self):
        info = {"less_than": "1.0"}
        out = merge_constraints_into_cve_info(info, "fixed in 9.9.9")
        assert out["less_than"] == "1.0"

    def test_input_is_not_mutated(self):
        # `check_many` aynı çıkarımı birden çok sürümde paylaşır; girdi
        # değişirse ilk sürümün kısıtı sonrakilere sızardı.
        info = {"product": "x"}
        merge_constraints_into_cve_info(info, "affects versions before 4.2.1")
        assert info == {"product": "x"}

    def test_description_fills_missing_bounds(self):
        out = merge_constraints_into_cve_info({}, "affects versions before 4.2.1")
        assert out["less_than"] == "4.2.1"
        assert "description_regex" in out.get("constraint_source", "")


class TestVersionField:
    """`version` metninin çok parçalı hâli.

    Depodaki 1,09M satırın 535 bini (%49) hiç yapısal sınır taşımıyor; etkilenen
    sürümler metnin içinde. Bu biçimler ayrıştırılmazsa karar "sürüm kısıtı
    çıkarılamadı" deyip UNCERTAIN döner — oysa etkilenen sürümler kayıtlıdır.
    """

    @pytest.mark.parametrize(
        "raw,expected",
        [
            # "and below/earlier/prior" — üst sınır
            ("5.6.9 and below", [{"less_than_or_equal": "5.6.9"}]),
            ("42.00 and prior", [{"less_than_or_equal": "42.00"}]),
            ("1.0.4 and earlier", [{"less_than_or_equal": "1.0.4"}]),
            # Ürün adı ön eki sınırı gizlememeli
            ("BrightwaveOS versions 4.6.2 and below", [{"less_than_or_equal": "4.6.2"}]),
            # Diğer üst sınır dilleri
            ("before 2.0.1", [{"less_than": "2.0.1"}]),
            ("prior to 3.1", [{"less_than": "3.1"}]),
            ("through 1.2.9", [{"less_than_or_equal": "1.2.9"}]),
            ("up to and including 3.4", [{"less_than_or_equal": "3.4"}]),
            # Tam sürüm
            ("6.2.0", [{"version": "6.2.0"}]),
            ("v2.10.1", [{"version": "2.10.1"}]),
        ],
    )
    def test_single_constraint_forms(self, raw, expected):
        assert parse_version_field(raw) == expected

    def test_enumeration_becomes_one_row_per_version(self):
        # "4.8.3, 4.6.7" iki AYRI tam sürümdür; tek satıra indirgemek ikincisini
        # düşürür ve o sürümdeki müşteri SAFE görünür.
        assert parse_version_field("BrightwaveOS 4.8.3, 4.6.7") == [
            {"version": "4.8.3"}, {"version": "4.6.7"},
        ]

    def test_multi_branch_upper_bounds_are_all_kept(self):
        # Çok dallı biçim: her parça ayrı bir bakım dalının üst sınırı. Tek sınıra
        # indirgemek diğer dalları kapsamsız bırakırdı.
        out = parse_version_field(
            "2098.014.20051 and earlier, 2097.012.30090 and earlier, "
            "and 2095.007.30311 and earlier"
        )
        assert out == [
            {"less_than_or_equal": "2098.014.20051"},
            {"less_than_or_equal": "2097.012.30090"},
            {"less_than_or_equal": "2095.007.30311"},
        ]

    def test_operator_range_stays_a_single_constraint(self):
        # Virgülden bölünürse alt ve üst sınır BAĞIMSIZ iki satıra ayrılır ve
        # "< 0.39.0" tek başına 0.1.0'ı da etkilenmiş gösterirdi.
        assert parse_version_field(">= 0.2.0, < 0.39.0") == [
            {"greater_equal": "0.2.0", "less_than": "0.39.0"},
        ]

    @pytest.mark.parametrize(
        "raw",
        [
            "S7x and prior",           # sürüm tokenı harfle başlıyor
            "R7x and prior",
            'The first 5 digits of serial No. "26061" and prior',
            "n/a", "unspecified", "", None,
        ],
    )
    def test_unparseable_text_yields_nothing(self, raw):
        # Uydurma sınır üretmektense hiç üretmemek yeğdir; karar metne kalır.
        assert parse_version_field(raw) == []

    def test_bare_integer_is_not_an_exact_version(self):
        # "12" bir bakım DALI olabilir; eşitlik kıyası orada yanlış tehdit üretir.
        assert parse_version_field("Android 12") == []
        assert parse_version_field("Android 12.0") == [{"version": "12.0"}]

    def test_row_count_is_bounded(self):
        many = ", ".join(f"1.0.{i}" for i in range(200))
        assert len(parse_version_field(many)) <= 48
