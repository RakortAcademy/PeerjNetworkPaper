"""Sürüm ayrıştırma ve aralık eşleme testleri."""
from __future__ import annotations

import pytest

from refimpl.versioning import check_version_in_range, compare_versions, parse_version


class TestParse:
    def test_semver(self):
        v = parse_version("9.0.1")
        assert (v.major, v.minor, v.patch) == (9, 0, 1)

    def test_v_prefix_stripped(self):
        assert parse_version("v2.4.1").major == 2

    def test_four_part_build(self):
        v = parse_version("141.0.7390.77")
        assert v.major == 141

    def test_garbage_returns_none(self):
        assert parse_version("not-a-version") is None


class TestCompare:
    @pytest.mark.parametrize(
        "a,b,expected",
        [
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.0.0", 1),
            ("1.0.0", "1.0.0", 0),
            ("2.0", "1.9.9", 1),
            ("1.10.0", "1.9.0", 1),  # sayısal karşılaştırma, sözlüksel değil
        ],
    )
    def test_ordering(self, a, b, expected):
        assert compare_versions(a, b) == expected


class TestRangeMatching:
    def test_below_upper_bound_is_vulnerable(self):
        result = check_version_in_range("1.0.0", {"less_than": "1.2.0"})
        assert result["vulnerable"] is True

    def test_at_or_above_upper_bound_is_safe(self):
        result = check_version_in_range("1.2.0", {"less_than": "1.2.0"})
        assert result["vulnerable"] is False

    def test_less_than_or_equal_includes_boundary(self):
        assert check_version_in_range("1.2.0", {"less_than_or_equal": "1.2.0"})["vulnerable"]

    def test_inside_range_is_vulnerable(self):
        result = check_version_in_range(
            "1.5.0", {"greater_equal": "1.0.0", "less_than": "2.0.0"}
        )
        assert result["vulnerable"] is True

    def test_below_range_start_is_safe(self):
        result = check_version_in_range(
            "0.9.0", {"greater_equal": "1.0.0", "less_than": "2.0.0"}
        )
        assert result["vulnerable"] is False

    def test_unparseable_customer_version_is_not_a_threat(self):
        result = check_version_in_range("bilinmiyor", {"less_than": "1.2.0"})
        assert result["vulnerable"] is False


class TestCommitHashBounds:
    """Sürüm sınırı olarak bildirilen git commit hash'leri.

    Linux kernel CNA'sı düzeltmeyi commit ile bildirir; bu değerler rakamla
    başladığında "sürüm gibi" görünür. Sürüm sanılınca "4.14.0 iki hash
    arasında" gibi anlamsız karşılaştırmalar THREAT üretir.
    """

    @pytest.mark.parametrize(
        "value",
        [
            "3c68d44a2b49a0ac9165faa9c191e1e618c8a8d5",
            "50f0012da1040f69a4e788cd9ae2ed7ca47a9756",
            "97bc3683c24999ee621d847c9348c75d2fe86272",
            "9ad15e214fcd",  # kısaltılmış hash
        ],
    )
    def test_hashes_are_rejected_as_bounds(self, value):
        from refimpl.scanner import _clean_bound

        assert _clean_bound(value) == ""

    @pytest.mark.parametrize(
        "value",
        [
            "4.14.0", "9.0.90", "1.1.1k", "v2.3", "11.0.21",
            "202401011200",   # saf rakam build numarası — hash değil
            "20231025",       # tarih biçimli sürüm
            "8u212",
        ],
    )
    def test_real_versions_still_accepted(self, value):
        from refimpl.scanner import _clean_bound

        assert _clean_bound(value) != ""

    def test_hash_bound_yields_no_verdict(self):
        # Sınır yalnızca hash ise karar verilemez; uydurma THREAT üretilmemeli.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{
            "greater_equal": "3c68d44a2b49a0ac9165faa9c191e1e618c8a8d5",
            "less_than": "50f0012da1040f69a4e788cd9ae2ed7ca47a9756",
            "less_than_or_equal": "",
        }]
        assert _resolve_with_structured_bounds("4.14.0", ranges) is None

    def test_real_bound_alongside_hash_still_decides(self):
        # Kernel kayıtlarında hash satırlarının yanında gerçek sürüm satırı da
        # bulunabiliyor; o satır kararı vermeye devam etmeli.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [
            {"greater_equal": "3c68d44a2b49a0ac9165faa9c191e1e618c8a8d5",
             "less_than": "50f0012da1040f69a4e788cd9ae2ed7ca47a9756",
             "less_than_or_equal": ""},
            {"greater_equal": "4.14", "less_than": "4.14.300", "less_than_or_equal": ""},
        ]
        resolved = _resolve_with_structured_bounds("4.14.0", ranges)
        assert resolved is not None
        assert resolved[0] == "THREAT"


class TestExactVersionList:
    """Aralık yerine TEK TEK sayılan etkilenen sürümler.

    CNA'ların bir bölümü "4.8.3, 4.6.7" gibi listeler yazıyor. Bu satırlar
    yapısal sınır taşımadığı için karar motoruna hiç ulaşmıyor, etkilenen
    sürümleri kayıtlı olan ürünler UNCERTAIN döner.
    """

    def test_listed_version_is_a_threat(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
                   "greater_equal": "", "default_status": ""}]
        resolved = _resolve_with_structured_bounds("4.8.3", ranges)
        assert resolved is not None and resolved[0] == "THREAT"
        assert resolved[2] == "eq"

    def test_version_outside_the_list_is_safe(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [
            {"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
             "greater_equal": "", "default_status": ""},
            {"version": "4.6.7", "less_than": "", "less_than_or_equal": "",
             "greater_equal": "", "default_status": ""},
        ]
        resolved = _resolve_with_structured_bounds("5.1.0", ranges)
        assert resolved is not None and resolved[0] == "SAFE"
        assert resolved[2] == "neq"

    def test_default_status_affected_blocks_the_safe_conclusion(self):
        # defaultStatus='affected' olduğunda liste bir ÖRNEKtir; sayılmayan
        # sürümler de etkilenmiştir ve "listede yok → güvenli" kaçan tehdit olur.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
                   "greater_equal": "", "default_status": "affected"}]
        assert _resolve_with_structured_bounds("5.1.0", ranges) is None

    def test_listed_version_still_matches_when_default_status_affected(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
                   "greater_equal": "", "default_status": "affected"}]
        resolved = _resolve_with_structured_bounds("4.8.3", ranges)
        assert resolved is not None and resolved[0] == "THREAT"

    def test_range_derived_safe_wins_over_list_derived_safe(self):
        # Aralıktan gelen SAFE ("düzeltmeden sonra") daha güçlü bir gerekçedir;
        # yanıtta o görünmeli.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [
            {"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
             "greater_equal": "", "default_status": ""},
            {"version": "", "less_than": "", "less_than_or_equal": "4.6.2",
             "greater_equal": "", "default_status": ""},
        ]
        resolved = _resolve_with_structured_bounds("5.1.0", ranges)
        assert resolved is not None and resolved[0] == "SAFE"
        assert resolved[2] == "le"

    def test_threat_in_another_branch_beats_a_non_match(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [
            {"version": "4.8.3", "less_than": "", "less_than_or_equal": "",
             "greater_equal": "", "default_status": ""},
            {"version": "4.6.7", "less_than": "", "less_than_or_equal": "",
             "greater_equal": "", "default_status": ""},
        ]
        resolved = _resolve_with_structured_bounds("4.6.7", ranges)
        assert resolved is not None and resolved[0] == "THREAT"

    def test_non_version_text_is_ignored(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"version": "S7x and prior", "less_than": "", "less_than_or_equal": "",
                   "greater_equal": "", "default_status": ""}]
        assert _resolve_with_structured_bounds("5.1.0", ranges) is None

    def test_commit_hash_is_not_an_exact_version(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"version": "50f0012da1040f69a4e788cd9ae2ed7ca47a9756",
                   "less_than": "", "less_than_or_equal": "", "greater_equal": "",
                   "default_status": ""}]
        assert _resolve_with_structured_bounds("4.14.0", ranges) is None


class TestExclusiveLowerBound:
    """NVD `versionStartExcluding`: sınırın KENDİSİ etkilenmiyor.

    CPE verisinde geçiyor, CNA kayıtlarında karşılığı yok. `greater_equal` gibi
    işlemek tam sınırdaki sürümü yanlışlıkla tehdit gösterirdi.
    """

    def test_boundary_version_is_safe(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"greater_than": "6.0.0", "less_than": "6.0.7",
                   "less_than_or_equal": "", "greater_equal": ""}]
        resolved = _resolve_with_structured_bounds("6.0.0", ranges)
        assert resolved is not None and resolved[0] == "SAFE"

    def test_version_above_the_boundary_is_a_threat(self):
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"greater_than": "6.0.0", "less_than": "6.0.7",
                   "less_than_or_equal": "", "greater_equal": ""}]
        resolved = _resolve_with_structured_bounds("6.0.1", ranges)
        assert resolved is not None and resolved[0] == "THREAT"

    def test_inclusive_boundary_still_matches(self):
        # greater_equal davranışı değişmemeli.
        from refimpl.scanner import _resolve_with_structured_bounds

        ranges = [{"greater_equal": "6.0.0", "less_than": "6.0.7",
                   "less_than_or_equal": "", "greater_than": ""}]
        resolved = _resolve_with_structured_bounds("6.0.0", ranges)
        assert resolved is not None and resolved[0] == "THREAT"
