"""Envanter planlayıcısı — yinelenen kayıt filtresi ve ürün gruplaması.

İki davranış birbirine karıştırılmamalı:
  * aynı ürün + AYNI sürüm  → tek tarama, sonuç kopyalanır
  * aynı ürün + FARKLI sürüm → ayrı kararlar, yalnızca hazırlık paylaşılır
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest

from refimpl.planning.planner import build_plan, dedup_key, product_key


@dataclass
class Item:
    product: str
    version: str
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    platform: Optional[str] = None


class TestDedupKey:
    def test_case_and_spacing_are_ignored(self):
        assert dedup_key(Item("  Google   Chrome ", "120.0")) == dedup_key(
            Item("google chrome", "120.0")
        )

    def test_version_is_part_of_the_key(self):
        assert dedup_key(Item("Tomcat", "9.0")) != dedup_key(Item("Tomcat", "10.0"))

    def test_vendor_distinguishes_generic_names(self):
        # "Calendar" satıcıya göre bambaşka bir üründür.
        assert dedup_key(Item("Calendar", "1.0", vendor="Apple")) != dedup_key(
            Item("Calendar", "1.0", vendor="Zimbra")
        )

    def test_os_distinguishes_items(self):
        assert dedup_key(Item("Chrome", "1", operating_system="macOS")) != dedup_key(
            Item("Chrome", "1", operating_system="Windows")
        )

    def test_product_key_drops_only_the_version(self):
        a, b = Item("Tomcat", "9.0", vendor="Apache"), Item("Tomcat", "10.0", vendor="Apache")
        assert product_key(a) == product_key(b)
        assert product_key(a) != product_key(Item("Tomcat", "9.0", vendor="Eclipse"))


class TestExactDuplicates:
    def test_repeated_installations_scanned_once(self):
        plan = build_plan([Item("7-Zip", "21.07")] * 8)
        assert plan.total == 8
        assert len(plan.unique_items) == 1
        assert plan.duplicates == 7

    def test_every_input_gets_a_result_slot(self):
        items = [Item("7-Zip", "21.07")] * 3 + [Item("Nginx", "1.24")]
        plan = build_plan(items)
        assert len(plan.assignment) == len(items)
        assert plan.assignment == [0, 0, 0, 1]

    def test_spelling_variants_collapse(self):
        plan = build_plan(
            [Item("Google Chrome", "120"), Item("  google   CHROME ", "120")]
        )
        assert len(plan.unique_items) == 1


class TestSameProductDifferentVersions:
    """Kritik: farklı sürümler ASLA tek kayda indirgenmemeli."""

    def test_versions_stay_separate(self):
        versions = ["9.0.90", "9.0.85", "10.1.20"]
        plan = build_plan([Item("Apache Tomcat", v) for v in versions])
        assert len(plan.unique_items) == 3
        assert plan.duplicates == 0

    def test_but_they_share_one_product_group(self):
        plan = build_plan([Item("Apache Tomcat", v) for v in ["9.0", "10.0", "11.0"]])
        assert plan.products == 1
        assert plan.groups[0].versions == ["9.0", "10.0", "11.0"]

    def test_different_vendors_do_not_share_a_group(self):
        plan = build_plan(
            [Item("Calendar", "1.0", vendor="Apple"), Item("Calendar", "2.0", vendor="Zimbra")]
        )
        assert plan.products == 2


class TestOrdering:
    def test_input_order_is_preserved(self):
        items = [Item("A", "1"), Item("B", "1"), Item("A", "1"), Item("C", "1")]
        plan = build_plan(items)
        assert plan.assignment == [0, 1, 0, 2]
        assert [i.product for i in plan.unique_items] == ["A", "B", "C"]

    def test_group_targets_line_up_with_versions(self):
        items = [Item("A", "1"), Item("B", "9"), Item("A", "2")]
        plan = build_plan(items)
        group_a = next(g for g in plan.groups if plan.unique_items[g.sample_index].product == "A")
        for version, target in zip(group_a.versions, group_a.targets):
            assert plan.unique_items[target].version == version

    def test_targets_of_maps_back_to_every_position(self):
        items = [Item("A", "1"), Item("A", "1"), Item("B", "1")]
        plan = build_plan(items)
        assert plan.targets_of() == {0: [0, 1], 1: [2]}


class TestSummary:
    def test_counts_add_up(self):
        items = [Item("A", "1")] * 5 + [Item("A", "2")] + [Item("B", "1")] * 2
        s = build_plan(items).summary()
        assert s == {"received": 8, "unique": 3, "duplicates": 5, "product_groups": 2}

    def test_empty_input(self):
        plan = build_plan([])
        assert plan.summary() == {
            "received": 0, "unique": 0, "duplicates": 0, "product_groups": 0
        }


class TestRealisticInventory:
    def test_mixed_inventory(self):
        items = (
            [Item("Google Chrome", "120.0")] * 12
            + [Item("Apache Tomcat", v) for v in ["9.0.90", "9.0.85", "10.1.20"]]
            + [Item("7-Zip", "21.07")] * 4
        )
        plan = build_plan(items)
        # 1 Chrome + 3 Tomcat sürümü + 1 7-Zip = 5 tarama
        assert len(plan.unique_items) == 5
        assert plan.duplicates == 14
        # Chrome, Tomcat, 7-Zip → 3 hazırlık
        assert plan.products == 3
