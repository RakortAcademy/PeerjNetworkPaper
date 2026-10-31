"""Estate reduction / fan-back, extraction cache keying, engine identity digest."""
from __future__ import annotations

import json
from pathlib import Path

from refimpl import engine_identity, extraction_cache
from refimpl.planning.estate_reduction import collect, fan_back, os_family
from refimpl.planning.planner import build_plan

ROOT = Path(__file__).resolve().parents[1]


class _Item:
    def __init__(self, d):
        self.product, self.version = d["product"], d["version"]
        self.vendor, self.operating_system, self.platform = d.get("vendor"), d.get("operating_system"), None


def rows():
    return [tuple(r) for r in json.loads((ROOT / "example_data/synthetic_inventory_rows.json").read_text())["rows"]]


def test_os_family_text_first_then_type():
    assert os_family("Microsoft Windows 11 Pro", None) == "Windows"
    assert os_family("Windows Server 2022", None) == "Windows Server"
    assert os_family("Ubuntu 22.04", None) == "Linux"
    assert os_family("", 3) == "macOS" and os_family("", 9) is None


def test_collect_merge_key_and_vendor_adoption():
    items, stats = collect(rows(), keep_versionless=False)
    assert stats["app_rows"] == 25 and stats["skipped_no_version"] == 1 and stats["skipped_no_name"] == 1
    browser = next(i for i in items if i["product"] == "Orbital Browser" and i["version"] == "109.0.1")
    assert browser["endpoint_count"] == 6 and browser["vendor"] == "Stellar Software"   # blank vendor row adopted
    assert browser["endpoints"] == [1001, 1002, 1003, 1004, 1005, 1006]              # duplicate endpoint collapsed
    # case-insensitive product key: "ACME LEDGERLY SERVER" 2.4.1 is its own item (different version) but same product
    names = {i["product"].lower() for i in items}
    assert "acme ledgerly server" in names
    # OS family is part of the key: Photolens Viewer on macOS is a separate item from Contoso Photolens Viewer on Windows
    assert sum(1 for i in items if "photolens viewer" in i["product"].lower()) == 3
    assert items == sorted(items, key=lambda it: (-it["endpoint_count"], it["product"].lower(), it["version"]))


def test_fan_back_restores_endpoint_granularity():
    items, _ = collect(rows(), keep_versionless=False)
    fake_results = [{"status": "SAFE", "threats": []} for _ in items]
    exposures = fan_back(items, fake_results)
    assert len(exposures) == sum(i["endpoint_count"] for i in items)
    assert {e["endpoint_id"] for e in exposures} == {1001, 1002, 1003, 1004, 1005, 1006, 1007}


def test_planner_groups_versions_and_copies_duplicates():
    items, _ = collect(rows(), keep_versionless=False)
    plan = build_plan([_Item(i) for i in items] + [_Item(items[0])])   # resubmit the first item raw
    assert plan.total == len(items) + 1 and plan.duplicates == 1
    assert plan.assignment[-1] == 0
    # product_key = (product, vendor, operating_system, platform): the two Linux
    # versions share one preparation, the Windows Server install is its own group
    groups = {tuple(sorted(g.versions)) for g in plan.groups
              if plan.unique_items[g.sample_index].product.lower() == "acme ledgerly server"}
    assert groups == {("2.3.9",), ("2.4.1", "3.1.4")}


def test_extraction_cache_keyed_by_text_digest_and_model_version():
    extraction_cache.clear()
    extraction_cache.store([("CVE-1", "text A", {"app_name": "x"})], "model-1")
    assert extraction_cache.fetch([("CVE-1", "text A")], "model-1") == {"CVE-1": {"app_name": "x"}}
    assert extraction_cache.fetch([("CVE-1", "text A edited")], "model-1") == {}   # advisory edited → miss
    assert extraction_cache.fetch([("CVE-1", "text A")], "model-2") == {}          # other model → miss
    assert extraction_cache.description_hash("text A") == extraction_cache.description_hash("text A")
    assert len(extraction_cache.description_hash("text A")) == 16
    assert extraction_cache.stats() == {"total": 1, "by_model": {"model-1": 1}}


def test_engine_identity_digest_is_content_based(tmp_path):
    a = tmp_path / "a.pth"
    b = tmp_path / "b.pth"
    a.write_bytes(b"weights"); b.write_bytes(b"weights")
    assert engine_identity.checkpoint_digest(a) == engine_identity.checkpoint_digest(b)  # path irrelevant
    engine_identity.register_checkpoint(a)
    assert engine_identity.model_version() == engine_identity.checkpoint_digest(a)
    engine_identity.reset()
    assert engine_identity.model_version() == "none"
