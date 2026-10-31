"""Taranmış kayıt uçları — filtreleme, sayfalama, yetki ve ayrıntı (ported from the
production test suite; the admin router is replaced by `routers/scans.py`).

Veritabanı taklit edilir; sınanan şey yönlendirme, doğrulama kuralları ve
`storage.cache` çağrılarına giden parametrelerdir.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from service_tier.backend.routers import scans as admin_router
from service_tier.config import get_settings

TOKEN = "test-admin-token"

ROW = {
    "id": 7,
    "product": "Northwind Mailflow Gateway",
    "version": "19.2",
    "platform": "",
    "status": "THREAT",
    "safety_score": 0,
    "threat_count": 13,
    "scanned_cves": 41,
    "hit_count": 2,
    "model_version": "abc123",
    "created_at": datetime(2026, 7, 30, 9, 0, tzinfo=timezone.utc),
    "updated_at": datetime(2026, 7, 30, 10, 0, tzinfo=timezone.utc),
}


@pytest.fixture
def calls():
    return {}


@pytest.fixture
def client(monkeypatch, calls):
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)
    get_settings.cache_clear()

    def fake_list(limit, offset, status, search):
        calls["list"] = (limit, offset, status, search)
        return {"total": 1, "limit": limit, "offset": offset, "items": [ROW]}

    def fake_summary(scan_id):
        calls["summary"] = scan_id
        if scan_id != ROW["id"]:
            return None
        return {**ROW, "counts": {"threats": 13, "uncertain": 4, "safe": 20}}

    def fake_findings(scan_id, bucket, limit, offset):
        calls["findings"] = (scan_id, bucket, limit, offset)
        if scan_id != ROW["id"]:
            return None
        return {
            "scan_id": scan_id, "bucket": bucket, "total": 13,
            "limit": limit, "offset": offset,
            "items": [{"cve_id": "CVE-2099-0101", "reason": "19.2 <= 19.2 < 19.2.1"}],
        }

    monkeypatch.setattr(admin_router.cache, "list_scans", fake_list)
    monkeypatch.setattr(admin_router.cache, "get_scan_summary", fake_summary)
    monkeypatch.setattr(admin_router.cache, "get_scan_findings", fake_findings)

    app = FastAPI()
    app.include_router(admin_router.router)
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def _get(client, path):
    return client.get(path, headers={"X-Admin-Token": TOKEN})


class TestAuth:
    def test_token_required(self, client):
        assert client.get("/admin/scans").status_code == 401

    def test_wrong_token_rejected(self, client):
        res = client.get("/admin/scans", headers={"X-Admin-Token": "wrong-token"})
        assert res.status_code == 401


class TestListing:
    def test_returns_rows(self, client):
        res = _get(client, "/admin/scans")
        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        assert body["items"][0]["product"] == "Northwind Mailflow Gateway"
        assert body["items"][0]["threat_count"] == 13

    def test_default_paging(self, client, calls):
        _get(client, "/admin/scans")
        limit, offset, status, search = calls["list"]
        assert (limit, offset, status, search) == (50, 0, None, None)

    def test_filters_are_forwarded(self, client, calls):
        _get(client, "/admin/scans?limit=10&offset=20&status=THREAT&search=git")
        assert calls["list"] == (10, 20, "THREAT", "git")

    @pytest.mark.parametrize("query", ["status=BOGUS", "limit=0", "limit=501", "offset=-1"])
    def test_invalid_query_rejected(self, client, query):
        assert _get(client, f"/admin/scans?{query}").status_code == 422

    def test_list_omits_heavy_result_payload(self, client):
        # Liste yanıtı CVE gövdelerini taşımamalı; ayrıntı ayrı uçtan gelir.
        assert "result" not in _get(client, "/admin/scans").json()["items"][0]


class TestDetail:
    """Özet uç bulgu LİSTELERİNİ taşımamalı — tek tarama binlerce kayıt üretebiliyor."""

    def test_counts_returned_without_lists(self, client):
        body = _get(client, "/admin/scans/7").json()
        assert body["counts"] == {"threats": 13, "uncertain": 4, "safe": 20}
        for key in ("threats", "uncertain_items", "safe_reasons", "result"):
            assert key not in body

    def test_missing_scan_is_404(self, client):
        assert _get(client, "/admin/scans/404404").status_code == 404


class TestFindingsPaging:
    """Bulgular sayfa sayfa okunur; on binlerce kaydı tek yanıtta göndermek
    tarayıcıyı kilitler (megabaytlarca JSON)."""

    def test_default_page(self, client, calls):
        body = _get(client, "/admin/scans/7/findings").json()
        assert body["total"] == 13
        assert body["items"][0]["cve_id"] == "CVE-2099-0101"
        assert calls["findings"] == (7, "threats", 25, 0)

    def test_bucket_and_offset_forwarded(self, client, calls):
        _get(client, "/admin/scans/7/findings?bucket=uncertain&limit=50&offset=200")
        assert calls["findings"] == (7, "uncertain", 50, 200)

    @pytest.mark.parametrize("bucket", ["threats", "uncertain", "safe"])
    def test_valid_buckets(self, client, bucket):
        assert _get(client, f"/admin/scans/7/findings?bucket={bucket}").status_code == 200

    def test_unknown_bucket_rejected(self, client):
        assert _get(client, "/admin/scans/7/findings?bucket=bogus").status_code == 422

    def test_page_size_capped(self, client):
        # Sayfa boyutu sınırsız olsaydı tek istek yine tüm listeyi çekerdi.
        assert _get(client, "/admin/scans/7/findings?limit=5000").status_code == 422

    def test_missing_scan_is_404(self, client):
        assert _get(client, "/admin/scans/404404/findings").status_code == 404


class TestCacheVersioning:
    """Önbellek anahtarı model AĞIRLIKLARINI ve KARAR MANTIĞINI birlikte taşımalı.

    Anahtar yalnızca model dosyasının hash'ini taşıdığında, karar mantığındaki
    bir düzeltmeden sonra API eski kararı döndürmeye devam ediyordu: bir ürünün
    kapısı kodda düzeltilmişken API hâlâ 'etkilenmiyor' diyordu.

    Karar artık goscan'de verildiği için mantık damgası da ORADAN gelir —
    çalışan ikilinin özeti. Python kaynak dosyalarının özetini kullanmak yanlış olurdu:
    goscan yeniden derlendiğinde eski kararlar geçersizleşmezdi.
    """

    @staticmethod
    def _fake_health(monkeypatch, model="m1", engine="e1"):
        from service_tier.backend.services import goscan, scanner as svc

        monkeypatch.setattr(
            goscan, "health",
            lambda refresh=False: {"status": "ok", "model_version": model,
                                   "engine_version": engine, "model_loaded": True},
        )
        svc.reset_model_version()

    def test_engine_version_covers_model_and_logic(self, monkeypatch):
        from service_tier.backend.services import scanner as svc

        self._fake_health(monkeypatch)
        engine = svc.engine_version()
        assert svc.model_version() in engine
        assert svc.logic_version() in engine
        assert engine != svc.model_version()

    def test_logic_version_changes_when_goscan_binary_changes(self, monkeypatch):
        """goscan yeniden derlendiğinde damga değişmeli — yoksa önbellek eski
        kararı vermeye devam eder."""
        from service_tier.backend.services import scanner as svc

        self._fake_health(monkeypatch, engine="e1")
        first = svc.logic_version()
        self._fake_health(monkeypatch, engine="e2")
        assert svc.logic_version() != first

    def test_logic_version_is_stable_without_changes(self, monkeypatch):
        from service_tier.backend.services import scanner as svc

        self._fake_health(monkeypatch)
        first = svc.logic_version()
        svc.reset_model_version()
        assert svc.logic_version() == first
