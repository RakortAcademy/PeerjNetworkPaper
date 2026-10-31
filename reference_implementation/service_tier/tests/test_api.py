"""HTTP uç testleri (ported from the production test suite; imports rewritten).

Model ve PostgreSQL bu testlerde devre dışı bırakılır; amaç yönlendirme,
doğrulama, kimlik doğrulama ve senkron/asenkron davranışı sınamaktır.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from service_tier.backend.routers import jobs as jobs_router
from service_tier.backend.routers import scan as scan_router
from service_tier.backend.schemas import ScanItem
from service_tier.backend.security import Caller
from service_tier.backend.services import scanner as scanner_service
from service_tier.config import get_settings


def _fake_result(product: str, version: str, status: str = "SAFE") -> dict:
    return {
        "product": product,
        "version": version,
        "status": status,
        "safety_score": 100 if status == "SAFE" else 0,
        "scanned_cves": 3,
        "threats": [],
        "uncertain_items": [],
        "safe_reasons": [],
        "scanned_cve_ids": ["CVE-2024-0001"],
        "model_version": "test",
    }


@pytest.fixture(autouse=True)
def _clean_settings(monkeypatch):
    """Her test kendi ortam değişkenlerini kursun."""
    get_settings.cache_clear()
    monkeypatch.delenv("API_KEYS", raising=False)
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _no_db(monkeypatch):
    """Veritabanına gitmeden auth ve job deposu taklit edilir."""
    from service_tier.storage import api_keys as key_store

    monkeypatch.setattr(key_store, "any_active", lambda: False)
    monkeypatch.setattr(key_store, "verify", lambda raw: None)
    monkeypatch.setattr(scan_router.job_store, "create_job", lambda items: "job-1")


@pytest.fixture
def client(monkeypatch):
    """Model ve DB'siz, yalnızca router'ları içeren uygulama."""
    monkeypatch.setattr(
        scanner_service,
        "scan",
        lambda product, version, platform=None, vendor=None, operating_system=None, use_cache=True: (
            _fake_result(product, version),
            False,
        ),
    )
    # Senkron yol planı kurup TEK çağrıda taratır (`scan_groups`); kararı
    # goscan veriyor, bu testlerde motor devre dışı.
    def _fake_groups(groups, unique_items, use_cache=True):
        out = [None] * len(unique_items)
        for group in groups:
            sample = unique_items[group.sample_index]
            for version, target in zip(group.versions, group.targets):
                out[target] = (_fake_result(sample.product, version), False)
        return out

    monkeypatch.setattr(scanner_service, "scan_groups", _fake_groups)
    monkeypatch.setattr(scan_router.scanner_service, "scan_groups", _fake_groups)
    app = FastAPI()
    app.include_router(scan_router.router)
    app.include_router(jobs_router.router)
    with TestClient(app) as c:
        yield c


class TestAsyncScan:
    """Varsayılan davranış: kuyruğa al, job_id döndür."""

    def test_single_item_is_queued(self, client):
        r = client.post("/scan", json={"product": "Apache Tomcat", "version": "9.0.1"})
        assert r.status_code == 202
        body = r.json()
        assert body["job_id"] == "job-1"
        assert body["status"] == "PENDING"
        assert body["total"] == 1
        assert body["result_url"] == "/jobs/job-1/result"

    def test_multiple_items_queued_as_one_job(self, client):
        r = client.post(
            "/scan",
            json={"items": [
                {"product": "OpenSSL", "version": "1.0.1g"},
                {"product": "VLC media player", "version": "3.0.19"},
            ]},
        )
        assert r.status_code == 202
        assert r.json()["total"] == 2

    def test_over_job_limit_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("MAX_JOB_ITEMS", "2")
        get_settings.cache_clear()
        r = client.post(
            "/scan",
            json={"items": [{"product": f"p{i}", "version": "1.0"} for i in range(3)]},
        )
        assert r.status_code == 413


class TestSyncScan:
    """wait=true ile sonucu bekleyen çağrı."""

    def test_single_item_body(self, client):
        r = client.post(
            "/scan?wait=true", json={"product": "Apache Tomcat", "version": "9.0.1"}
        )
        assert r.status_code == 200
        body = r.json()
        assert len(body["results"]) == 1
        assert body["results"][0]["product"] == "Apache Tomcat"
        assert body["results"][0]["status"] == "SAFE"

    def test_multiple_items(self, client):
        r = client.post(
            "/scan?wait=true",
            json={"items": [
                {"product": "OpenSSL", "version": "1.0.1g"},
                {"product": "VLC media player", "version": "3.0.19"},
            ]},
        )
        assert r.status_code == 200
        assert len(r.json()["results"]) == 2

    def test_batch_over_limit_is_rejected(self, client, monkeypatch):
        monkeypatch.setenv("MAX_BATCH_ITEMS", "2")
        get_settings.cache_clear()
        r = client.post(
            "/scan?wait=true",
            json={"items": [{"product": f"p{i}", "version": "1.0"} for i in range(3)]},
        )
        assert r.status_code == 413


class TestValidation:
    def test_empty_body_is_rejected(self, client):
        assert client.post("/scan", json={}).status_code == 422

    def test_blank_product_is_rejected(self, client):
        r = client.post("/scan", json={"items": [{"product": "  ", "version": "1.0"}]})
        assert r.status_code == 422

    def test_scan_item_strips_whitespace(self):
        assert ScanItem(product="  Tomcat  ", version=" 9.0 ").product == "Tomcat"


class TestAuth:
    def test_missing_key_rejected_when_configured(self, client, monkeypatch):
        monkeypatch.setenv("API_KEYS", "secret-key")
        get_settings.cache_clear()
        assert client.post("/scan", json={"product": "x", "version": "1.0"}).status_code == 401

    def test_static_key_accepted(self, client, monkeypatch):
        monkeypatch.setenv("API_KEYS", "secret-key")
        get_settings.cache_clear()
        r = client.post(
            "/scan",
            json={"product": "x", "version": "1.0"},
            headers={"X-API-Key": "secret-key"},
        )
        assert r.status_code == 202

    def test_bearer_token_accepted(self, client, monkeypatch):
        monkeypatch.setenv("API_KEYS", "secret-key")
        get_settings.cache_clear()
        r = client.post(
            "/scan",
            json={"product": "x", "version": "1.0"},
            headers={"Authorization": "Bearer secret-key"},
        )
        assert r.status_code == 202

    def test_wrong_key_rejected(self, client, monkeypatch):
        monkeypatch.setenv("API_KEYS", "secret-key")
        get_settings.cache_clear()
        r = client.post(
            "/scan",
            json={"product": "x", "version": "1.0"},
            headers={"X-API-Key": "nope"},
        )
        assert r.status_code == 401

    def test_database_key_accepted(self, client, monkeypatch):
        """Panelden üretilmiş anahtar veritabanından doğrulanır."""
        from service_tier.storage import api_keys as key_store

        monkeypatch.setenv("API_KEYS", "")
        get_settings.cache_clear()
        monkeypatch.setattr(key_store, "any_active", lambda: True)
        monkeypatch.setattr(
            key_store,
            "verify",
            lambda raw: {"id": 7, "name": "demo-client", "key_prefix": "demo_ab"}
            if raw == "demo_valid"
            else None,
        )
        ok = client.post(
            "/scan",
            json={"product": "x", "version": "1.0"},
            headers={"X-API-Key": "demo_valid"},
        )
        assert ok.status_code == 202
        bad = client.post(
            "/scan",
            json={"product": "x", "version": "1.0"},
            headers={"X-API-Key": "demo_wrong"},
        )
        assert bad.status_code == 401

    def test_open_when_no_keys_configured(self, client):
        """Hiç anahtar tanımlı değilse (ilk kurulum) erişim açıktır."""
        r = client.post("/scan", json={"product": "x", "version": "1.0"})
        assert r.status_code == 202


class TestJobsEndpoint:
    def test_create_job(self, client, monkeypatch):
        monkeypatch.setattr(jobs_router.job_store, "create_job", lambda items: "job-2")
        r = client.post("/jobs", json={"items": [{"product": "x", "version": "1.0"}]})
        assert r.status_code == 202
        assert r.json() == {"job_id": "job-2", "status": "PENDING", "total": 1}

    def test_unknown_job_returns_404(self, client, monkeypatch):
        monkeypatch.setattr(jobs_router.job_store, "get_job", lambda job_id: None)
        assert client.get("/jobs/missing").status_code == 404

    def test_result_returns_202_while_running(self, client, monkeypatch):
        monkeypatch.setattr(
            jobs_router.job_store,
            "get_job",
            lambda job_id: {
                "id": job_id, "status": "RUNNING", "total": 5,
                "completed": 2, "failed": 0, "error": None,
                "created_at": None, "started_at": None, "finished_at": None,
            },
        )
        assert client.get("/jobs/job-1/result").status_code == 202

    def test_result_returned_when_done(self, client, monkeypatch):
        monkeypatch.setattr(
            jobs_router.job_store,
            "get_job",
            lambda job_id: {
                "id": job_id, "status": "DONE", "total": 1,
                "completed": 1, "failed": 0, "error": None,
                "created_at": None, "started_at": None, "finished_at": None,
            },
        )
        monkeypatch.setattr(
            jobs_router.job_store,
            "get_job_items",
            lambda job_id: [
                {
                    "position": 0, "product": "OpenSSL", "version": "1.0.1g",
                    "platform": "", "status": "THREAT", "cached": False,
                    "result": _fake_result("OpenSSL", "1.0.1g", "THREAT"), "error": None,
                }
            ],
        )
        r = client.get("/jobs/job-1/result")
        assert r.status_code == 200
        assert r.json()["items"][0]["status"] == "THREAT"


# --------------------------------------------------------------------------
# Request → response through the real decision code (reviewer path, no DB).
# The engine shim runs `ThreatScanner` over the synthetic corpus without the
# neural layer (rule and regex extraction only); the service tier's blocking
# variant (`?wait=true`) is pointed at it with the verdict cache off.

import json as _json
import threading
import urllib.error
import urllib.request
from pathlib import Path

_EXAMPLE_DATA = Path(__file__).resolve().parents[2] / "example_data"


@pytest.fixture(scope="module")
def shim_url():
    from service_tier.tools import engine_shim

    server = engine_shim.serve("127.0.0.1:0")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _post_shim(url, body):
    req = urllib.request.Request(
        f"{url}/scan", data=_json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, _json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, _json.loads(exc.read())


def _ids(entries):
    return {e["cve_id"] for e in entries}


class TestEngineShimHTTP:
    def test_affected_version_is_threat_with_advisory_and_reason(self, shim_url):
        code, body = _post_shim(shim_url, {"items": [
            {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"}]})
        assert code == 200
        r = body["results"][0]
        assert r["status"] == "THREAT"
        assert _ids(r["threats"]) == {"CVE-2099-0001"}
        assert "2.3.9 < 2.4.1" in r["threats"][0]["reason"]
        assert "CVE-2099-0001" in r["decision_summary"]["summary"]

    def test_fixed_version_is_safe(self, shim_url):
        code, body = _post_shim(shim_url, {"product": "Acme Ledgerly Server", "version": "2.4.1", "vendor": "Acme"})
        assert code == 200
        r = body["results"][0]
        assert r["status"] == "SAFE" and r["threats"] == []
        assert "CVE-2099-0001" in _ids(r["safe_reasons"])

    def test_vendor_decides_which_advisory_applies(self, shim_url):
        _, body = _post_shim(shim_url, {"items": [
            {"product": "Acme Ledgerly Server", "version": "2.1", "vendor": "Acme"},
            {"product": "Fabrikam Ledgerly Server", "version": "2.1", "vendor": "Fabrikam"}]})
        acme, fabrikam = body["results"]
        assert _ids(acme["threats"]) == {"CVE-2099-0001"}
        assert _ids(fabrikam["threats"]) == {"CVE-2099-0009"}

    def test_os_gate(self, shim_url):
        item = {"product": "Orbital Browser", "version": "110.0.1", "vendor": "Stellar Software"}
        _, body = _post_shim(shim_url, {"items": [
            {**item, "operating_system": "Windows 11"}, {**item, "operating_system": "Android 14"}]})
        windows, android = body["results"]
        assert _ids(windows["threats"]) == {"CVE-2099-0007"}
        assert _ids(android["threats"]) == {"CVE-2099-0006", "CVE-2099-0007"}

    def test_free_os_text_does_not_change_product_identity(self, shim_url):
        item = {"product": "ZetaDB", "version": "4.0.3", "vendor": "Zeta Labs"}
        _, body = _post_shim(shim_url, {"items": [item, {**item, "operating_system": "Ubuntu 22.04"}]})
        bare, ubuntu = body["results"]
        assert _ids(bare["threats"]) == _ids(ubuntu["threats"]) == {"CVE-2099-0011"}
        assert ubuntu["operating_system"] == "Linux"

    def test_generic_name_is_uncertain_with_reason(self, shim_url):
        _, body = _post_shim(shim_url, {"items": [{"product": "Notes", "version": "4.13"}]})
        r = body["results"][0]
        assert r["status"] == "UNCERTAIN" and r["ambiguous_product"] is True
        assert "vendor or operating_system" in r["decision_summary"]["summary"]

    def test_unknown_product_is_not_found_with_reason(self, shim_url):
        _, body = _post_shim(shim_url, {"items": [{"product": "Quasar Widget Studio", "version": "1.0"}]})
        r = body["results"][0]
        assert r["status"] == "NOT_FOUND" and r["threats"] == []
        assert "no product match" in r["decision_summary"]["summary"]

    def test_unparseable_version_is_uncertain_not_safe(self, shim_url):
        _, body = _post_shim(shim_url, {"items": [{"product": "Acme Ledgerly Server", "version": "latest", "vendor": "Acme"}]})
        assert body["results"][0]["status"] == "UNCERTAIN"

    @pytest.mark.parametrize("body", [
        {"items": "x"}, {"items": [{"product": "", "version": "1.0"}]}, {"items": [{"product": "x"}]}, {}, [1],
    ])
    def test_malformed_request_is_rejected(self, shim_url, body):
        code, resp = _post_shim(shim_url, body)
        assert code == 422 and resp["detail"]

    def test_inventory_batch_keeps_submitted_order(self, shim_url):
        rows = _json.loads((_EXAMPLE_DATA / "synthetic_inventory_rows.json").read_text(encoding="utf-8"))["rows"]
        items = [{"product": r[1], "version": r[2], "vendor": r[3] or None, "operating_system": r[5] or None}
                 for r in rows if r[1] and r[2]]
        code, body = _post_shim(shim_url, {"items": items})
        assert code == 200
        assert [(r["product"], r["version"]) for r in body["results"]] == [(i["product"], i["version"]) for i in items]
        assert {r["status"] for r in body["results"]} >= {"THREAT", "SAFE", "NOT_FOUND"}
        assert all(r["decision_summary"]["summary"] for r in body["results"])


class TestServiceTierRealEngine:
    """`POST /scan?wait=true` → planner → engine contract → ThreatScanner, no database."""

    @pytest.fixture
    def real_client(self, shim_url, monkeypatch):
        monkeypatch.setenv("GOSCAN_URL", shim_url)
        monkeypatch.setenv("CACHE_ENABLED", "0")
        get_settings.cache_clear()
        scanner_service.reset_model_version()
        app = FastAPI()
        app.include_router(scan_router.router)
        with TestClient(app) as c:
            yield c
        scanner_service.reset_model_version()

    def test_batch_round_trip(self, real_client):
        r = real_client.post("/scan?wait=true", json={"items": [
            {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"},
            {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"},
            {"product": "Acme Ledgerly Server", "version": "2.4.1", "vendor": "Acme"},
            {"product": "Contoso Photolens Viewer", "version": "1.2.3", "vendor": "Contoso"},
            {"product": "Notes", "version": "4.13"},
        ]})
        assert r.status_code == 200
        res = r.json()["results"]
        assert [x["status"] for x in res] == ["THREAT", "THREAT", "SAFE", "THREAT", "UNCERTAIN"]
        assert [x["cached"] for x in res] == [False, True, False, False, False]
        assert [t["cve_id"] for t in res[0]["threats"]] == ["CVE-2099-0001"]
        assert [t["cve_id"] for t in res[3]["threats"]] == ["CVE-2099-0005"]
        assert res[4]["ambiguous_product"] is True
        assert r.json()["inventory"]["duplicates"] == 1
