"""End-to-end run of the service tier against a LOCAL PostgreSQL and the engine
shim (reference engine over HTTP, synthetic corpus): migrations, queue claim,
worker, incremental persistence and restart resumption, verdict cache keyed by
scope and engine identity, store-side pagination, and the HTTP API through the
application's own lifespan.

Skipped unless SERVICE_TIER_E2E=1 and PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD
point at a database you own (see docker-compose.example.yml). Tables are TRUNCATED.
"""
from __future__ import annotations

import os
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SERVICE_TIER_E2E") != "1",
    reason="set SERVICE_TIER_E2E=1 and PG* variables for a local PostgreSQL",
)

ITEMS = [
    {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"},
    {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"},   # exact duplicate
    {"product": "Acme Ledgerly Server", "version": "2.4.1", "vendor": "Acme"},   # same product, other version
    {"product": "Contoso Photolens Viewer", "version": "1.2.3", "vendor": "Contoso"},
    {"product": "Tailspin Relaywire Client", "version": "5.2.8.3141", "vendor": "Tailspin"},
]
EXPECTED = {0: "THREAT", 1: "THREAT", 2: "SAFE", 3: "THREAT", 4: "THREAT"}


@pytest.fixture(scope="module")
def env():
    os.environ.setdefault("API_KEYS", "e2e-key")
    os.environ.setdefault("ADMIN_TOKEN", "e2e-admin")
    os.environ["JOB_WORKERS"] = "1"
    os.environ["CVE_SYNC_INTERVAL_HOURS"] = "0"
    from service_tier.config import get_settings
    from service_tier.storage import pool
    from service_tier.storage.migrate import run_migrations
    from service_tier.tools import engine_shim

    server = engine_shim.serve("127.0.0.1:0")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    os.environ["GOSCAN_URL"] = f"http://127.0.0.1:{server.server_address[1]}"
    get_settings.cache_clear()

    pool.close_pool()
    pool.init_pool()
    run_migrations()
    with pool.cursor(commit=True) as cur:
        cur.execute("TRUNCATE job_items, jobs, scan_results, cve_extractions, api_requests RESTART IDENTITY CASCADE")
    from service_tier.backend.services import scanner as svc
    svc.reset_model_version()
    yield {"engine_url": os.environ["GOSCAN_URL"]}
    server.shutdown()
    pool.close_pool()
    get_settings.cache_clear()


def _statuses(rows):
    return {r["position"]: (r["result"] or {}).get("status") for r in rows}


def test_migrations_create_the_schema(env):
    from service_tier.storage import pool
    with pool.cursor() as cur:
        cur.execute("SELECT version FROM schema_migrations ORDER BY version")
        versions = [r["version"] for r in cur.fetchall()]
    assert versions == ["001_init", "003_api_keys", "004_job_context", "005_job_resume", "006_extraction_cache"]


def test_queue_worker_end_to_end(env):
    from service_tier.backend.services import worker
    from service_tier.storage import jobs as job_store

    job_id = job_store.create_job(ITEMS)
    assert job_store.claim_next_job() == job_id
    worker._process_job(job_id)
    job = job_store.get_job(job_id)
    assert job["status"] == "DONE" and job["completed"] == len(ITEMS) and job["failed"] == 0
    rows = job_store.get_job_items(job_id)
    assert _statuses(rows) == EXPECTED
    assert rows[0]["cached"] is False and rows[1]["cached"] is True   # the copy is marked
    assert rows[1]["result"] == rows[0]["result"]


def test_restart_resumes_from_stored_rows(env):
    from service_tier.backend.services import worker
    from service_tier.storage import jobs as job_store

    job_id = job_store.create_job(ITEMS)
    sentinel = {"status": "UNCERTAIN", "marker": "stored before the restart"}
    job_store.save_item_result(job_id, 0, result=sentinel)
    assert [r["position"] for r in job_store.pending_items(job_id)] == [1, 2, 3, 4]
    job_store.claim_next_job()
    worker._process_job(job_id)
    rows = job_store.get_job_items(job_id)
    assert rows[0]["result"]["marker"] == "stored before the restart"   # not rescanned
    assert all(r["result"] is not None for r in rows)
    assert job_store.get_job(job_id)["completed"] == len(ITEMS)


def test_requeue_keeps_results_and_caps_attempts(env):
    from service_tier.storage import jobs as job_store

    job_id = job_store.create_job(ITEMS[:2])
    job_store.claim_next_job()
    job_store.save_item_result(job_id, 0, result={"status": "SAFE"})
    assert job_store.requeue_job(job_id) is True
    assert job_store.get_job(job_id)["status"] == "PENDING"
    assert [r["position"] for r in job_store.pending_items(job_id)] == [1]
    for _ in range(job_store.MAX_JOB_ATTEMPTS):
        job_store.claim_next_job()
        job_store.requeue_job(job_id)
    assert job_store.requeue_job(job_id) is False     # attempt cap reached
    job_store.finish_job(job_id, error="gave up")


def test_claim_is_exclusive_across_workers(env):
    from service_tier.storage import jobs as job_store

    ids = {job_store.create_job(ITEMS[:1]) for _ in range(3)}
    claimed = []
    lock = threading.Lock()

    def claim():
        got = job_store.claim_next_job()
        with lock:
            claimed.append(got)

    threads = [threading.Thread(target=claim) for _ in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()
    taken = [c for c in claimed if c]
    assert len(taken) == len(set(taken)) == 3 and set(taken) == ids   # each job claimed exactly once
    for j in ids:
        job_store.finish_job(j)


def test_verdict_cache_key_covers_scope_and_engine_identity(env, monkeypatch):
    from service_tier.backend.services import goscan, scanner as svc

    # a (product, version) pair no earlier test has scanned
    r1, hit1 = svc.scan("Acme Ledgerly Server", "2.3.5", vendor="Acme")
    r2, hit2 = svc.scan("Acme Ledgerly Server", "2.3.5", vendor="Acme")
    assert (hit1, hit2) == (False, True) and r1["status"] == r2["status"]
    _, hit3 = svc.scan("Acme Ledgerly Server", "2.3.5", vendor="Other Vendor")   # scope differs
    assert hit3 is False
    real = goscan.health()
    monkeypatch.setattr(goscan, "health", lambda refresh=False: {**real, "engine_version": "rebuilt-binary"})
    svc.reset_model_version()
    monkeypatch.setattr(goscan, "health", lambda refresh=False: {**real, "engine_version": "rebuilt-binary"})
    _, hit4 = svc.scan("Acme Ledgerly Server", "2.3.5", vendor="Acme")           # engine identity differs
    assert hit4 is False
    monkeypatch.undo()
    svc.reset_model_version()


def test_store_side_pagination(env):
    from service_tier.backend.services import scanner as svc
    from service_tier.storage import cache

    scope = svc.cache_scope(None, "Acme", None)
    scan_id = cache.scan_id_for("Acme Ledgerly Server", "2.3.9", scope, svc.engine_version())
    assert scan_id is not None
    summary = cache.get_scan_summary(scan_id)
    assert summary["counts"]["threats"] >= 1
    for key in ("threats", "uncertain_items", "safe_reasons", "result"):
        assert key not in summary                                         # summary carries counts, no lists
    page0 = cache.get_scan_findings(scan_id, "threats", limit=1, offset=0)
    page1 = cache.get_scan_findings(scan_id, "threats", limit=1, offset=1)
    assert page0["total"] == summary["counts"]["threats"] and len(page0["items"]) == 1
    if page0["total"] > 1:
        assert page0["items"] != page1["items"]
    assert cache.get_scan_findings(scan_id, "bogus") is None


def test_http_api_round_trip(env):
    from fastapi.testclient import TestClient
    from service_tier.backend.main import create_app

    headers = {"X-API-Key": os.environ["API_KEYS"]}
    with TestClient(create_app()) as client:
        health = client.get("/health").json()
        assert health["status"] == "ok" and health["database"] is True
        queued = client.post("/scan", json={"items": ITEMS}, headers=headers)
        assert queued.status_code == 202
        job_id = queued.json()["job_id"]
        deadline = time.time() + 90
        while time.time() < deadline:
            status = client.get(f"/jobs/{job_id}", headers=headers).json()
            if status["status"] in ("DONE", "FAILED"):
                break
            time.sleep(0.5)
        assert status["status"] == "DONE" and status["completed"] == len(ITEMS)
        result = client.get(f"/jobs/{job_id}/result", headers=headers).json()
        assert [i["status"] for i in result["items"]] == [EXPECTED[i] for i in range(len(ITEMS))]
        assert result["items"][1]["cached"] is True
        sync = client.post("/scan?wait=true", json={"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme"}, headers=headers)
        assert sync.status_code == 200 and sync.json()["results"][0]["status"] == "THREAT"
        assert client.post("/scan", json={"items": ITEMS}).status_code == 401          # no key
        admin = {"X-Admin-Token": os.environ["ADMIN_TOKEN"]}
        listing = client.get("/admin/scans", headers=admin).json()
        assert listing["total"] >= 1 and "result" not in listing["items"][0]
        sid = listing["items"][0]["id"]
        detail = client.get(f"/admin/scans/{sid}", headers=admin).json()
        assert "counts" in detail and "threats" not in detail
        assert client.get(f"/admin/scans/{sid}/findings?limit=5000", headers=admin).status_code == 422
