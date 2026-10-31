"""Job worker without a database: incremental persistence per product group,
copied results marked as such, and per-group failure isolation (manuscript
Section 7, "Queue Durability and Failure Isolation"). The job store is replaced
by an in-memory double with the same call shape."""
from __future__ import annotations

import pytest

from service_tier.backend.services import scanner as scanner_service
from service_tier.backend.services import worker


class FakeJobStore:
    def __init__(self, rows):
        self.rows = {r["position"]: dict(r) for r in rows}
        self.saved = {}
        self.finished = None
        self.heartbeats = 0

    def pending_items(self, job_id):
        return [r for p, r in sorted(self.rows.items())
                if p not in self.saved or (self.saved[p].get("result") is None and self.saved[p].get("error") is None)]

    def save_item_result(self, job_id, position, *, result=None, cached=False, error=None):
        self.saved[position] = {"result": result, "cached": cached, "error": error}

    def finish_job(self, job_id, error=None):
        self.finished = ("FAILED" if error else "DONE", error)

    def heartbeat(self, job_id):
        self.heartbeats += 1


def _rows(specs):
    return [{"position": i, "product": p, "version": v, "platform": "", "vendor": "", "operating_system": ""}
            for i, (p, v) in enumerate(specs)]


def _fake_scan_versions(calls, failing=()):
    def scan_versions(product, versions, platform=None, *, vendor=None, operating_system=None, use_cache=True):
        calls.append((product, tuple(versions)))
        if product in failing:
            raise RuntimeError("engine failure for " + product)
        return [({"product": product, "version": v, "status": "SAFE", "threats": []}, False) for v in versions]
    return scan_versions


@pytest.fixture
def run(monkeypatch):
    def _run(specs, failing=()):
        worker._stop.clear()  # another test may have stopped the worker pool through the app lifespan
        fake = FakeJobStore(_rows(specs))
        calls = []
        monkeypatch.setattr(worker, "job_store", fake)
        monkeypatch.setattr(scanner_service, "scan_versions", _fake_scan_versions(calls, failing))
        worker._process_job("job-1")
        return fake, calls
    return _run


def test_duplicates_are_scanned_once_and_copies_marked(run):
    fake, calls = run([("Acme Ledgerly Server", "2.3.9"), ("Acme Ledgerly Server", "2.3.9"),
                       ("Acme Ledgerly Server", "2.4.1"), ("Contoso Photolens Viewer", "1.2.3")])
    # one preparation per product, versions of one product in one call
    assert sorted(calls) == [("Acme Ledgerly Server", ("2.3.9", "2.4.1")), ("Contoso Photolens Viewer", ("1.2.3",))]
    assert fake.saved[0]["cached"] is False and fake.saved[1]["cached"] is True  # the copy is marked
    assert fake.saved[1]["result"] == fake.saved[0]["result"]
    assert len(fake.saved) == 4 and fake.finished == ("DONE", None)
    assert fake.heartbeats == 2  # one heartbeat per persisted group


def test_group_failure_does_not_discard_the_rest(run):
    fake, _ = run([("Acme Ledgerly Server", "2.3.9"), ("Broken Product", "1.0"), ("Contoso Photolens Viewer", "1.2.3")],
                  failing=("Broken Product",))
    assert fake.saved[1]["error"].startswith("engine failure") and fake.saved[1]["result"] is None
    assert fake.saved[0]["result"]["status"] == "SAFE" and fake.saved[2]["result"]["status"] == "SAFE"
    assert fake.finished == ("DONE", None)  # the job completes; the failed group is reported per item


def test_resumption_scans_only_rows_without_an_outcome(monkeypatch):
    worker._stop.clear()
    fake = FakeJobStore(_rows([("Acme Ledgerly Server", "2.3.9"), ("Contoso Photolens Viewer", "1.2.3")]))
    fake.saved[0] = {"result": {"status": "THREAT", "marker": "kept"}, "cached": False, "error": None}
    calls = []
    monkeypatch.setattr(worker, "job_store", fake)
    monkeypatch.setattr(scanner_service, "scan_versions", _fake_scan_versions(calls))
    worker._process_job("job-1")
    assert calls == [("Contoso Photolens Viewer", ("1.2.3",))]  # derived resumption: stored rows are not rescanned
    assert fake.saved[0]["result"]["marker"] == "kept"
    assert fake.finished == ("DONE", None)
