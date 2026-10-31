"""Engine shim: serves the Python reference engine over the compiled engine's HTTP
contract, so the service tier can be run end to end without the Go binary, a
trained checkpoint or a populated store.

    python -m service_tier.tools.engine_shim --addr 127.0.0.1:8390 [--model DIR]

Contract (the subset `service_tier/backend/services/goscan.py` uses):

    GET  /health  -> {"status": "ok", "model_loaded": true,
                      "model_version": <digest>, "engine_version": <digest>}
    POST /scan    {"items": [{product, version, vendor, operating_system, platform}, ...]}
                  or one item as the body: {product, version, ...}
                  -> {"results": [<ThreatScanner result>, ...]}   (same order)
                  -> 422 {"detail": [...]} when the body does not satisfy the service
                     tier's request schema (`service_tier/backend/schemas.py`:
                     product and version required and non-empty)

This is a REVIEWER HARNESS, not a component of the production system: it is
single-threaded, runs over the synthetic corpus (`example_data/synthetic_corpus.jsonl`)
and, unless `--model` names a checkpoint, uses the test double that runs the
rule and regex extraction layers without the neural tagger (`tests/helpers.py`,
`NoModelExtractor`). Verdicts it produces are illustrative. Its two identifiers
follow the production rule: `model_version` is a digest of the checkpoint bytes
(or "no-model"), `engine_version` a digest of the decision code it runs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]  # reference_implementation/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from refimpl import engine_identity, extraction_cache, store  # noqa: E402
from refimpl.corpus import InMemoryCorpus  # noqa: E402
from refimpl.planning.estate_reduction import os_family  # noqa: E402
from refimpl.rationale import build_product_decision_summary  # noqa: E402
from refimpl.scanner import ThreatScanner  # noqa: E402

from pydantic import ValidationError  # noqa: E402

from service_tier.backend.schemas import ScanRequest  # noqa: E402

logger = logging.getLogger("engine_shim")

DEFAULT_CORPUS = ROOT / "example_data" / "synthetic_corpus.jsonl"


def engine_code_digest() -> str:
    """Digest of the decision code the shim runs, and of the shim itself (the analogue
    of the binary digest)."""
    h = hashlib.sha256()
    for p in sorted((ROOT / "refimpl").rglob("*.py")) + [Path(__file__).resolve()]:
        h.update(p.relative_to(ROOT).as_posix().encode())
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _explain(r: dict) -> None:
    """Gives every result an English `decision_summary.summary`.

    The decision code's early exits (no candidate, relevance rejection, generic
    name, update package) return before the rationale step and carry either no
    summary or only the Turkish `summary_tr`. The verdict is not changed here.
    """
    ds = r.get("decision_summary") or {}
    if ds.get("summary"):
        return
    product, version = r.get("product"), r.get("version")
    if r.get("ambiguous_product"):
        text = (f"Result UNCERTAIN: the name '{product}' alone does not identify a product "
                f"(the same name is used by several vendors); give vendor or "
                f"operating_system to scan it.")
    elif r.get("update_package"):
        text = (f"Result NOT_FOUND: '{product}' is an installed update/patch record, not an "
                f"application; the product to scan is the operating system itself.")
    elif r.get("relevance_rejected"):
        text = (f"Result NOT_FOUND: {r.get('cve_candidates_total', 0)} advisory(ies) matched "
                f"{product} v{version} by keyword only, with relevance "
                f"{r.get('top_relevance_score')} below the acceptance threshold; no product "
                f"match in the reference CVE database.")
    elif r.get("scan_failed"):
        text = f"Scan failed for this item ({r['scan_failed']}); no verdict was computed."
    else:
        text = build_product_decision_summary(r)["summary"]
    r["decision_summary"] = {**ds, "status": r.get("status"), "summary": text}


class Engine:
    def __init__(self, corpus_path: Path, model: str | None) -> None:
        corpus = InMemoryCorpus.load(corpus_path)
        store.use_corpus(corpus)
        extraction_cache.clear()
        if model:
            self.scanner = ThreatScanner(model_path=model)
            self.scanner.load()
            self.model_version = engine_identity.model_version()
        else:
            from tests.helpers import NoModelExtractor  # test double, see module docstring

            self.scanner = ThreatScanner(extractor=NoModelExtractor())
            self.model_version = "no-model"
        self.engine_version = engine_code_digest()
        self.corpus_stats = corpus.stats()
        self._lock = threading.Lock()

    def health(self) -> dict:
        return {
            "status": "ok",
            "model_loaded": True,
            "model_version": self.model_version,
            "engine_version": self.engine_version,
            "corpus": self.corpus_stats,
            "shim": True,
        }

    def scan(self, items: list[dict]) -> list[dict]:
        out = []
        for it in items:
            # Free OS text ("Ubuntu 22.04") is reduced to its family ("Linux") as the
            # estate reduction does for inventory rows (Section 6.1); passed raw, the
            # engine takes it for part of the product name ("zetadb ubuntu").
            # Unrecognised OS text is dropped there too, so no platform gate applies.
            os_text = it.get("operating_system") or None
            if os_text:
                os_text = os_family(os_text, None)
            try:
                with self._lock:  # the reference engine is single-threaded
                    r = self.scanner.check(
                        it.get("product") or "",
                        it.get("version") or "",
                        it.get("platform") or None,
                        vendor=it.get("vendor") or None,
                        operating_system=os_text,
                    )
                r = dict(r)
            except Exception as exc:  # per-item isolation, as in the compiled engine
                logger.exception("scan failed for %r", it)
                r = {"status": "NOT_FOUND", "threats": [], "uncertain_items": [],
                     "safe_reasons": [], "scanned_cves": 0, "safety_score": 0,
                     "scan_failed": str(exc)}
            r.setdefault("product", it.get("product"))
            r.setdefault("version", it.get("version"))
            _explain(r)
            r["model_version"] = self.model_version
            out.append(r)
        return out


def make_handler(engine: Engine):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            if self.path.split("?")[0] == "/health":
                return self._send(200, engine.health())
            return self._send(404, {"detail": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path.split("?")[0] != "/scan":
                return self._send(404, {"detail": "not found"})
            length = int(self.headers.get("Content-Length") or 0)
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
            except Exception as exc:
                return self._send(400, {"detail": f"bad request: {exc}"})
            try:
                items = ScanRequest.model_validate(payload).normalized_items()
            except ValidationError as exc:
                return self._send(422, {"detail": exc.errors(include_url=False, include_context=False)})
            if not items:
                return self._send(422, {"detail": "'items' list or 'product' + 'version' fields required"})
            return self._send(200, {"results": engine.scan([i.model_dump() for i in items])})

        def log_message(self, fmt, *args):  # quieter than the default
            logger.debug(fmt, *args)

    return Handler


def serve(addr: str, corpus: Path = DEFAULT_CORPUS, model: str | None = None) -> ThreadingHTTPServer:
    host, _, port = addr.rpartition(":")
    engine = Engine(corpus, model)
    server = ThreadingHTTPServer((host or "127.0.0.1", int(port)), make_handler(engine))
    logger.info("engine shim on http://%s:%d  model=%s engine=%s corpus=%s",
                server.server_address[0], server.server_address[1],
                engine.model_version, engine.engine_version, engine.corpus_stats)
    return server


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default="127.0.0.1:8390")
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--model", default=None, help="tagger checkpoint (.pth) or its directory; default: no neural layer")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s — %(message)s")
    server = serve(args.addr, Path(args.corpus), args.model)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
