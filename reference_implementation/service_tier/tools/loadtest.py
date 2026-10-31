"""
Job kuyruğu yük testi.

Sentetik bir envanter (kurgusal ürünler) üretir, `POST /scan`
ile kuyruğa atar ve iş bitene kadar ilerlemeyi izler. Ölçtükleri:

  - kuyruğa alma gecikmesi (istemci ne kadar bekliyor)
  - işleme hızı (kalem/sn) ve önbellek isabet oranı
  - hafıza ve API yanıt süresi, iş sürerken

Kullanım:
    python service_tier/tools/loadtest.py --items 500
    python service_tier/tools/loadtest.py --items 20000 --url https://service.example:8443 --insecure
"""
from __future__ import annotations

import argparse
import functools
import json
import random
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

# İlerleme uzun koşularda canlı görünsün (yönlendirilmiş çıktı tamponlanır).
print = functools.partial(print, flush=True)

# Kurgusal ürün adları (sentetik korpusla aynı evren) — temiz, kirli ve
# belirsiz ad biçimleri karışık.
PRODUCTS = [
    "Acme Ledgerly Server", "ACME LEDGERLY SERVER", "Northwind Mailflow Gateway",
    "Contoso Photolens Viewer", "Photolens Viewer", "Orbital Browser", "ZetaDB",
    "Tailspin Relaywire Client", "Hypothetical Unknown App", "Fabrikam Notepadder",
    "Wingtip Chartwise", "Litware Packetscope", "Proseware Archiver",
    "LEDGERLY.EXE x64 setup", "org.acme:ledgerly-server",
    "Orbital Browser 110.0 (x64 tr)", "Mailflow Gateway (64-bit)",
    "Calendar", "Notes", "Terminal",
]

VERSIONS = [
    "1.0", "1.2.3", "2.4.1", "3.0.19", "4.1", "5.6.20", "8.0.1", "9.0.1",
    "0.70", "16.0", "130.0", "120.0.0.0", "21.07", "2.20.0", "18.09.0",
]


def build_items(count: int, seed: int = 42) -> List[Dict[str, str]]:
    """Tekrarlı kalemler içeren bir envanter üretir.

    Envanterlerde aynı uygulama birçok uç noktada tekrar eder; önbellek
    kazancının ölçülebilmesi için burada da tekrar bırakılır.
    """
    rng = random.Random(seed)
    items = []
    for _ in range(count):
        item: Dict[str, str] = {
            "product": rng.choice(PRODUCTS),
            "version": rng.choice(VERSIONS),
        }
        if item["product"] in ("Calendar", "Notes", "Terminal") and rng.random() < 0.5:
            item["operating_system"] = rng.choice(["macOS", "Windows"])
        items.append(item)
    return items


def _request(url: str, payload: Any, headers: Dict[str, str], insecure: bool,
             method: str = "POST") -> Tuple[int, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = ssl._create_unverified_context() if insecure else None
    try:
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        return exc.code, (json.loads(body) if body else None)


def run(url: str, api_key: str, items: List[Dict[str, str]], insecure: bool) -> None:
    headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    print(f"  Kalem sayısı  : {len(items)}")
    print(f"  Tekil kalem   : {len({(i['product'], i['version']) for i in items})}")

    started = time.perf_counter()
    status, body = _request(f"{url}/scan", {"items": items}, headers, insecure)
    enqueue_ms = (time.perf_counter() - started) * 1000

    if status != 202:
        print(f"  ✗ Kuyruğa alınamadı: HTTP {status} — {body}")
        return

    job_id = body["job_id"]
    print(f"  Kuyruğa alma  : {enqueue_ms:.0f} ms  (job {job_id[:8]}…)")
    print()

    job_started = time.perf_counter()
    last_done, stall_checks = 0, 0

    while True:
        time.sleep(5)
        poll_started = time.perf_counter()
        status, job = _request(f"{url}/jobs/{job_id}", None, headers, insecure, method="GET")
        poll_ms = (time.perf_counter() - poll_started) * 1000
        if status != 200:
            print(f"  ✗ Durum sorgusu başarısız: HTTP {status}")
            return

        done = job["completed"] + job["failed"]
        elapsed = time.perf_counter() - job_started
        rate = done / elapsed if elapsed > 0 else 0
        remaining = (job["total"] - done) / rate if rate > 0 else float("inf")

        print(f"  {job['status']:8s} {done:6d}/{job['total']:<6d} "
              f"{rate:6.1f} kalem/sn  kalan ~{remaining/60:5.1f} dk  "
              f"(poll {poll_ms:.0f} ms, hata {job['failed']})")

        if job["status"] in ("DONE", "FAILED"):
            break
        # İlerleme durduysa erken çık — sonsuza kadar bekleme.
        stall_checks = stall_checks + 1 if done == last_done else 0
        if stall_checks >= 12:
            print("  ✗ 60 saniyedir ilerleme yok, izleme durduruldu")
            return
        last_done = done

    total = time.perf_counter() - job_started
    print()
    print(f"  Toplam süre   : {total:.1f} sn  ({job['total']/total:.1f} kalem/sn)")

    status, result = _request(f"{url}/jobs/{job_id}/result", None, headers, insecure, method="GET")
    if status == 200:
        rows = result["items"]
        cached = sum(1 for r in rows if r.get("cached"))
        by_status: Dict[str, int] = {}
        for r in rows:
            by_status[r.get("status") or "ERROR"] = by_status.get(r.get("status") or "ERROR", 0) + 1
        print(f"  Önbellekten   : {cached}/{len(rows)}  (%{100*cached/max(1,len(rows)):.1f})")
        print(f"  Sonuç dağılımı: {by_status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Job kuyruğu yük testi")
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--items", type=int, default=500)
    parser.add_argument("--insecure", action="store_true", help="TLS doğrulamasını atla")
    args = parser.parse_args()

    key = args.api_key
    if not key:
        import os
        import pathlib

        env = pathlib.Path(__file__).resolve().parents[1] / ".env"
        if env.is_file():
            for line in env.read_text().splitlines():
                if line.startswith("API_KEYS="):
                    key = line.split("=", 1)[1].split(",")[0].strip()
        key = key or os.environ.get("API_KEYS", "").split(",")[0]

    run(args.url.rstrip("/"), key, build_items(args.items), args.insecure)


if __name__ == "__main__":
    main()
