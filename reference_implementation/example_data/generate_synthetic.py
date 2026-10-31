"""Generate the synthetic example data of this package.

EVERYTHING produced here is synthetic: fictional products ("Acme Ledgerly Server",
"Northwind Mailflow Gateway", ...), fictional advisory identifiers (CVE-2099-xxxx),
fictional version numbers and fictional endpoint ids. The data exists only so a
reviewer can execute and inspect the code. It is not experimental data, not a
benchmark, and reproduces no number in the manuscript.

Outputs (all in this directory):
  synthetic_corpus.jsonl        advisory corpus (12 advisories) for refimpl.corpus
  synthetic_inventory_rows.json per-endpoint installed-application rows (the exporter input)
  synthetic_training.jsonl      labelled sentences for training a tiny tagger
  synthetic_verify_texts.txt    descriptions for the ONNX decode-equivalence check
  synthetic_golden.jsonl        golden-set cases for the metric code
Deterministic (fixed seed); re-running overwrites identical files.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent
rng = random.Random(20990101)

# --------------------------------------------------------------------------- corpus
CORPUS = [
    # 1. structured bounds, single range: THREAT for 2.3.x, SAFE for 2.4.1+
    {"cve_id": "CVE-2099-0001",
     "description": "Acme Ledgerly Server before 2.4.1 allows remote attackers to execute arbitrary code via a crafted request.",
     "published_at": "2099-01-10", "cvss_score": 9.8, "cvss_severity": "CRITICAL",
     "affected": [{"product": "Ledgerly Server", "vendor": "Acme", "version": "", "less_than": "2.4.1",
                   "less_than_or_equal": "", "greater_equal": "2.0.0", "default_status": "unaffected"}],
     "risk": {"kev": True, "epss": 0.42, "cvss": 9.8, "kev_due_date": "2099-02-01"}},
    # 2. multi-branch ranges (two maintenance lines): 3.1.4 THREAT, 3.1.7 SAFE, 2.8.0 SAFE (range lower bound)
    {"cve_id": "CVE-2099-0002",
     "description": "An injection flaw in Acme Ledgerly Server versions 3.0.0 through 3.1.6 and 2.9.0 through 2.9.3 lets authenticated users read files.",
     "published_at": "2099-02-02", "cvss_score": 6.5, "cvss_severity": "MEDIUM",
     "affected": [
         {"product": "Ledgerly Server", "vendor": "Acme", "version": "", "less_than": "3.1.7",
          "less_than_or_equal": "", "greater_equal": "3.0.0", "default_status": "unaffected"},
         {"product": "Ledgerly Server", "vendor": "Acme", "version": "", "less_than": "2.9.4",
          "less_than_or_equal": "", "greater_equal": "2.9.0", "default_status": "unaffected"}],
     "risk": {"kev": False, "epss": 0.015, "cvss": 6.5}},
    # 3. text-only: NO structural bounds → constraint recovered from prose (tagger + regex operators)
    {"cve_id": "CVE-2099-0003",
     "description": "Northwind Mailflow Gateway prior to 5.2.0 mishandles attachment names, allowing a denial of service.",
     "published_at": "2099-03-03", "cvss_score": 5.3, "cvss_severity": "MEDIUM",
     "affected": [{"product": "Mailflow Gateway", "vendor": "Northwind", "version": "", "less_than": "",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": ""}]},
    # 4. text-only with "and earlier" (inclusive upper bound)
    {"cve_id": "CVE-2099-0004",
     "description": "Northwind Mailflow Gateway 5.4.2 and earlier contains an authentication bypass in the admin console.",
     "published_at": "2099-03-20", "cvss_score": 8.1, "cvss_severity": "HIGH",
     "affected": [{"product": "Mailflow Gateway", "vendor": "Northwind", "version": "", "less_than": "",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": ""}],
     "risk": {"kev": False, "epss": 0.12, "cvss": 8.1}},
    # 5. exact-version list (no bounds, default_status unaffected): 1.2.3 THREAT, 1.2.4 SAFE (neq)
    {"cve_id": "CVE-2099-0005",
     "description": "Contoso Photolens Viewer 1.2.3 and 1.2.2 are affected by a heap overflow when opening TIFF images.",
     "published_at": "2099-04-04", "cvss_score": 7.8, "cvss_severity": "HIGH",
     "affected": [
         {"product": "Photolens Viewer", "vendor": "Contoso", "version": "1.2.3", "less_than": "",
          "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"},
         {"product": "Photolens Viewer", "vendor": "Contoso", "version": "1.2.2", "less_than": "",
          "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"}]},
    # 6. OS gate: Android-specific advisory for the same browser → not applicable on Windows
    {"cve_id": "CVE-2099-0006",
     "description": "Orbital Browser on Android before 110.0.2 allowed a remote attacker to spoof the address bar.",
     "published_at": "2099-05-05", "cvss_score": 4.3, "cvss_severity": "MEDIUM",
     "affected": [{"product": "Orbital Browser", "vendor": "Stellar Software", "version": "", "less_than": "110.0.2",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"}]},
    # 7. same browser, platform-independent → THREAT for 109.x
    {"cve_id": "CVE-2099-0007",
     "description": "Use after free in Orbital Browser prior to 110.0.5 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page.",
     "published_at": "2099-05-06", "cvss_score": 8.8, "cvss_severity": "HIGH",
     "affected": [{"product": "Orbital Browser", "vendor": "Stellar Software", "version": "", "less_than": "110.0.5",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"}],
     "risk": {"kev": False, "epss": 0.03, "cvss": 8.8}},
    # 8. web/CMS plugin gate: a plugin that shares a name with the desktop app
    {"cve_id": "CVE-2099-0008",
     "description": "The Photolens Viewer Gallery plugin for WordPress before 3.3.0 is vulnerable to stored cross-site scripting. This issue affects Photolens Viewer Gallery: from n/a through 3.2.9.",
     "published_at": "2099-06-06", "cvss_score": 6.1, "cvss_severity": "MEDIUM",
     "affected": [{"product": "Photolens Viewer Gallery", "vendor": "wpdeveloper", "version": "", "less_than": "3.3.0",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"}]},
    # 9. vendor gate: same product name, different vendor
    {"cve_id": "CVE-2099-0009",
     "description": "Fabrikam Ledgerly Server 2.1 allows directory traversal in the file upload component.",
     "published_at": "2099-07-07", "cvss_score": 7.5, "cvss_severity": "HIGH",
     "affected": [{"product": "Ledgerly Server", "vendor": "Fabrikam", "version": "2.1", "less_than": "",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": "unaffected"}]},
    # 10. kernel-style corrupt bound (git commit hash) → cleaned out, decision falls to text (none) → uncertain/ignored
    {"cve_id": "CVE-2099-0010",
     "description": "In the ZetaDB storage engine, a race condition in the page cache was fixed in commit 3c68d44a2b49.",
     "published_at": "2099-08-08", "cvss_score": 5.5, "cvss_severity": "MEDIUM",
     "affected": [{"product": "ZetaDB", "vendor": "Zeta Labs", "version": "", "less_than": "3c68d44a2b49a0ac9165faa9c191e1e618c8a8d5",
                   "less_than_or_equal": "", "greater_equal": "9f2c1e7d4b5a6c8e0f1a2b3c4d5e6f7a8b9c0d1e", "default_status": ""}]},
    # 11. NVD CPE applicability row only (CNA row without bounds): 4.0.3 THREAT via nvd-cpe
    {"cve_id": "CVE-2099-0011",
     "description": "ZetaDB allows SQL injection through the import wizard.",
     "published_at": "2099-09-09", "cvss_score": 9.1, "cvss_severity": "CRITICAL",
     "affected": [{"product": "ZetaDB", "vendor": "Zeta Labs", "version": "", "less_than": "",
                   "less_than_or_equal": "", "greater_equal": "", "default_status": ""}],
     "cpe": [{"product": "ZetaDB", "vendor": "zeta_labs", "version": "", "less_than": "4.0.5",
              "less_than_or_equal": "", "greater_equal": "4.0.0", "greater_than": ""}]},
    # 12. inclusive upper bound with build-number inventory version (is_build_of): 5.2.8.3141 <= 5.2.8 → THREAT
    {"cve_id": "CVE-2099-0012",
     "description": "An improper certificate validation in Tailspin Relaywire Client 5.2.8 and below allows a man-in-the-middle attacker to intercept traffic.",
     "published_at": "2099-10-10", "cvss_score": 7.4, "cvss_severity": "HIGH",
     "affected": [{"product": "Relaywire Client", "vendor": "Tailspin", "version": "", "less_than": "",
                   "less_than_or_equal": "5.2.8", "greater_equal": "5.2.0", "default_status": "unaffected"}]},
]

# ------------------------------------------------------------------- inventory rows
# (endpoint_id, name, version, vendor, architecture, os_text, os_type) — the shape the
# exporter's SQL returned. Duplicates across endpoints are deliberate (fan-back).
INVENTORY_ROWS = []
def add(ep, name, ver, vendor, arch, os_text, os_type=None):
    INVENTORY_ROWS.append([ep, name, ver, vendor, arch, os_text, os_type])

for ep in range(1001, 1007):            # six Windows endpoints with the same browser build
    add(ep, "Orbital Browser", "109.0.1", "Stellar Software", "x64", "Microsoft Windows 11 Pro")
add(1001, "Orbital Browser", "109.0.1", "", "x64", "Microsoft Windows 11 Pro")  # vendor sometimes blank → adopted
add(1007, "Orbital Browser", "110.0.6", "Stellar Software", "x64", "Microsoft Windows 11 Pro")
add(1001, "Acme Ledgerly Server", "2.3.9", "Acme", "x64", "Windows Server 2022")
add(1002, "Acme Ledgerly Server", "2.3.9", "Acme", "x64", "Windows Server 2022")
add(1003, "Acme Ledgerly Server", "3.1.4", "Acme", "x64", "Ubuntu 22.04")
add(1004, "ACME LEDGERLY SERVER", "2.4.1", "Acme", "x64", "Ubuntu 22.04")   # case differs → same item
add(1005, "Northwind Mailflow Gateway", "5.1.0", "Northwind", "x64", "Debian 12")
add(1006, "Northwind Mailflow Gateway", "5.4.2", "Northwind", "x64", "Debian 12")
add(1007, "Northwind Mailflow Gateway", "5.5.0", "Northwind", "x64", "Debian 12")
add(1002, "Contoso Photolens Viewer", "1.2.3", "Contoso", "x64", "Microsoft Windows 11 Pro")
add(1003, "Contoso Photolens Viewer", "1.2.4", "Contoso", "x64", "Microsoft Windows 11 Pro")
add(1004, "Photolens Viewer", "1.2.3", "Contoso", "x64", "macOS 15.1")        # OS family in the merge key
add(1005, "ZetaDB", "4.0.3", "Zeta Labs", "x64", "Ubuntu 22.04")
add(1006, "Tailspin Relaywire Client", "5.2.8.3141", "Tailspin", "x64", "Microsoft Windows 11 Pro")
add(1007, "Notes", "4.13", "", "arm64", "macOS 15.1", 3)                   # generic name, no vendor → UNCERTAIN
add(1001, "Security Update for Windows (KB5099999)", "1.0", "Microsoft", "x64", "Microsoft Windows 11 Pro")  # update package
add(1002, "Hypothetical Unknown App", "1.0.0", "Nobody", "x64", "Microsoft Windows 11 Pro")  # NOT_FOUND
add(1003, "Northwind Mailflow Gateway", "", "Northwind", "x64", "Debian 12")   # versionless → dropped by the exporter
add(1004, "", "1.0", "", "", "Microsoft Windows 11 Pro")                   # nameless → dropped

# ------------------------------------------------------------------ training data
PRODUCTS = ["Acme Ledgerly Server", "Northwind Mailflow Gateway", "Contoso Photolens Viewer", "Orbital Browser",
            "ZetaDB", "Tailspin Relaywire Client", "Fabrikam Ledgerly Server", "Lumen Office Suite",
            "Quartz Media Player", "Pioneer Backup Agent", "Helix Chat Client", "Vortex PDF Reader"]
TEMPLATES = [
    "{p} before {v} allows remote attackers to execute arbitrary code via a crafted request.",
    "{p} prior to {v} mishandles input, allowing a denial of service.",
    "A buffer overflow in {p} {v} allows attackers to gain privileges.",
    "{p} versions {v} and earlier contain an authentication bypass.",
    "An issue was discovered in {p} through {v} where sessions are not invalidated.",
    "Use after free in {p} prior to {v} allowed a remote attacker to exploit heap corruption.",
    "{p} {v} and below is vulnerable to cross-site scripting in the settings page.",
    "Improper certificate validation in {p} before {v} allows a man-in-the-middle attack.",
    "The update mechanism of {p} {v} does not verify signatures.",
    "{p} up to {v} stores credentials in plain text.",
]
def rand_version():
    k = rng.choice([2, 3, 3, 3, 4])
    return ".".join(str(rng.randint(0, 20)) for _ in range(k))

TRAIN = []
for i in range(600):
    p = rng.choice(PRODUCTS)
    v = rand_version()
    TRAIN.append({"cve_id": f"CVE-2098-{i:04d}", "text": rng.choice(TEMPLATES).format(p=p, v=v),
                  "product": p, "version": v})

VERIFY = [rec["text"] for rec in TRAIN[:120]] + [c["description"] for c in CORPUS]

# ---------------------------------------------------------------------- golden set
GOLDEN = [
    {"product": "Acme Ledgerly Server", "version": "2.3.9", "vendor": "Acme", "expected_status": "THREAT",
     "accept_statuses": ["THREAT"], "expected_cve_ids": ["CVE-2099-0001"], "category": "evidence-threat",
     "evidence": "synthetic: [2.0.0, 2.4.1) covers 2.3.9"},
    {"product": "Acme Ledgerly Server", "version": "2.4.1", "vendor": "Acme", "expected_status": "SAFE",
     "accept_statuses": ["SAFE", "UNCERTAIN"], "forbidden_cve_ids": ["CVE-2099-0001"], "category": "patched-version",
     "evidence": "synthetic: 2.4.1 is the fixed version"},
    {"product": "Acme Ledgerly Server", "version": "3.1.4", "vendor": "Acme", "expected_status": "THREAT",
     "accept_statuses": ["THREAT"], "expected_cve_ids": ["CVE-2099-0002"], "category": "multi-branch"},
    {"product": "Orbital Browser", "version": "109.0.1", "vendor": "Stellar Software", "operating_system": "Windows",
     "expected_status": "THREAT", "accept_statuses": ["THREAT"], "expected_cve_ids": ["CVE-2099-0007"],
     "forbidden_cve_ids": ["CVE-2099-0006"], "category": "os-gate",
     "evidence": "synthetic: the Android-only advisory must not be a threat on Windows"},
    {"product": "Contoso Photolens Viewer", "version": "1.2.4", "vendor": "Contoso", "expected_status": "SAFE",
     "accept_statuses": ["SAFE", "NOT_FOUND"], "forbidden_cve_ids": ["CVE-2099-0005", "CVE-2099-0008"],
     "category": "exact-list / plugin-gate"},
    {"product": "Tailspin Relaywire Client", "version": "5.2.8.3141", "vendor": "Tailspin", "expected_status": "THREAT",
     "accept_statuses": ["THREAT"], "expected_cve_ids": ["CVE-2099-0012"], "category": "build-number"},
    {"product": "Notes", "version": "4.13", "expected_status": "UNCERTAIN", "accept_statuses": ["UNCERTAIN"],
     "category": "generic-name"},
    {"product": "Nonexistent Product XYZ", "version": "1.0", "expected_status": "NOT_FOUND",
     "accept_statuses": ["NOT_FOUND", "UNCERTAIN"], "category": "negative-control"},
]


def write_jsonl(path: Path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    write_jsonl(HERE / "synthetic_corpus.jsonl", CORPUS)
    (HERE / "synthetic_inventory_rows.json").write_text(
        json.dumps({"_note": "SYNTHETIC per-endpoint rows: [endpoint_id, name, version, vendor, architecture, os_text, os_type]",
                    "rows": INVENTORY_ROWS}, indent=1), encoding="utf-8")
    write_jsonl(HERE / "synthetic_training.jsonl", TRAIN)
    (HERE / "synthetic_verify_texts.txt").write_text("\n".join(VERIFY) + "\n", encoding="utf-8")
    write_jsonl(HERE / "synthetic_golden.jsonl", GOLDEN)
    print("written:", len(CORPUS), "advisories,", len(INVENTORY_ROWS), "inventory rows,",
          len(TRAIN), "training records,", len(VERIFY), "verify texts,", len(GOLDEN), "golden cases")
