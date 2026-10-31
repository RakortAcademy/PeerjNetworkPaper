#!/usr/bin/env python3
"""Scan the package for material that must not reach an external reader:
credentials and private keys, private/internal network addresses, absolute
paths of the authors' machines, references to internal repositories or
services, and binary/office files that should not be in a public tree.

    python reproducibility/scan_sensitive.py [--root DIR] [--extra-pattern REGEX ...]

Names of a maintainer's own internal hosts or repositories are not written into
this public file; pass them with ``--extra-pattern`` (repeatable).

Exit code 1 if any finding is reported. The patterns are deliberately broad;
every hit is printed with file, line and the matched text, so a reviewer can
judge false positives (e.g. a version string that looks like an IP address).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PATTERNS = {
    "private key": re.compile("BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE " + "KEY"),
    "credential assignment": re.compile(
        r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    "env file with values": re.compile(r"(?i)^(PGPASSWORD|ADMIN_TOKEN|API_KEYS|NVD_API_KEY)=\S+"),
    "private IPv4": re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    # (patterns are assembled from fragments so this file does not itself contain the strings)
    "absolute home/root path": re.compile("(/" + "root/|/" + "home/[A-Za-z0-9_.-]+/|/" + "Users/[A-Za-z0-9_.-]+/|[A-Za-z]:\\\\" + "Users\\\\)"),
    "internal hostname": re.compile(r"(?i)(\.local\b|\.lan\b|\.internal\b)"),
    "email address": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
}
# Public identifiers that are part of the manuscript / citation metadata.
ALLOW = {
    "email address": {"ramazan.kocaoglu@ostimteknik.edu.tr", "noreply@anthropic.com"},
}
# Version strings and XML namespaces that look like private IPs or paths.
ALLOW_LINE = re.compile(r"(version|v\d|release|build|xmlns|schemaLocation|cpe:2\.3|CVE-|prior to|before|through|up to|earlier|fixed in|affected)", re.I)
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", "out", "figures",
             "tiny_model",  # tiny_model: git-ignored output of the reviewer example (holds a checkpoint by design)
             ".venv", "venv"}  # git-ignored virtual environments (third-party packages, not part of the package)
TEXT_EXT = {".py", ".go", ".md", ".txt", ".tex", ".bib", ".cff", ".json", ".jsonl", ".csv", ".yml",
            ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sql", ".sh", ".env", ".example", ".xml", ".mod", ".sum", ".cls", ".bbl"}
BINARY_FLAG = {".pth", ".pt", ".onnx", ".ckpt", ".safetensors", ".xlsx", ".xls", ".docx", ".doc", ".db",
               ".sqlite", ".sqlite3", ".dump", ".pem", ".key", ".p12", ".pfx"}


def scan(root: Path) -> list[tuple[str, str, int, str]]:
    findings = []
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_dir():
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix.lower() in BINARY_FLAG:
            findings.append(("binary/office/weight file", rel, 0, path.name))
            continue
        if path.suffix.lower() not in TEXT_EXT and path.name not in (".gitignore", "LICENSE", "NOTICE", "CITATION.cff"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for label, rx in PATTERNS.items():
                if label == "env file with values" and path.name.endswith(".example"):
                    continue  # documented placeholders (change-me, local-*), never real values
                for m in rx.finditer(line):
                    hit = m.group(0)
                    if hit in ALLOW.get(label, set()):
                        continue
                    if label == "private IPv4" and ALLOW_LINE.search(line):
                        continue
                    if label == "credential assignment" and re.search(r"(?i)(example|placeholder|test|fake|dummy|change-me|<)", line):
                        continue
                    findings.append((label, rel, lineno, hit if len(hit) < 60 else hit[:57] + "..."))
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--extra-pattern", action="append", default=[], metavar="REGEX",
                    help="additional pattern to report (e.g. an internal repository name); repeatable")
    args = ap.parse_args()
    for i, rx in enumerate(args.extra_pattern, 1):
        PATTERNS[f"extra pattern {i}"] = re.compile(rx)
    root = Path(args.root).resolve()
    findings = scan(root)
    # The scanner's own pattern table matches itself; exclude it.
    findings = [f for f in findings if f[1] != "reproducibility/scan_sensitive.py"]
    for label, rel, lineno, hit in findings:
        print(f"{label:28s} {rel}:{lineno}: {hit}")
    print(f"\n{len(findings)} finding(s) in {root}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
