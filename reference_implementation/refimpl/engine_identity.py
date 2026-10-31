"""Model identifier used as part of the cache keys (manuscript Section 7).

Production computed two digests: one over the model weights' *bytes* (not their
path) and one over the compiled decision binary. This module reproduces the
first exactly as the service tier did when the engine was unavailable
(`service_tier/backend/services/scanner.py::model_version`): SHA-256 of the checkpoint file,
first 16 hex characters; `"none"` when no checkpoint is loaded.

The second digest (the running engine binary) is produced by the compiled
engine itself — see `compiled_engine/goscan/main.go::binaryVersion` — and has no
Python counterpart here.
"""
from __future__ import annotations

import hashlib
import threading
from pathlib import Path
from typing import Optional

_model_path: Optional[Path] = None
_model_version: Optional[str] = None
_lock = threading.Lock()


def checkpoint_digest(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def register_checkpoint(path) -> None:
    """Called by the extractor once it knows which checkpoint file it loaded."""
    global _model_path, _model_version
    with _lock:
        _model_path = Path(path) if path else None
        _model_version = None


def model_version() -> str:
    global _model_version
    if _model_version is not None:
        return _model_version
    with _lock:
        if _model_version is not None:
            return _model_version
        if _model_path is None or not _model_path.is_file():
            _model_version = "none"
        else:
            _model_version = checkpoint_digest(_model_path)
        return _model_version


def reset() -> None:
    global _model_path, _model_version
    with _lock:
        _model_path, _model_version = None, None
