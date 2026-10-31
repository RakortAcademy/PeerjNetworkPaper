"""Host-side CRF decoding and ONNX inference path — Python mirror of the compiled
engine's `model.go` (manuscript Section 9, "The Model Runs Faster Without the
Accelerator" and "Decoding equivalence").

The production path exports the network up to the emission layer as ONNX and
re-implements the conditional-random-field decoder (Viterbi) in the host
language (Go), because `torchcrf.decode()` contains a data-dependent loop that
does not export cleanly. This module is a line-by-line port of the Go code so a
reviewer can inspect and exercise the decoder without a Go toolchain:

* `encode_batch`   — token/char tensor construction (`model.go::runChunk`)
* `viterbi`        — the decoder (`model.go::viterbi`): start transitions on the
                     first step, end transitions on the last, first-index tie-break
* `decode_labels`  — label sequence → product / version spans (`model.go::decodeLabels`)
* `OnnxExtractor`  — runs `emissions.onnx` with onnxruntime on CPU and decodes;
                     same chunk size (256) and the same input discipline as Go.

`refimpl.export.export_onnx` checks that this decoder and `torchcrf` produce
identical label sequences on the same emissions.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

CHUNK = 256  # model.go: "const chunk = 256"


def load_export(model_dir) -> Dict[str, object]:
    d = Path(model_dir)
    meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
    crf = json.loads((d / "crf.json").read_text(encoding="utf-8"))
    token2idx = json.loads((d / "token2idx.json").read_text(encoding="utf-8"))
    char2idx = json.loads((d / "char2idx.json").read_text(encoding="utf-8"))
    idx2label = [""] * int(meta["tagset_size"])
    for name, i in meta["label2idx"].items():
        if 0 <= i < len(idx2label):
            idx2label[i] = name
    return {
        "onnx_path": d / "emissions.onnx",
        "max_len": int(meta.get("max_len") or 200),
        "max_word_len": int(meta.get("max_word_len") or 20),
        "tagset": int(meta["tagset_size"]),
        "idx2label": idx2label,
        "token2idx": token2idx,
        "char2idx": char2idx,
        "start": np.asarray(crf["start"], dtype=np.float32),
        "end": np.asarray(crf["end"], dtype=np.float32),
        "transitions": np.asarray(crf["transitions"], dtype=np.float32),
        "model_version": meta.get("model_version", ""),
    }


def encode_batch(tokenized: Sequence[Sequence[str]], token2idx: Dict[str, int],
                 char2idx: Dict[str, int], max_len: int, max_word_len: int
                 ) -> Tuple[np.ndarray, np.ndarray, List[int]]:
    """model.go::runChunk — words zero-padded, chars PAD-filled, lower-cased word
    lookup, raw-case character lookup, post-truncation at max_len / max_word_len."""
    b, L, W = len(tokenized), max_len, max_word_len
    unk_tok = token2idx["UNK"]
    unk_chr = char2idx["UNK"]
    pad_chr = char2idx["PAD"]
    words = np.zeros((b, L), dtype=np.int64)
    chars = np.full((b, L, W), pad_chr, dtype=np.int64)
    lengths = [0] * b
    for r, toks in enumerate(tokenized):
        n = min(len(toks), L)
        lengths[r] = n
        for c in range(n):
            words[r, c] = token2idx.get(toks[c].lower(), unk_tok)
            for k, ch in enumerate(toks[c]):
                if k >= W:
                    break
                chars[r, c, k] = char2idx.get(ch, unk_chr)
    return words, chars, lengths


def viterbi(emissions: np.ndarray, start: np.ndarray, end: np.ndarray,
            trans: np.ndarray) -> List[int]:
    """model.go::viterbi — `emissions` is (n, T) for the n real tokens of one text.

    Identical to torchcrf's `_viterbi_decode`: start transitions are added at the
    first step, end transitions at the last; masked (padding) steps are simply
    not present. Ties resolve to the lowest index (`s > best`).
    """
    n, T = emissions.shape
    score = [float(start[t]) + float(emissions[0, t]) for t in range(T)]
    backptr: List[List[int]] = [[0] * T for _ in range(n)]
    for i in range(1, n):
        nxt = [0.0] * T
        back = [0] * T
        for cur in range(T):
            best = -math.inf
            best_prev = 0
            for prev in range(T):
                s = score[prev] + float(trans[prev, cur])
                if s > best:
                    best, best_prev = s, prev
            nxt[cur] = best + float(emissions[i, cur])
            back[cur] = best_prev
        backptr[i] = back
        score = nxt
    best_last, best_score = 0, -math.inf
    for t in range(T):
        s = score[t] + float(end[t])
        if s > best_score:
            best_score, best_last = s, t
    tags = [0] * n
    tags[n - 1] = best_last
    for i in range(n - 1, 0, -1):
        tags[i - 1] = backptr[i][tags[i]]
    return tags


def decode_labels(tokens: Sequence[str], tags: Sequence[int], idx2label: Sequence[str]) -> Dict[str, object]:
    """model.go::decodeLabels — collect B-/I-PRODUCT and B-/I-VERSION tokens."""
    product, version, labels = [], [], []
    for i, tag in enumerate(tags):
        if i >= len(tokens):
            break
        label = "O"
        if 0 <= tag < len(idx2label) and idx2label[tag]:
            label = idx2label[tag]
        labels.append(label)
        if label in ("B-PRODUCT", "I-PRODUCT"):
            product.append(tokens[i])
        elif label in ("B-VERSION", "I-VERSION"):
            version.append(tokens[i])
    return {
        "product": " ".join(product) if product else None,
        "version": " ".join(version) if version else None,
        "tokens": list(tokens),
        "labels": labels,
    }


class OnnxExtractor:
    """CPU inference over the exported emissions graph + host-side Viterbi."""

    def __init__(self, model_dir, intra_op_threads: int = 4) -> None:
        import onnxruntime as ort  # local import: optional dependency

        self.cfg = load_export(model_dir)
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = intra_op_threads  # model.go: SetIntraOpNumThreads(4)
        # The GPU provider is deliberately NOT requested (model.go: 8.8M parameters,
        # at this model size kernel-launch overhead dominates on a GPU).
        self.session = ort.InferenceSession(str(self.cfg["onnx_path"]), opts,
                                            providers=["CPUExecutionProvider"])

    def emissions(self, words: np.ndarray, chars: np.ndarray) -> np.ndarray:
        return self.session.run(["emissions"], {"words": words, "chars": chars})[0]

    def extract_batch(self, texts: Sequence[str]) -> List[Dict[str, object]]:
        """model.go::ExtractBatch — empty texts never enter the model; chunks of 256."""
        empty = {"product": None, "version": None, "tokens": [], "labels": []}
        out: List[Dict[str, object]] = [dict(empty) for _ in texts]
        tokenized = [t.split() for t in texts]  # strings.Fields ≡ str.split()
        usable = [i for i, toks in enumerate(tokenized) if toks]
        cfg = self.cfg
        for from_ in range(0, len(usable), CHUNK):
            slots = usable[from_:from_ + CHUNK]
            words, chars, lengths = encode_batch(
                [tokenized[i] for i in slots], cfg["token2idx"], cfg["char2idx"],
                cfg["max_len"], cfg["max_word_len"])
            em = self.emissions(words, chars)
            for r, slot in enumerate(slots):
                n = lengths[r]
                if n == 0:
                    continue
                tags = viterbi(em[r, :n, :], cfg["start"], cfg["end"], cfg["transitions"])
                out[slot] = decode_labels(tokenized[slot], tags, cfg["idx2label"])
        return out
