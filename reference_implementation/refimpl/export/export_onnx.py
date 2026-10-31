"""BiLSTM-CRF modelini ONNX'e aktarır — CRF HARİÇ.

Neden CRF hariç: `torchcrf.decode()` veriye bağlı döngü içerir ve ONNX'e temiz
çıkmaz. Ama gerek de yok — CRF yalnızca üç küçük tensör (start/end geçişleri ve
6x6 geçiş matrisi) ve Viterbi çözümlemesi 40 satırlık deterministik bir
algoritma. Ağ emisyonlara kadar ONNX'e çıkar, Viterbi çağıranda yazılır.

Production measurement (recorded in the original script): on 300 real advisory
descriptions PyTorch-CUDA and ONNX-CPU produced identical label sequences, and
ONNX on the CPU was faster than PyTorch on the GPU (small model: kernel-launch
overhead dominates). That measurement is NOT reproduced here; the
original checkpoint is not part of this package.

Reference-implementation changes to the original export script:
  * the checkpoint is given with --checkpoint (production loaded the serving model);
  * verification texts come from a file (--verify-texts, one description per
    line or JSONL with "description"), not from the corpus database;
  * the verification additionally runs the pure-Python port of the Go Viterbi
    decoder (`refimpl.export.crf_decode.viterbi`) on the same emissions and
    reports whether it matches `torchcrf.decode()` label-for-label — the
    "decoding equivalence" check of the manuscript, made runnable without Go.

Kullanım:
    python -m refimpl.export.export_onnx --checkpoint tiny_model/bilstm_crf.pth --out tiny_model/onnx \
        --verify-texts example_data/synthetic_verify_texts.txt
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Modeli ONNX + CRF matrisleri olarak dışa aktar")
    ap.add_argument("--checkpoint", required=True, help=".pth dosyası ya da onu içeren dizin")
    ap.add_argument("--out", required=True, help="çıktı dizini")
    ap.add_argument("--verify-texts", default="",
                    help="çözümleme eşitliği sınaması için metin dosyası (boş = atla)")
    ap.add_argument("--verify", type=int, default=200, help="en çok kaç metin sınansın")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    import numpy as np
    import torch
    from torch import nn

    from refimpl.engine_identity import checkpoint_digest
    from refimpl.extraction.architecture import load_checkpoint

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    net, token2idx, char2idx, label2idx, cfg = load_checkpoint(args.checkpoint, device=torch.device("cpu"))
    net = net.eval()
    device = next(net.parameters()).device
    max_len = cfg.get("max_len", 200)
    max_word = cfg.get("max_word_length", cfg.get("max_word_len", 20))

    class Emissions(nn.Module):
        """Ağın CRF'ye kadar olan kısmı."""

        def __init__(self, base):
            super().__init__()
            self.b = base

        def forward(self, words, chars):
            we = self.b.word_embedding(words)
            flat = chars.reshape(-1, chars.shape[-1])
            cr = self.b.char_embed_layer(flat).reshape(words.size(0), words.size(1), -1)
            lstm_out, _ = self.b.lstm(torch.cat([we, cr], dim=-1))
            return self.b.hidden2tag(lstm_out)

    wrapper = Emissions(net).eval()
    onnx_path = out_dir / "emissions.onnx"
    words = torch.randint(1, max(2, min(5000, len(token2idx))), (1, max_len), device=device)
    chars = torch.randint(1, max(2, min(60, len(char2idx))), (1, max_len, max_word), device=device)
    # Reference implementation seam: torch >= 2.9 defaults `torch.onnx.export` to the
    # dynamo-based exporter (which needs the separate `onnxscript` package); the
    # original ran under torch 2.5 with the TorchScript exporter. Request it
    # explicitly where the keyword exists so the exported graph is the same.
    export_kwargs = {}
    try:
        import inspect

        if "dynamo" in inspect.signature(torch.onnx.export).parameters:
            export_kwargs["dynamo"] = False
    except (TypeError, ValueError):  # pragma: no cover - signature not introspectable
        pass
    with torch.no_grad():
        torch.onnx.export(
            wrapper, (words, chars), str(onnx_path),
            input_names=["words", "chars"], output_names=["emissions"],
            # Yalnızca yığın boyutu değişken: dizi uzunluğunu da değişken
            # bırakmak LSTM'de ONNX uyarısı üretiyor ve sabit `max_len` zaten
            # doldurma (padding) ile garanti.
            dynamic_axes={"words": {0: "b"}, "chars": {0: "b"}, "emissions": {0: "b"}},
            opset_version=17, do_constant_folding=True, **export_kwargs,
        )
    logger.info("ONNX yazıldı: %s (%.1f MB)", onnx_path, onnx_path.stat().st_size / 1e6)

    crf = net.crf
    np.savez(
        out_dir / "crf.npz",
        start=crf.start_transitions.detach().cpu().numpy(),
        end=crf.end_transitions.detach().cpu().numpy(),
        transitions=crf.transitions.detach().cpu().numpy(),
    )
    (out_dir / "crf.json").write_text(json.dumps({
        "start": crf.start_transitions.detach().cpu().numpy().tolist(),
        "end": crf.end_transitions.detach().cpu().numpy().tolist(),
        "transitions": crf.transitions.detach().cpu().numpy().tolist(),
    }), encoding="utf-8")
    logger.info("CRF geçiş matrisleri yazıldı: %s (+ crf.json)", out_dir / "crf.npz")

    ckpt_file = Path(args.checkpoint)
    if ckpt_file.is_dir():
        ckpt_file = ckpt_file / "bilstm_crf.pth"
    meta = {
        "max_len": max_len,
        "max_word_len": max_word,
        "tagset_size": net.hidden2tag.out_features,
        "label2idx": label2idx,
        # Model damgası: checkpoint içeriğinin SHA-256'sı (ilk 16 hex), servis
        # tarafının önbellek anahtarında kullandığı değerle aynı.
        "model_version": checkpoint_digest(ckpt_file),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    (out_dir / "token2idx.json").write_text(json.dumps(token2idx), encoding="utf-8")
    (out_dir / "char2idx.json").write_text(json.dumps(char2idx), encoding="utf-8")
    logger.info("Sözlükler yazıldı (%d kelime, %d karakter)", len(token2idx), len(char2idx))

    if args.verify_texts:
        texts = _read_texts(args.verify_texts, args.verify)
        rep = verify(str(onnx_path), out_dir, net, token2idx, char2idx, max_len, max_word, texts)
        return 0 if rep["sentences_differing"] == 0 and rep["viterbi_port_differing"] == 0 else 1
    return 0


def _read_texts(path: str, limit: int):
    texts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    line = json.loads(line).get("description") or ""
                except json.JSONDecodeError:
                    continue
            if line:
                texts.append(line)
            if len(texts) >= limit:
                break
    return texts


def verify(onnx_path, export_dir, net, token2idx, char2idx, max_len, max_word, texts):
    """Çözümleme EŞİTLİĞİNİ sınar — emisyon farkı değil, ETİKET farkı önemli.

    Three decodings per text: (1) torchcrf on PyTorch emissions (reference),
    (2) torchcrf on ONNX emissions (the production export check), (3) the ported
    host-side Viterbi on ONNX emissions (the compiled-engine decoder path).
    """
    import numpy as np
    import onnxruntime as ort
    import torch

    from refimpl.export.crf_decode import load_export, viterbi
    from refimpl.extraction.architecture import pad_sequences, sentence_to_char_ids

    session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
    exp = load_export(export_dir)
    device = next(net.parameters()).device

    same = diff = tok_diff = tok_total = port_diff = 0
    for i in range(0, len(texts), 16):
        batch = texts[i:i + 16]
        seqs = [[token2idx.get(w.lower(), token2idx.get("UNK", 1)) for w in t.split()] for t in batch]
        w = torch.tensor(pad_sequences(seqs, max_len), dtype=torch.long)
        c = torch.tensor(
            np.array([sentence_to_char_ids(t, char2idx, max_len, max_word) for t in batch], dtype="int64"),
            dtype=torch.long)
        mask = (w != 0).to(device)
        with torch.no_grad():
            cr = net.char_embed_layer(c.to(device).reshape(-1, c.shape[-1])).reshape(w.size(0), w.size(1), -1)
            emissions = net.hidden2tag(net.lstm(torch.cat([net.word_embedding(w.to(device)), cr], dim=-1))[0])
            ref = net.crf.decode(emissions, mask=mask)
            onnx_em_np = session.run(None, {"words": w.numpy(), "chars": c.numpy()})[0]
            onnx_em = torch.tensor(onnx_em_np).to(device)
            got = net.crf.decode(onnx_em, mask=mask)
        for row, (a, b) in enumerate(zip(ref, got)):
            tok_total += len(a)
            if a == b:
                same += 1
            else:
                diff += 1
                tok_diff += sum(1 for x, y in zip(a, b) if x != y)
            n = len(a)
            ported = viterbi(onnx_em_np[row, :n, :], exp["start"], exp["end"], exp["transitions"]) if n else []
            if ported != b:
                port_diff += 1

    logger.info("Doğrulama: %d/%d cümlede etiket dizisi AYNI (%d token farkı / %d)",
                same, same + diff, tok_diff, tok_total)
    logger.info("Host-side Viterbi (Go port): %d/%d cümlede torchcrf ile AYNI",
                same + diff - port_diff, same + diff)
    if diff:
        logger.warning("ONNX çözümlemesi PyTorch'tan AYRIŞIYOR")
    if port_diff:
        logger.warning("Ported Viterbi decoder differs from torchcrf")
    return {"sentences": same + diff, "sentences_differing": diff, "tokens": tok_total,
            "tokens_differing": tok_diff, "viterbi_port_differing": port_diff}


if __name__ == "__main__":
    raise SystemExit(main())
