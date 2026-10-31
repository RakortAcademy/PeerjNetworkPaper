"""Learned tagger: construction, forward/loss, masking, decode, training helpers,
the ported host-side Viterbi, and ONNX export equivalence (synthetic/random weights)."""
from __future__ import annotations

import json
import os
import sys

import numpy as np
import pytest

torch = pytest.importorskip("torch")
pytest.importorskip("torchcrf")

from refimpl.extraction.architecture import (  # noqa: E402
    BiLSTM_CRF, load_checkpoint, pad_sequences, predict_batch, sentence_to_char_ids,
)
from refimpl.export.crf_decode import decode_labels, encode_batch, viterbi  # noqa: E402
from refimpl.training.dataset import LABELS, build_vocabularies  # noqa: E402

RECORDS = [
    {"text": "Acme Ledgerly Server before 2.4.1 allows remote code execution", "product": "Acme Ledgerly Server", "version": "2.4.1"},
    {"text": "Northwind Mailflow Gateway prior to 5.2.0 mishandles attachments", "product": "Northwind Mailflow Gateway", "version": "5.2.0"},
    {"text": "A flaw in ZetaDB 4.0.3 allows injection", "product": "ZetaDB", "version": "4.0.3"},
]


def tiny_model(seed=0):
    torch.manual_seed(seed)
    tok, chr_, lab = build_vocabularies(RECORDS, min_word_freq=1, min_char_freq=1)
    m = BiLSTM_CRF(vocab_size=len(tok), char_vocab_size=len(chr_), embedding_dim=8, char_embedding_dim=4,
                   char_hidden_dim=4, word_hidden_dim=8, tagset_size=len(lab),
                   token2idx=tok, char2idx=chr_, label2idx=lab).eval()
    return m, tok, chr_, lab


def test_parameter_count_formula_matches_architecture():
    """Parameter count is the production formula for these dimensions (sanity on construction)."""
    m, tok, chr_, lab = tiny_model()
    V, C, E, CE, CH, H, T = len(tok), len(chr_), 8, 4, 4, 8, len(lab)
    expected = (V * E + C * CE
                + 2 * (4 * CH * CE + 4 * CH * CH + 8 * CH)                 # char BiLSTM
                + 2 * (4 * (H // 2) * (E + 2 * CH) + 4 * (H // 2) * (H // 2) + 8 * (H // 2))  # word BiLSTM
                + H * T + T                                                 # projection
                + T * T + 2 * T)                                            # CRF transitions
    assert sum(p.numel() for p in m.parameters()) == expected


def test_production_dimensions_give_a_model_in_the_millions():
    """With the production layer sizes and the manuscript's vocabulary sizes
    (86,279 words, 199 characters, 6 labels) the parameter count is 8.8M."""
    V, C, E, CE, CH, H, T = 86279, 199, 100, 50, 50, 128, 6
    n = (V * E + C * CE + 2 * (4 * CH * CE + 4 * CH * CH + 8 * CH)
         + 2 * (4 * (H // 2) * (E + 2 * CH) + 4 * (H // 2) * (H // 2) + 8 * (H // 2)) + H * T + T + T * T + 2 * T)
    assert round(n / 1e6, 1) == 8.8


def test_forward_returns_nll_with_tags_and_paths_without():
    m, tok, chr_, lab = tiny_model()
    texts = [r["text"] for r in RECORDS]
    seqs = [[tok.get(w.lower(), tok["UNK"]) for w in t.split()] for t in texts]
    words = torch.tensor(pad_sequences(seqs, 20), dtype=torch.long)
    chars = torch.tensor(np.array([sentence_to_char_ids(t, chr_, 20, 10) for t in texts]), dtype=torch.long)
    tags = torch.full_like(words, LABELS["O"])
    tags[words == 0] = LABELS["PAD"]
    loss = m(words, chars, tags)
    assert loss.dim() == 0 and loss.item() > 0
    paths = m(words, chars)
    assert [len(p) for p in paths] == [len(s) for s in seqs]  # mask = non-padding tokens


def test_predict_batch_skips_empty_texts_and_keeps_order():
    m, tok, chr_, lab = tiny_model()
    out = predict_batch(["", RECORDS[0]["text"], "   "], m, tok, chr_, lab, max_len=20, max_word_length=10)
    assert out[0]["labels"] == [] and out[2]["labels"] == []
    assert len(out[1]["labels"]) == len(RECORDS[0]["text"].split())


def test_viterbi_port_matches_torchcrf_on_random_emissions():
    from torchcrf import CRF
    torch.manual_seed(7)
    T = 6
    crf = CRF(T, batch_first=True)
    start = crf.start_transitions.detach().numpy()
    end = crf.end_transitions.detach().numpy()
    trans = crf.transitions.detach().numpy()
    rng = np.random.default_rng(7)
    for n in (1, 2, 5, 17, 40):
        em = rng.normal(size=(n, T)).astype(np.float32)
        ref = crf.decode(torch.tensor(em)[None, :, :], mask=torch.ones(1, n, dtype=torch.bool))[0]
        assert viterbi(em, start, end, trans) == ref


def test_encode_batch_matches_python_tensor_construction():
    m, tok, chr_, lab = tiny_model()
    texts = [RECORDS[0]["text"], "ZetaDB 4.0.3"]
    tokenized = [t.split() for t in texts]
    words, chars, lengths = encode_batch(tokenized, tok, chr_, 20, 10)
    ref_words = pad_sequences([[tok.get(w.lower(), tok["UNK"]) for w in t.split()] for t in texts], 20)
    ref_chars = np.array([sentence_to_char_ids(t, chr_, 20, 10) for t in texts])
    assert (words == ref_words).all() and (chars == ref_chars).all()
    assert lengths == [len(t.split()) for t in texts]


def test_decode_labels_collects_spans():
    out = decode_labels(["Acme", "Widget", "9.1"], [2, 3, 4], ["PAD", "O", "B-PRODUCT", "I-PRODUCT", "B-VERSION", "I-VERSION"])
    assert out["product"] == "Acme Widget" and out["version"] == "9.1"


def test_checkpoint_roundtrip_and_export_equivalence(tmp_path):
    """Save a checkpoint in the production format, reload it, export to ONNX and
    check decode equivalence (torchcrf on torch emissions vs torchcrf on ONNX
    emissions vs the ported host-side Viterbi)."""
    pytest.importorskip("onnx")
    pytest.importorskip("onnxruntime")
    m, tok, chr_, lab = tiny_model(seed=3)
    cfg = {"embedding_dim": 8, "char_embedding_dim": 4, "char_hidden_dim": 4, "word_hidden_dim": 8,
           "max_len": 20, "max_word_length": 10}
    ckpt = tmp_path / "bilstm_crf.pth"
    torch.save({"model_state_dict": m.state_dict(), "token2idx": tok, "char2idx": chr_, "label2idx": lab,
                "config": cfg}, ckpt)
    m2, tok2, chr2, lab2, cfg2 = load_checkpoint(str(tmp_path), device=torch.device("cpu"))
    assert tok2 == tok and cfg2["max_len"] == 20

    texts_file = tmp_path / "texts.txt"
    texts_file.write_text("\n".join(r["text"] for r in RECORDS) + "\n", encoding="utf-8")
    from refimpl.export import export_onnx
    rc = export_onnx.main(["--checkpoint", str(ckpt), "--out", str(tmp_path / "onnx"),
                           "--verify-texts", str(texts_file)])
    assert rc == 0
    meta = json.loads((tmp_path / "onnx" / "meta.json").read_text())
    assert meta["tagset_size"] == len(lab) and len(meta["model_version"]) == 16
    assert (tmp_path / "onnx" / "emissions.onnx").exists()

    from refimpl.export.crf_decode import OnnxExtractor
    ox = OnnxExtractor(tmp_path / "onnx")
    got = ox.extract_batch([r["text"] for r in RECORDS] + [""])
    ref = predict_batch([r["text"] for r in RECORDS], m2, tok2, chr2, lab2, max_len=20, max_word_length=10)
    assert [g["labels"] for g in got[:3]] == [r["labels"] for r in ref]
    assert got[3]["labels"] == []


@pytest.mark.skipif(not os.environ.get("REFIMPL_MODEL_PATH"), reason="set REFIMPL_MODEL_PATH to a trained checkpoint")
def test_trained_checkpoint_loads_and_extracts():
    from refimpl.extraction.extractor import BiLSTMCRFExtractor
    ex = BiLSTMCRFExtractor(model_dir=os.environ["REFIMPL_MODEL_PATH"])
    out = ex.extract("Acme Ledgerly Server before 2.4.1 allows remote attackers to execute arbitrary code.", "X")
    assert out["less_than"] == "2.4.1"           # operator by rule, independent of the model
    assert out["extraction_method"].startswith("bilstm-crf")
