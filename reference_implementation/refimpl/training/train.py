"""
BiLSTM-CRF eğitimi — yerel GPU (Jetson/CUDA) ya da CPU.

Kullanım:
    python -m refimpl.training.train --data records.jsonl --output out/
    python -m refimpl.training.train --data records.jsonl --output out/ --max-samples 5000
    python -m refimpl.training.train --data records.jsonl --output out/ --epochs 30 --batch-size 64

Örnekler DataLoader üzerinden istendiğinde kodlanır, bu yüzden bellek kullanımı
veri kümesi büyüklüğünden bağımsızdır.

En iyi validation kaybını veren ağırlıklar `<output>/bilstm_crf.pth`
dosyasına yazılır; çıkarım tarafı (`refimpl.extraction`) doğrudan bunu okur.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional, Sequence

import numpy as np
import torch
from torch import nn, optim
from torch.utils.data import DataLoader, Subset

from refimpl.extraction.architecture import BiLSTM_CRF
from refimpl.training.dataset import (
    LABELS,
    CVENerDataset,
    build_vocabularies,
    load_cve_jsonl,
    split_indices,
)

# Checkpoint and dictionary file names (same as the production serving layout).
MODEL_FILENAME = "bilstm_crf.pth"
DICTS_FILENAME = "model_dictionaries.json"

logger = logging.getLogger(__name__)

DEFAULTS = {
    "epochs": 30,
    "batch_size": 64,
    "learning_rate": 1e-3,
    "weight_decay": 1e-4,
    "patience": 5,
    "embedding_dim": 100,
    "char_embedding_dim": 50,
    "char_hidden_dim": 50,
    "word_hidden_dim": 128,
    "max_len": 200,
    "max_word_length": 20,
    "min_word_freq": 2,
    "train_ratio": 0.8,
    "val_ratio": 0.1,
    "seed": 42,
}


def _run_epoch(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    optimizer: Optional[optim.Optimizer] = None,
) -> float:
    """Bir epoch çalıştırır. optimizer verilirse eğitim, verilmezse doğrulama."""
    training = optimizer is not None
    model.train(training)
    total_loss, n_batches = 0.0, 0

    for words, chars, tags in loader:
        words = words.to(device, non_blocking=True)
        chars = chars.to(device, non_blocking=True)
        tags = tags.to(device, non_blocking=True)

        with torch.set_grad_enabled(training):
            loss = model(words, chars, tags)
            if training:
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                # CRF kaybı uzun dizilerde patlayabiliyor; gradyanı sınırla.
                torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
                optimizer.step()

        total_loss += float(loss.item())
        n_batches += 1

    return total_loss / max(1, n_batches)


@torch.no_grad()
def evaluate(model: nn.Module, loader: DataLoader, device: torch.device) -> Dict[str, float]:
    """PRODUCT/VERSION etiketleri için token düzeyinde mikro precision/recall/F1."""
    model.eval()
    idx2label = {v: k for k, v in LABELS.items()}
    tp = fp = fn = 0

    for words, chars, tags in loader:
        words = words.to(device)
        chars = chars.to(device)
        predictions = model(words, chars)
        for row_pred, row_true in zip(predictions, tags.tolist()):
            for j, p in enumerate(row_pred):
                gold = idx2label.get(int(row_true[j]), "PAD")
                pred = idx2label.get(int(p), "O")
                gold_entity = gold not in ("O", "PAD")
                pred_entity = pred not in ("O", "PAD")
                if pred_entity and gold_entity and pred == gold:
                    tp += 1
                elif pred_entity:
                    fp += 1
                elif gold_entity:
                    fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "support": tp + fn}


def _loader(
    dataset: CVENerDataset,
    indices: Sequence[int],
    batch_size: int,
    shuffle: bool,
    workers: int,
    pin: bool,
) -> DataLoader:
    return DataLoader(
        Subset(dataset, list(indices)),
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=workers,
        pin_memory=pin,
        persistent_workers=workers > 0,
    )


def train(args: argparse.Namespace) -> Path:
    config = dict(DEFAULTS)
    config.update(
        {
            "epochs": args.epochs,
            "batch_size": args.batch_size,
            "learning_rate": args.learning_rate,
            "max_len": args.max_len,
            "min_word_freq": args.min_word_freq,
            # Reference implementation: layer sizes are exposed as flags so a
            # reviewer can train a small model quickly. Defaults are the
            # production values (100 / 50 / 50 / 128).
            "embedding_dim": args.embedding_dim,
            "char_embedding_dim": args.char_embedding_dim,
            "char_hidden_dim": args.char_hidden_dim,
            "word_hidden_dim": args.word_hidden_dim,
            "patience": args.patience,
        }
    )

    torch.manual_seed(config["seed"])
    np.random.seed(config["seed"])

    device = torch.device(args.device or ("cuda" if torch.cuda.is_available() else "cpu"))
    logger.info("Cihaz: %s", device)
    if device.type == "cuda":
        logger.info("GPU: %s", torch.cuda.get_device_name(0))

    # Reference implementation: training data is always a JSONL file. The
    # production loader that read labelled rows from the corpus store is not
    # included (restricted data path); the JSONL loader is the same code path
    # the production trainer used as its file-based source.
    source = Path(args.data)
    if not source.is_file():
        raise FileNotFoundError(f"CVE veri dosyası bulunamadı: {source}")
    records = load_cve_jsonl(source, max_samples=args.max_samples)
    if not records:
        raise ValueError("Eğitilebilir kayıt yok (text + product gerekli)")

    token2idx, char2idx, label2idx = build_vocabularies(
        records, min_word_freq=config["min_word_freq"]
    )
    dataset = CVENerDataset(
        records,
        token2idx,
        char2idx,
        max_len=config["max_len"],
        max_word_length=config["max_word_length"],
    )
    # Etiketleri bir kez hesapla; aksi halde her epoch'ta yeniden üretilir ve
    # eğitim GPU değil CPU sınırlı kalır.
    dataset.prepare(workers=args.label_workers, drop_unaligned=not args.keep_unaligned)

    train_idx, val_idx, test_idx = split_indices(
        len(dataset), config["train_ratio"], config["val_ratio"], config["seed"]
    )
    logger.info("Bölünme — train:%d val:%d test:%d", len(train_idx), len(val_idx), len(test_idx))

    pin = device.type == "cuda"
    train_loader = _loader(dataset, train_idx, config["batch_size"], True, args.workers, pin)
    val_loader = _loader(dataset, val_idx, config["batch_size"], False, args.workers, pin)
    test_loader = _loader(dataset, test_idx, config["batch_size"], False, args.workers, pin)

    model = BiLSTM_CRF(
        vocab_size=len(token2idx),
        char_vocab_size=len(char2idx),
        embedding_dim=config["embedding_dim"],
        char_embedding_dim=config["char_embedding_dim"],
        char_hidden_dim=config["char_hidden_dim"],
        word_hidden_dim=config["word_hidden_dim"],
        tagset_size=len(label2idx),
        token2idx=token2idx,
        char2idx=char2idx,
        label2idx=label2idx,
    ).to(device)
    n_params = sum(p.numel() for p in model.parameters())
    logger.info("Model parametre sayısı: %.1fM", n_params / 1e6)

    optimizer = optim.Adam(
        model.parameters(),
        lr=config["learning_rate"],
        weight_decay=config["weight_decay"],
    )
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="min", factor=0.5, patience=2)

    # Eğitim çıktısı ASLA doğrudan servis yoluna yazılmaz: API yeniden başlarsa
    # yarım eğitilmiş modeli canlıya alırdı. Terfi ayrı bir adımdır
    # (python -m model.promote apply).
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    best_path = out_dir / MODEL_FILENAME

    best_val = float("inf")
    no_improve = 0
    history = []

    for epoch in range(config["epochs"]):
        started = time.time()
        train_loss = _run_epoch(model, train_loader, device, optimizer)
        val_loss = _run_epoch(model, val_loader, device)
        scheduler.step(val_loss)
        history.append(
            {"epoch": epoch + 1, "train_loss": train_loss, "val_loss": val_loss}
        )

        logger.info(
            "Epoch %d/%d (%.1fs) — train %.4f | val %.4f | lr %.6f",
            epoch + 1, config["epochs"], time.time() - started,
            train_loss, val_loss, optimizer.param_groups[0]["lr"],
        )

        if val_loss < best_val:
            best_val = val_loss
            no_improve = 0
            torch.save(
                {
                    "model_state_dict": model.state_dict(),
                    "token2idx": token2idx,
                    "char2idx": char2idx,
                    "label2idx": label2idx,
                    "config": config,
                    "val_loss": val_loss,
                    "epoch": epoch + 1,
                },
                best_path,
            )
            (out_dir / DICTS_FILENAME).write_text(
                json.dumps(
                    {"token2idx": token2idx, "char2idx": char2idx, "label2idx": label2idx},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            logger.info("  ↳ yeni en iyi model kaydedildi (val_loss %.4f)", val_loss)
        else:
            no_improve += 1
            if no_improve >= config["patience"]:
                logger.info("Erken durdurma — %d epoch iyileşme yok", no_improve)
                break

    # Test setinde son değerlendirme (en iyi ağırlıklarla).
    checkpoint = torch.load(best_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])
    metrics = evaluate(model, test_loader, device)
    logger.info(
        "Test — precision %.4f | recall %.4f | F1 %.4f (%d varlık)",
        metrics["precision"], metrics["recall"], metrics["f1"], metrics["support"],
    )

    report = {
        "checkpoint": str(best_path),
        "best_val_loss": best_val,
        "test_metrics": metrics,
        "n_records": len(records),
        "vocab_size": len(token2idx),
        "n_params": n_params,
        "config": config,
        "history": history,
    }
    (out_dir / "training_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Model hazır: %s", best_path)
    return best_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BiLSTM-CRF CVE NER eğitimi")
    p.add_argument("--data", required=True, help="JSONL eğitim dosyası")
    p.add_argument("--output", required=True, help="Çıktı dizini (checkpoint + sözlükler + rapor)")
    p.add_argument("--epochs", type=int, default=DEFAULTS["epochs"])
    p.add_argument("--patience", type=int, default=DEFAULTS["patience"])
    p.add_argument("--embedding-dim", type=int, default=DEFAULTS["embedding_dim"])
    p.add_argument("--char-embedding-dim", type=int, default=DEFAULTS["char_embedding_dim"])
    p.add_argument("--char-hidden-dim", type=int, default=DEFAULTS["char_hidden_dim"])
    p.add_argument("--word-hidden-dim", type=int, default=DEFAULTS["word_hidden_dim"])
    p.add_argument("--batch-size", type=int, default=DEFAULTS["batch_size"])
    p.add_argument("--learning-rate", type=float, default=DEFAULTS["learning_rate"])
    p.add_argument("--max-len", type=int, default=DEFAULTS["max_len"])
    p.add_argument("--min-word-freq", type=int, default=DEFAULTS["min_word_freq"])
    p.add_argument("--max-samples", type=int, help="Yalnızca ilk N kaydı kullan")
    p.add_argument("--workers", type=int, default=2, help="DataLoader işçi sayısı")
    p.add_argument(
        "--label-workers", type=int, default=8,
        help="BIO etiketlerini önceden hesaplarken kullanılacak süreç sayısı",
    )
    p.add_argument(
        "--keep-unaligned", action="store_true",
        help="Varlığı konumlandırılamayan örnekleri de eğitimde tut (varsayılan: düşür)",
    )
    p.add_argument("--device", help="cuda | cpu (varsayılan: otomatik)")
    return p


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )
    train(build_parser().parse_args())


if __name__ == "__main__":
    main()
