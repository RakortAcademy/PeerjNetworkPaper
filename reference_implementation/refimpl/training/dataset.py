"""
Eğitim verisi hazırlama — CVE JSONL kayıtlarından BIO etiketli NER örnekleri.

Girdi satırı:  {"cve_id": ..., "text": ..., "product": ..., "version": ...}
Çıktı:         token/karakter id dizileri + BIO etiketleri (PAD'lenmiş numpy dizileri)

Etiket seti: O, B-PRODUCT, I-PRODUCT, B-VERSION, I-VERSION (+ PAD).
`product`/`version` alanları açıklama metninde birebir geçmeyebildiği için
varlıklar bulanık pencere eşlemesiyle konumlandırılır.
"""
from __future__ import annotations

import json
import logging
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

logger = logging.getLogger(__name__)

LABELS = {
    "PAD": 0,
    "O": 1,
    "B-PRODUCT": 2,
    "I-PRODUCT": 3,
    "B-VERSION": 4,
    "I-VERSION": 5,
}

# Etiketlenemeyecek yer tutucu değerler.
_PLACEHOLDERS = {"", "unspecified", "n/a", "na", "unknown", "-"}


def pad_sequences(
    sequences: Sequence[Sequence[int]],
    maxlen: int,
    dtype: str = "int32",
    value: int = 0,
) -> np.ndarray:
    """Dizileri sona doldurarak/keserek (maxlen,) biçimine getirir."""
    padded = np.full((len(sequences), maxlen), value, dtype=dtype)
    for i, seq in enumerate(sequences):
        seq = seq[:maxlen]
        padded[i, : len(seq)] = seq
    return padded


def word_to_char_ids(word: str, char2idx: Dict[str, int], max_len: int) -> List[int]:
    ids = [char2idx.get(c, char2idx["UNK"]) for c in word]
    return ids[:max_len] + [char2idx["PAD"]] * max(0, max_len - len(ids))


def sentence_to_char_ids(
    sentence: str,
    char2idx: Dict[str, int],
    max_sent_len: int,
    max_word_len: int,
) -> List[List[int]]:
    """Cümleyi (max_sent_len × max_word_len) karakter-id matrisine çevirir."""
    words = sentence.split()
    chars = [word_to_char_ids(w, char2idx, max_word_len) for w in words]
    pad_word = [char2idx["PAD"]] * max_word_len
    if len(chars) < max_sent_len:
        chars += [pad_word] * (max_sent_len - len(chars))
    return chars[:max_sent_len]


def fuzzy_find_entity(
    text_tokens: List[str],
    entity_tokens: List[str],
    threshold: float = 0.85,
) -> Optional[Tuple[int, int]]:
    """Varlığı token dizisinde konumlandırır; (start, end) ya da None.

    Önce birebir eşleşme denenir; bulunamazsa varlık uzunluğu civarındaki
    pencereler SequenceMatcher oranına göre taranır.
    """
    if not entity_tokens:
        return None

    entity_len = len(entity_tokens)
    for i in range(len(text_tokens) - entity_len + 1):
        if text_tokens[i : i + entity_len] == entity_tokens:
            return i, i + entity_len

    entity_str = " ".join(entity_tokens)
    best_match: Optional[Tuple[int, int]] = None
    best_score = 0.0
    for length in range(max(1, entity_len - 2), min(len(text_tokens) + 1, entity_len + 3)):
        for i in range(len(text_tokens) - length + 1):
            window = " ".join(text_tokens[i : i + length])
            score = SequenceMatcher(None, window, entity_str).ratio()
            if score > best_score and score >= threshold:
                best_score = score
                best_match = (i, i + length)
    return best_match


def _is_labelable(value: Optional[str]) -> bool:
    return bool(value) and value.strip().lower() not in _PLACEHOLDERS


# Katalog adında geçen ama metinde görünmeyen satıcı/edisyon kelimeleri. Hizalama
# bunlar yüzünden tutmuyor: katalog "Rational Rhapsody Design Manager" derken
# metin "IBM Rhapsody DM" diyor.
_ALIGN_STOPWORDS = frozenset({
    "ibm", "microsoft", "oracle", "apache", "google", "adobe", "cisco", "sap",
    "hp", "hpe", "dell", "vmware", "redhat", "rational", "tivoli", "websphere",
    "edition", "standard", "select", "professional", "enterprise", "server",
    "client", "manager", "management", "design", "suite", "platform", "system",
    "software", "solution", "solutions", "tools", "tool", "service", "services",
    "for", "and", "the", "of",
})


def _alignment_candidates(name: str) -> List[List[str]]:
    """Bir varlık adı için metinde aranacak biçimler — genişten dara.

    "Rational Rhapsody Design Manager" → tam ad, sonra ["rhapsody"] gibi
    ayırt edici çekirdek. Satıcılar katalog adıyla düzyazıyı farklı yazdığı
    için tek biçim denemek örneklerin %40'ını etiketsiz bırakıyordu.
    """
    tokens = name.split()
    if not tokens:
        return []

    forms: List[List[str]] = [tokens]

    distinctive = [t for t in tokens if t.lower() not in _ALIGN_STOPWORDS]
    if distinctive and distinctive != tokens:
        forms.append(distinctive)
    # Tek ayırt edici kelime (en uzun) — "Rhapsody", "QRadar", "Concert".
    long_tokens = [t for t in distinctive if len(t) >= 4]
    if long_tokens:
        forms.append([max(long_tokens, key=len)])

    seen, unique = set(), []
    for form in forms:
        key = tuple(t.lower() for t in form)
        if key not in seen:
            seen.add(key)
            unique.append(form)
    return unique


def _align(tokens: List[str], name: str) -> Optional[Tuple[int, int]]:
    """Varlığı metinde konumlandırır; giderek daha dar biçimler dener."""
    for form in _alignment_candidates(name):
        match = fuzzy_find_entity(tokens, form)
        if match:
            return match
    return None


def create_bio_labels(
    text: str,
    product: str,
    version: str,
    extra_versions: Sequence[str] = (),
) -> Tuple[List[str], List[int]]:
    """Bir CVE açıklaması için (tokens, label_ids) üretir.

    `extra_versions` yapısal sürüm sınırlarıdır (less_than vb.). `version`
    alanı metinde geçmediğinde bunlar çoğu kez geçer ("... before 1.2.3").
    """
    tokens = text.split()
    labels = [LABELS["O"]] * len(tokens)

    if _is_labelable(product):
        match = _align(tokens, product)
        if match:
            start, end = match
            labels[start] = LABELS["B-PRODUCT"]
            for j in range(start + 1, min(end, len(labels))):
                labels[j] = LABELS["I-PRODUCT"]

    for candidate in [version, *extra_versions]:
        if not _is_labelable(candidate):
            continue
        match = fuzzy_find_entity(tokens, candidate.split())
        if not match:
            continue
        start, end = match
        for j in range(start, min(end, len(labels))):
            if labels[j] == LABELS["O"]:
                labels[j] = LABELS["B-VERSION"] if j == start else LABELS["I-VERSION"]
        break

    return tokens, labels


def _sample(
    records: List[Dict[str, Any]],
    max_samples: Optional[int],
    seed: int,
) -> List[Dict[str, Any]]:
    """Baştan kesmek yerine rastgele örnekler.

    CVE kayıtları kimliğe göre sıralı geldiği için ilk N'i almak eğitimi
    yalnızca en eski açıklarla sınırlardı.
    """
    total = len(records)
    if not max_samples or total <= max_samples:
        return records
    rng = np.random.default_rng(seed)
    picked = rng.choice(total, size=max_samples, replace=False)
    return [records[i] for i in sorted(picked)]


def load_cve_jsonl(
    path: Path,
    max_samples: Optional[int] = None,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """JSONL dosyasından eğitilebilir kayıtları okur (yedek kaynak)."""
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            text = (item.get("text") or item.get("description") or "").strip()
            product = (item.get("product") or "").strip()
            if not text or not product:
                continue
            records.append(
                {
                    "text": text,
                    "product": product,
                    "version": (item.get("version") or "").strip(),
                    "cve_id": item.get("cve_id") or f"CVE-{idx}",
                }
            )

    total = len(records)
    records = _sample(records, max_samples, seed)
    logger.info("%d/%d eğitim kaydı yüklendi: %s", len(records), total, path)
    return records


def build_vocabularies(
    records: Sequence[Dict[str, Any]],
    min_word_freq: int = 2,
    min_char_freq: int = 5,
) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
    """Kelime ve karakter sözlüklerini kurar (etiket seti sabittir).

    Yalnızca bir kez geçen kelimeler (CVE metinlerinde çoğu benzersiz hash, yol
    ve tanımlayıcı) sözlüğe alınmaz: gömme tablosunu küçültür ve modeli UNK
    üzerinden genellemeye zorlar.
    """
    word_counts: Counter = Counter()
    char_counts: Counter = Counter()
    for item in records:
        for w in item["text"].split():
            word_counts[w.lower()] += 1
            char_counts.update(w)

    token2idx: Dict[str, int] = {"PAD": 0, "UNK": 1}
    for w, n in sorted(word_counts.items()):
        if n >= min_word_freq:
            token2idx[w] = len(token2idx)

    char2idx: Dict[str, int] = {"PAD": 0, "UNK": 1}
    for c, n in sorted(char_counts.items()):
        if n >= min_char_freq:
            char2idx[c] = len(char2idx)

    logger.info(
        "Sözlükler: %d/%d kelime (min_freq=%d), %d/%d karakter, %d etiket",
        len(token2idx), len(word_counts) + 2, min_word_freq,
        len(char2idx), len(char_counts) + 2,
        len(LABELS),
    )
    return token2idx, char2idx, dict(LABELS)


def encode_records(
    records: Sequence[Dict[str, Any]],
    token2idx: Dict[str, int],
    char2idx: Dict[str, int],
    max_len: int = 200,
    max_word_length: int = 20,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Kayıtları (X_words, X_chars, y) padded numpy dizilerine çevirir."""
    x_words: List[np.ndarray] = []
    x_chars: List[np.ndarray] = []
    y: List[np.ndarray] = []

    for item in records:
        tokens, labels = create_bio_labels(item["text"], item["product"], item["version"])
        if not tokens:
            continue
        token_ids = [token2idx.get(w.lower(), token2idx["UNK"]) for w in tokens]
        char_ids = sentence_to_char_ids(" ".join(tokens), char2idx, max_len, max_word_length)

        x_words.append(pad_sequences([token_ids], maxlen=max_len)[0])
        x_chars.append(np.array(char_ids, dtype=np.int32))
        y.append(pad_sequences([labels], maxlen=max_len, value=LABELS["PAD"])[0])

    logger.info("%d örnek kodlandı", len(x_words))
    return np.array(x_words), np.array(x_chars), np.array(y)


def _label_one(item: Dict[str, Any]) -> Tuple[List[str], List[int]]:
    """Tek kaydın BIO etiketlerini üretir (process havuzu için modül düzeyinde)."""
    return create_bio_labels(
        item["text"],
        item["product"],
        item.get("version") or "",
        extra_versions=item.get("bounds") or (),
    )


class CVENerDataset:
    """Örnekleri istendiğinde kodlayan torch Dataset'i.

    Tüm veriyi (özellikle karakter tensörlerini) önceden üretmek 120k kayıtta
    birkaç GB demek; bu yüzden karakter kodlaması istendiği anda yapılır ve
    bellek kayıt sayısından bağımsız kalır.

    BIO etiketleri ise `prepare()` ile BİR KEZ hesaplanıp saklanır: etiketleme
    varlıkları bulanık pencere taramasıyla (SequenceMatcher) konumlandırır ve
    kayıt başına birkaç milisaniye sürer. Önbelleklenmezse bu maliyet HER
    epoch'ta yeniden ödenir ve eğitim GPU değil CPU sınırlı hâle gelir.
    """

    def __init__(
        self,
        records: Sequence[Dict[str, Any]],
        token2idx: Dict[str, int],
        char2idx: Dict[str, int],
        max_len: int = 200,
        max_word_length: int = 20,
    ) -> None:
        self.records = records
        self.token2idx = token2idx
        self.char2idx = char2idx
        self.max_len = max_len
        self.max_word_length = max_word_length
        self._cache: Optional[List[Tuple[List[str], List[int]]]] = None

    def prepare(
        self,
        workers: int = 0,
        chunksize: int = 200,
        drop_unaligned: bool = True,
    ) -> "CVENerDataset":
        """BIO etiketlerini önceden hesaplar. Zincirleme için kendini döndürür.

        `drop_unaligned` (varsayılan) hiçbir varlığın konumlandırılamadığı
        örnekleri veri kümesinden çıkarır. Bu örneklerde ürün AÇIKLAMADA VAR,
        yalnızca katalog adıyla düzyazı farklı yazıldığı için bulunamıyor
        (katalog "Rational Rhapsody Design Manager", metin "IBM Rhapsody DM").
        Onları tutmak modele "bu metinde ürün yok" diye yanlış örnek verir.
        """
        import time

        started = time.time()
        if workers and workers > 1:
            from concurrent.futures import ProcessPoolExecutor

            with ProcessPoolExecutor(max_workers=workers) as pool:
                labelled = list(pool.map(_label_one, self.records, chunksize=chunksize))
        else:
            labelled = [_label_one(item) for item in self.records]

        elapsed = time.time() - started
        if drop_unaligned:
            entity_labels = {LABELS["B-PRODUCT"], LABELS["I-PRODUCT"],
                             LABELS["B-VERSION"], LABELS["I-VERSION"]}
            keep = [
                i for i, (tokens, labels) in enumerate(labelled)
                if tokens and entity_labels.intersection(labels)
            ]
            dropped = len(labelled) - len(keep)
            self.records = [self.records[i] for i in keep]
            labelled = [labelled[i] for i in keep]
            logger.info(
                "Hizalanamayan %d örnek (%.1f%%) eğitim dışı bırakıldı",
                dropped, 100 * dropped / max(1, dropped + len(keep)),
            )

        self._cache = labelled
        logger.info(
            "%d kaydın BIO etiketi %.1f sn'de hesaplandı (%d işçi)",
            len(self._cache), elapsed, workers or 1,
        )
        return self

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int):
        import torch

        if self._cache is not None:
            tokens, labels = self._cache[index]
        else:
            tokens, labels = _label_one(self.records[index])
        unk = self.token2idx["UNK"]
        token_ids = [self.token2idx.get(w.lower(), unk) for w in tokens]
        char_ids = sentence_to_char_ids(
            " ".join(tokens), self.char2idx, self.max_len, self.max_word_length
        )

        words = pad_sequences([token_ids], maxlen=self.max_len)[0]
        tags = pad_sequences([labels], maxlen=self.max_len, value=LABELS["PAD"])[0]
        return (
            torch.from_numpy(words.astype("int64")),
            torch.tensor(char_ids, dtype=torch.long),
            torch.from_numpy(tags.astype("int64")),
        )


def split_indices(
    n: int,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Karıştırılmış train/val/test indeksleri (sabit tohum → tekrarlanabilir)."""
    rng = np.random.default_rng(seed)
    indices = rng.permutation(n)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    return (
        indices[:n_train],
        indices[n_train : n_train + n_val],
        indices[n_train + n_val :],
    )
