"""
BiLSTM-CRF mimarisi ve çıkarım (inference).

Kelime gömmesi + karakter düzeyinde BiLSTM gömmesi birleştirilir, bir BiLSTM'den
geçirilir ve CRF katmanı BIO etiket dizisini çözer. Eğitim `model.training.train`
ile yapılır; checkpoint formatı ikisi arasında ortaktır.
"""

import os
import numpy as np
import torch
from torch import nn
from torchcrf import CRF


def pad_sequences(sequences, maxlen, dtype='int32', padding='post', truncating='post', value=0):
    """Pad sequences to maxlen."""
    padded = np.full((len(sequences), maxlen), value, dtype=dtype)
    for i, seq in enumerate(sequences):
        if len(seq) > maxlen:
            seq = seq[:maxlen] if truncating == 'post' else seq[-maxlen:]
        if padding == 'post':
            padded[i, :len(seq)] = seq
        else:
            padded[i, -len(seq):] = seq
    return padded


def word_to_char_ids(word, char2idx, max_len):
    """Convert word to character IDs."""
    ids = [char2idx.get(c, char2idx['UNK']) for c in word]
    return ids[:max_len] + [char2idx['PAD']] * max(0, max_len - len(ids))


def sentence_to_char_ids(sentence, char2idx, max_sent_len, max_word_len):
    """Convert sentence to character IDs matrix (max_sent_len x max_word_len)."""
    words = sentence.split()
    chars = [word_to_char_ids(w, char2idx, max_word_len) for w in words]
    pad_word = [char2idx['PAD']] * max_word_len
    if len(chars) < max_sent_len:
        chars += [pad_word] * (max_sent_len - len(chars))
    else:
        chars = chars[:max_sent_len]
    return chars


class CharEmbedding(nn.Module):
    """Character-level embedding with BiLSTM (matches notebook)."""

    def __init__(self, char_vocab_size, char_embedding_dim, char_hidden_dim):
        super().__init__()
        self.char_embed = nn.Embedding(char_vocab_size, char_embedding_dim)
        self.char_lstm = nn.LSTM(
            input_size=char_embedding_dim,
            hidden_size=char_hidden_dim,
            batch_first=True,
            bidirectional=True
        )

    def forward(self, char_input):
        embeds = self.char_embed(char_input)
        _, (hidden, _) = self.char_lstm(embeds)
        return torch.cat([hidden[0], hidden[1]], dim=1)


class BiLSTM_CRF(nn.Module):
    """Full BiLSTM-CRF model for NER (matches notebook)."""

    def __init__(self, vocab_size, char_vocab_size, embedding_dim, char_embedding_dim,
                 char_hidden_dim, word_hidden_dim, tagset_size,
                 token2idx=None, char2idx=None, label2idx=None):
        super().__init__()
        self.vocab_size = vocab_size
        self.char_vocab_size = char_vocab_size
        self.embedding_dim = embedding_dim
        self.char_embedding_dim = char_embedding_dim
        self.char_hidden_dim = char_hidden_dim
        self.word_hidden_dim = word_hidden_dim
        self.tagset_size = tagset_size
        self.word_embedding = nn.Embedding(vocab_size, embedding_dim)
        self.char_embed_layer = CharEmbedding(char_vocab_size, char_embedding_dim, char_hidden_dim)
        self.dropout = nn.Dropout(p=0.5)
        self.lstm = nn.LSTM(
            input_size=embedding_dim + 2 * char_hidden_dim,
            hidden_size=word_hidden_dim // 2,
            num_layers=1,
            bidirectional=True,
            batch_first=True,
            dropout=0
        )
        self.hidden2tag = nn.Linear(word_hidden_dim, tagset_size)
        self.crf = CRF(tagset_size, batch_first=True)
        self.token2idx = token2idx or {}
        self.char2idx = char2idx or {}
        self.label2idx = label2idx or {}
        self.idx2label = {v: k for k, v in (label2idx or {}).items()}

    def forward(self, words, chars, tags=None):
        word_embeds = self.word_embedding(words)
        chars_flat = chars.view(-1, chars.shape[-1])
        char_rep = self.char_embed_layer(chars_flat)
        char_rep = char_rep.view(words.size(0), words.size(1), -1)
        combined = torch.cat([word_embeds, char_rep], dim=-1)
        combined = self.dropout(combined)
        lstm_out, _ = self.lstm(combined)
        lstm_out = self.dropout(lstm_out)
        emissions = self.hidden2tag(lstm_out)
        mask = (words != 0)
        if tags is not None:
            return -self.crf(emissions, tags, mask=mask)
        return self.crf.decode(emissions, mask=mask)


def load_checkpoint(model_dir_or_file, device=None):
    """Eğitilmiş checkpoint'i yükler.

    Argüman bir dizin ya da doğrudan bir .pth dosyası olabilir; dosya vermek
    belirli bir sürümü sabitlemeyi sağlar (ör. eğitim arka planda checkpoint'i
    güncellerken analizin kararlı bir modelle sürmesi).

    Returns: (model, token2idx, char2idx, label2idx, config)
    """
    MODEL_FILENAME = "bilstm_crf.pth"  # checkpoint file name inside a directory

    target = str(model_dir_or_file)
    path = target if os.path.isfile(target) else os.path.join(target, MODEL_FILENAME)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Model dosyası bulunamadı: {path}\n"
            f"Modeli eğitmek için: python -m refimpl.training.train --data <jsonl> --output <dir>"
        )
    try:
        checkpoint = torch.load(path, map_location='cpu', weights_only=False)
    except TypeError:
        checkpoint = torch.load(path, map_location='cpu')
    token2idx = checkpoint.get('token2idx')
    char2idx = checkpoint.get('char2idx')
    label2idx = checkpoint.get('label2idx')
    config = checkpoint.get('config') or {}
    if not token2idx or not char2idx or not label2idx:
        raise ValueError("Checkpoint missing token2idx, char2idx, or label2idx")
    # Build model from config
    vocab_size = len(token2idx)
    char_vocab_size = len(char2idx)
    tagset_size = len(label2idx)
    embedding_dim = config.get('embedding_dim', 100)
    char_embedding_dim = config.get('char_embedding_dim', 50)
    char_hidden_dim = config.get('char_hidden_dim', 50)
    word_hidden_dim = config.get('word_hidden_dim', 128)
    model = BiLSTM_CRF(
        vocab_size=vocab_size,
        char_vocab_size=char_vocab_size,
        embedding_dim=embedding_dim,
        char_embedding_dim=char_embedding_dim,
        char_hidden_dim=char_hidden_dim,
        word_hidden_dim=word_hidden_dim,
        tagset_size=tagset_size,
        token2idx=token2idx,
        char2idx=char2idx,
        label2idx=label2idx,
    )
    model.load_state_dict(checkpoint['model_state_dict'], strict=True)
    if device is None:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model = model.to(device)
    model.eval()
    return model, token2idx, char2idx, label2idx, config


_EMPTY_PREDICTION = {'product': None, 'version': None, 'tokens': [], 'labels': []}


def _decode_labels(tokens, prediction, idx2label):
    """Etiket dizisinden ürün ve sürüm parçalarını toplar."""
    product, version, labels = [], [], []
    for token, label_idx in zip(tokens, prediction):
        label = idx2label.get(int(label_idx), 'O')
        labels.append(label)
        if label in ('B-PRODUCT', 'I-PRODUCT'):
            product.append(token)
        elif label in ('B-VERSION', 'I-VERSION'):
            version.append(token)
    return {
        'product': ' '.join(product) if product else None,
        'version': ' '.join(version) if version else None,
        'tokens': tokens,
        'labels': labels,
    }


def predict_batch(texts, model, token2idx, char2idx, label2idx,
                  max_len=200, max_word_length=20, device=None):
    """Birden çok CVE metnini TEK ileri geçişte çözümler.

    CRF'in Viterbi çözümlemesi dizi uzunluğu boyunca Python döngüsü çalıştırır;
    metinleri tek tek vermek bu döngüyü metin sayısı kadar tekrarlar. Toplu
    çağrı döngüyü bir kez çalıştırıp GPU'yu gerçekten doldurur.

    Returns: girdiyle aynı sırada tahmin sözlükleri listesi.
    """
    if not texts:
        return []
    if device is None:
        device = next(model.parameters()).device
    model.eval()

    tokenized = [(t or '').split() for t in texts]
    # Boş metinler CRF maskesini geçersiz kılar (ilk adım False olamaz); ayrılır.
    usable = [i for i, toks in enumerate(tokenized) if toks]
    if not usable:
        return [dict(_EMPTY_PREDICTION) for _ in texts]

    words_batch, chars_batch = [], []
    for i in usable:
        tokens = tokenized[i]
        token_ids = [token2idx.get(w.lower(), token2idx['UNK']) for w in tokens]
        words_batch.append(pad_sequences([token_ids], maxlen=max_len)[0])
        chars_batch.append(
            np.array(
                sentence_to_char_ids(' '.join(tokens), char2idx, max_len, max_word_length),
                dtype=np.int32,
            )
        )

    words_tensor = torch.tensor(np.array(words_batch), dtype=torch.long, device=device)
    chars_tensor = torch.tensor(np.array(chars_batch), dtype=torch.long, device=device)
    with torch.no_grad():
        predictions = model(words_tensor, chars_tensor)

    idx2label = model.idx2label
    results = [dict(_EMPTY_PREDICTION) for _ in texts]
    for slot, prediction in zip(usable, predictions):
        results[slot] = _decode_labels(tokenized[slot], prediction, idx2label)
    return results


def predict_cve(text, model, token2idx, char2idx, label2idx,
                max_len=200, max_word_length=20, device=None):
    """Tek CVE metninden ürün ve sürüm çıkarır."""
    return predict_batch(
        [text], model, token2idx, char2idx, label2idx, max_len, max_word_length, device
    )[0]
