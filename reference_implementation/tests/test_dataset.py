"""Eğitim verisi hazırlama testleri."""
from __future__ import annotations

from refimpl.training.dataset import (
    LABELS,
    build_vocabularies,
    create_bio_labels,
    fuzzy_find_entity,
    pad_sequences,
)


class TestFuzzyFindEntity:
    def test_exact_match(self):
        assert fuzzy_find_entity(["Apache", "Tomcat", "before", "9.0"], ["Apache", "Tomcat"]) == (0, 2)

    def test_missing_entity_returns_none(self):
        assert fuzzy_find_entity(["a", "b", "c"], ["zzzz"]) is None

    def test_empty_entity_returns_none(self):
        assert fuzzy_find_entity(["a"], []) is None


class TestBioLabels:
    def test_product_and_version_tagged(self):
        text = "Buffer overflow in Apache Tomcat 9.0.1 allows attackers"
        tokens, labels = create_bio_labels(text, "Apache Tomcat", "9.0.1")
        assert len(tokens) == len(labels)
        assert LABELS["B-PRODUCT"] in labels
        assert LABELS["I-PRODUCT"] in labels
        assert LABELS["B-VERSION"] in labels

    def test_placeholder_product_not_tagged(self):
        _, labels = create_bio_labels("Some generic text here", "unspecified", "")
        assert set(labels) == {LABELS["O"]}

    def test_labels_align_with_tokens(self):
        text = "Issue in OpenSSL 1.0.1g"
        tokens, labels = create_bio_labels(text, "OpenSSL", "1.0.1g")
        assert labels[tokens.index("OpenSSL")] == LABELS["B-PRODUCT"]


class TestVocabularies:
    def test_min_freq_filters_rare_words(self):
        records = [
            {"text": "common word here", "product": "x", "version": ""},
            {"text": "common word there", "product": "x", "version": ""},
        ]
        token2idx, _, label2idx = build_vocabularies(records, min_word_freq=2)
        assert "common" in token2idx and "word" in token2idx
        assert "here" not in token2idx  # yalnızca bir kez geçiyor
        assert label2idx == LABELS

    def test_reserved_indices(self):
        token2idx, char2idx, _ = build_vocabularies(
            [{"text": "a b", "product": "", "version": ""}]
        )
        assert token2idx["PAD"] == 0 and token2idx["UNK"] == 1
        assert char2idx["PAD"] == 0 and char2idx["UNK"] == 1


class TestPadding:
    def test_pads_short_sequence(self):
        out = pad_sequences([[1, 2, 3]], maxlen=5)
        assert out.shape == (1, 5)
        assert list(out[0]) == [1, 2, 3, 0, 0]

    def test_truncates_long_sequence(self):
        out = pad_sequences([[1, 2, 3, 4, 5]], maxlen=3)
        assert list(out[0]) == [1, 2, 3]
