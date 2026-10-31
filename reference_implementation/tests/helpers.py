"""Test doubles and fixtures shared by the reference-implementation tests."""
from __future__ import annotations

from pathlib import Path

from refimpl import extraction_cache, store
from refimpl.corpus import InMemoryCorpus

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "example_data" / "synthetic_corpus.jsonl"


def load_synthetic_corpus() -> InMemoryCorpus:
    corpus = InMemoryCorpus.load(CORPUS_PATH)
    store.use_corpus(corpus)
    extraction_cache.clear()
    return corpus


class NoModelExtractor:
    """Test double for the tagger: the production extractor's result construction
    (`_build_result` → rule-based layer 2, aggressive-regex layer 3, operator
    regexes, confidence, version scheme) with the neural layer returning no spans.

    It subclasses nothing and loads nothing, so engine tests run without torch or
    a checkpoint. It is a TEST DOUBLE, not part of the method: the production
    engine always consults the BiLSTM-CRF first.
    """

    def __init__(self) -> None:
        from refimpl.extraction.aggressive_regex import AggressiveRegexExtractor
        from refimpl.extraction.extractor import BiLSTMCRFExtractor
        from refimpl.extraction.rule_based import RuleBasedExtractor

        self._impl = BiLSTMCRFExtractor.__new__(BiLSTMCRFExtractor)
        self._impl.rule_extractor = RuleBasedExtractor()
        self._impl.aggressive_extractor = AggressiveRegexExtractor()
        self.calls = 0

    def extract(self, description, cve_id=None):
        return self.extract_batch([description], [cve_id])[0]

    def extract_batch(self, descriptions, cve_ids=None):
        ids = list(cve_ids or [None] * len(descriptions))
        self.calls += len(descriptions)
        empty = {"product": None, "version": None, "tokens": [], "labels": []}
        return [self._impl._build_result(dict(empty), d, c) for d, c in zip(descriptions, ids)]
