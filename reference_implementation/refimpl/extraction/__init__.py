"""CVE metninden ürün + sürüm çıkarımı (BiLSTM-CRF + kural tabanlı yedekler).

Reference implementation note: the production package imported the extractor
(and therefore torch) eagerly. Here the import is left to the caller so that
`refimpl.extraction.constraints` and friends can be tested without torch.
"""
