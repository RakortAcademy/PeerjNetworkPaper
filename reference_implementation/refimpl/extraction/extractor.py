"""
CVE açıklamasından ürün + sürüm çıkarımı.

Üç katman, sırayla denenir:
  1. BiLSTM-CRF   — eğitilmiş NER modeli
  2. Kural tabanlı — model ürün bulamazsa bilinen kalıplar
  3. Agresif regex — son çare

Çıktı `check_version_in_range` ve `merge_constraints_into_cve_info`
tarafından beklenen sözlük biçimindedir.
"""

import logging
import os
import re
from .architecture import load_checkpoint, predict_batch
from .confidence import calculate_confidence
from .version_scheme import infer_version_scheme
from .rule_based import RuleBasedExtractor
from .aggressive_regex import AggressiveRegexExtractor

logger = logging.getLogger(__name__)


def _batch_chunk_size() -> int:
    """Tek model çağrısında işlenecek en fazla CVE sayısı.

    Karakter tensörü batch × max_len × max_word_length büyüklüğünde; Orin'in
    paylaşımlı belleğinde birkaç yüz kaydın ötesi ayrılamıyor. 256 ölçümle
    seçildi: GPU'yu doyuruyor, taşırmıyor.
    """
    try:
        return max(1, int(os.environ.get("CVE_EXTRACT_BATCH", "256")))
    except (TypeError, ValueError):
        return 256


class BiLSTMCRFExtractor:
    """Eğitilmiş BiLSTM-CRF ile CVE açıklamasından ürün + sürüm çıkarır.

    Model ağırlıkları sınıf düzeyinde önbelleğe alınır; birden çok örnek
    oluşturmak modeli yeniden yüklemez.
    """

    _cached_model = None
    _cached_dicts = None
    _cached_config = None
    _cached_rule_extractor = None
    _cached_aggressive_extractor = None

    def __init__(self, model_dir=None, device=None):
        if BiLSTMCRFExtractor._cached_model is not None:
            self.model = BiLSTMCRFExtractor._cached_model
            self.token2idx = BiLSTMCRFExtractor._cached_dicts[0]
            self.char2idx = BiLSTMCRFExtractor._cached_dicts[1]
            self.label2idx = BiLSTMCRFExtractor._cached_dicts[2]
            self.config = BiLSTMCRFExtractor._cached_config or {}
            self.rule_extractor = BiLSTMCRFExtractor._cached_rule_extractor
            self.aggressive_extractor = BiLSTMCRFExtractor._cached_aggressive_extractor
            return
        if model_dir is None:
            # Reference implementation: no serving directory. The checkpoint is
            # given explicitly or through REFIMPL_MODEL_PATH (file or directory).
            model_dir = os.environ.get("REFIMPL_MODEL_PATH", "").strip()
            if not model_dir:
                raise FileNotFoundError(
                    "No tagger checkpoint: pass model_dir or set REFIMPL_MODEL_PATH. "
                    "Train a small one with `python -m refimpl.training.train "
                    "--data example_data/synthetic_training.jsonl --output example_data/tiny_model`."
                )
        self.model, self.token2idx, self.char2idx, self.label2idx, self.config = load_checkpoint(
            model_dir, device=device
        )
        # Reference implementation: register the checkpoint file so the extraction
        # cache key carries the weights digest (see refimpl.engine_identity).
        from refimpl import engine_identity

        engine_identity.register_checkpoint(
            model_dir if os.path.isfile(model_dir) else os.path.join(model_dir, "bilstm_crf.pth")
        )
        BiLSTMCRFExtractor._cached_model = self.model
        BiLSTMCRFExtractor._cached_dicts = (self.token2idx, self.char2idx, self.label2idx)
        BiLSTMCRFExtractor._cached_config = self.config
        
        # Initialize rule-based fallback extractor
        self.rule_extractor = RuleBasedExtractor()
        BiLSTMCRFExtractor._cached_rule_extractor = self.rule_extractor
        
        # Initialize aggressive fallback extractor
        self.aggressive_extractor = AggressiveRegexExtractor()
        BiLSTMCRFExtractor._cached_aggressive_extractor = self.aggressive_extractor
        
        logger.info("BiLSTM-CRF modeli yüklendi: %s", model_dir)

    def extract(self, cve_description, cve_id=None):
        """Tek CVE açıklamasından ürün + sürüm çıkarır."""
        return self.extract_batch([cve_description], [cve_id])[0]

    def extract_batch(self, descriptions, cve_ids=None):
        """Birden çok açıklamayı TEK model çağrısıyla işler.

        Tarama başına onlarca CVE bakıldığı için toplu çağrı belirleyici:
        CRF çözümlemesi dizi boyunca Python döngüsü çalıştırır ve tek tek
        çağrıldığında bu döngü her CVE için baştan döner.
        """
        if not descriptions:
            return []
        ids = list(cve_ids or [None] * len(descriptions))

        # Batch parçalara bölünür: karakter tensörü (batch × 200 × 20) GPU'da
        # hızla büyür ve aday sayısı üst sınırı kalktığından tek çağrıda binlerce
        # CVE gelebiliyor; binlerce adaylı bir ürün (ör. bir işletim sistemi
        # çekirdeği) parçalama olmadan GPU belleğini taşırır.
        chunk = _batch_chunk_size()
        predictions = []
        for start in range(0, len(descriptions), chunk):
            predictions.extend(
                predict_batch(
                    descriptions[start:start + chunk],
                    self.model,
                    self.token2idx,
                    self.char2idx,
                    self.label2idx,
                    max_len=self.config.get('max_len', 200),
                    max_word_length=self.config.get('max_word_length', 20),
                )
            )

        return [
            self._build_result(pred, description, cve_id)
            for pred, description, cve_id in zip(predictions, descriptions, ids)
        ]

    def _build_result(self, pred, cve_description, cve_id):
        """Model tahminini yedek katmanlarla tamamlayıp çıktı sözlüğünü kurar."""
        products = [pred['product']] if pred.get('product') else []
        versions = [pred['version']] if pred.get('version') else []

        extraction_method = 'bilstm-crf'
        fallback_confidence = None

        # Katman 2: model ürün bulamadıysa kural tabanlı çıkarım
        if not products:
            rule_result = self.rule_extractor.extract_product(cve_description)
            if rule_result['product']:
                products = [rule_result['product']]
                extraction_method = f"bilstm-crf+{rule_result['method']}"
                fallback_confidence = rule_result['confidence']
            else:
                # Katman 3: agresif regex (son çare)
                aggressive_result = self.aggressive_extractor.extract_product(cve_description)
                if aggressive_result['product']:
                    products = [aggressive_result['product']]
                    extraction_method = f"bilstm-crf+{aggressive_result['method']}"
                    fallback_confidence = aggressive_result['confidence']

        entities = {'products': products, 'versions': versions}
        out = self._convert_to_json(entities, cve_id, cve_description)
        out['is_binary'] = self._is_binary(out)
        out['extraction_method'] = extraction_method

        if fallback_confidence is not None:
            # Yedek yöntemler için güveni bir miktar düşür.
            out['confidence'] = min(out['confidence'], fallback_confidence * 0.95)

        return out

    def _convert_to_json(self, entities, cve_id, description):
        app_name = None
        if entities['products']:
            app_name = self._clean_product(entities['products'][0])
        version_info = self._extract_version_info(entities['versions'], description)

        platform = self._infer_platform(description)

        # Build JSON output
        json_output = {
            'cve_id': cve_id,
            'app_name': app_name,
            'app_version': version_info.get('exact'),
            'less_than': version_info.get('less_than'),
            'less_than_or_equal': version_info.get('less_than_or_equal'),
            'greater_equal': version_info.get('greater_equal'),
            'platform': platform,
            'confidence': 0.0,  # Will be calculated below
            'raw_entities': entities,
        }

        # Infer version scheme: build (e.g. 8684) vs semantic (e.g. 1.6) — so we don't compare incomparable versions
        json_output['version_scheme'] = infer_version_scheme(json_output)

        # Calculate confidence score
        json_output['confidence'] = calculate_confidence(json_output, description)

        return json_output

    def _clean_product(self, product):
        if not product:
            return None
        product = re.sub(r'\.(This|The|It|In|An|A)$', '', product, flags=re.IGNORECASE)
        return product.strip('.,;:')

    def _infer_platform(self, description):
        if not description:
            return "all"
        d = description.lower()
        if re.search(r'\b(for\s+)?windows\b', d) or re.search(r'\bwin\d+\b', d):
            return "windows"
        if re.search(r'\b(for\s+)?linux\b', d) or re.search(r'\bgnu/linux\b', d):
            return "linux"
        if re.search(r'\b(for\s+)?mac\s+os\b', d) or re.search(r'\bmacos\b', d) or re.search(r'\bos\s+x\b', d):
            return "mac"
        if re.search(r'\b(for\s+)?android\b', d):
            return "others"
        if re.search(r'\b(for\s+)?ios\b', d) or re.search(r'\biphone\b', d) or re.search(r'\bipad\b', d):
            return "others"
        return "all"

    def _extract_version_info(self, versions, description):
        # Fallback: when model returns no versions, still parse description for "through", "prior to", etc.
        result = {'exact': None, 'less_than': None, 'less_than_or_equal': None, 'greater_equal': None}
        version_text = ' '.join(versions) if versions else ''
        full_text = f"{version_text} {description}".strip()
        if not full_text:
            return result
        
        # Pattern 0: before/prior to + date (e.g. "before 8/29/2019") — must run before version pattern
        m = re.search(r'(?:before|prior\s+to)\s+(\d{1,2}/\d{1,2}/\d{4})', full_text, re.IGNORECASE)
        if m:
            result['less_than'] = m.group(1).strip()
            return result
        m = re.search(r'(?:before|prior\s+to)\s+(\d{4}-\d{2}-\d{2})', full_text, re.IGNORECASE)
        if m:
            result['less_than'] = m.group(1).strip()
            return result
        
        # Pattern 1: "affecting versions prior to X" (NEW)
        m = re.search(r'affecting\s+versions?\s+(?:prior\s+to|before)\s+([vV]?[\d.]+)', full_text, re.IGNORECASE)
        if m:
            result['less_than'] = self._normalize_version(m.group(1))
            return result
        
        # Pattern 2: "in versions before X" (NEW)
        m = re.search(r'in\s+versions?\s+(?:prior\s+to|before)\s+([vV]?[\d.]+)', full_text, re.IGNORECASE)
        if m:
            result['less_than'] = self._normalize_version(m.group(1))
            return result
        
        # Pattern 3: before/prior to + version
        m = re.search(r'(?:before|prior\s+to)\s+(?:version\s+)?([vV]?[\d.]+)', full_text, re.IGNORECASE)
        if m:
            result['less_than'] = self._normalize_version(m.group(1))
            return result
        
        # Pattern 4: "X and prior versions" (NEW)
        m = re.search(r'([vV]?[\d.]+)\s+and\s+prior\s+versions?', full_text, re.IGNORECASE)
        if m:
            result['less_than_or_equal'] = self._normalize_version(m.group(1))
            return result
        
        # Pattern 5: "versions X and earlier" (NEW)
        m = re.search(r'versions?\s+([vV]?[\d.]+)\s+and\s+earlier', full_text, re.IGNORECASE)
        if m:
            result['less_than_or_equal'] = self._normalize_version(m.group(1))
            return result
        
        m = re.search(r'<=\s*([vV]?[\d.]+)', full_text)
        if m:
            result['less_than_or_equal'] = self._normalize_version(m.group(1))
            return result
        m = re.search(r'<\s*([vV]?[\d.]+)', full_text)
        if m:
            result['less_than'] = self._normalize_version(m.group(1))
            return result
        m = re.search(r'(?:through|up\s+to)\s+([vV]?[\d.]+)', full_text, re.IGNORECASE)
        if m:
            result['less_than_or_equal'] = self._normalize_version(m.group(1))
            return result
        m = re.search(r'([vV]?[\d.]+)\s+and\s+earlier', full_text, re.IGNORECASE)
        if m:
            result['less_than_or_equal'] = self._normalize_version(m.group(1))
            return result
        # "X.Y.Z and later" (e.g. CVE-2018-0701 "macOS 2.0.0 and later") → affected if version >= X.Y.Z
        m = re.search(r'([vV]?[\d.]+)\s+and\s+later', full_text, re.IGNORECASE)
        if m:
            result['greater_equal'] = self._normalize_version(m.group(1))
            return result
        m = re.search(r'(?:>=|from)\s+([vV]?[\d.]+)', full_text, re.IGNORECASE)
        if m:
            result['greater_equal'] = self._normalize_version(m.group(1))
        m = re.search(r'([vV]?[\d]+\.[\d]+(?:\.[\d]+)*)', version_text)
        if m and not result['less_than'] and not result['less_than_or_equal'] and not result['greater_equal']:
            result['exact'] = self._normalize_version(m.group(1))
        return result

    def _normalize_version(self, version_str):
        if not version_str:
            return None
        version_str = re.sub(r'^[vV]', '', version_str)
        version_str = re.sub(r'\)[,\s].*$', '', version_str)
        version_str = re.sub(r'\.+$', '', version_str)
        if len(version_str) > 20:
            version_str = version_str[:20]
        return version_str.strip()

    def _is_binary(self, json_output):
        has_product = json_output.get('app_name') is not None
        version_count = sum([
            1 if json_output.get('app_version') else 0,
            1 if json_output.get('less_than') else 0,
            1 if json_output.get('less_than_or_equal') else 0,
            1 if json_output.get('greater_equal') else 0
        ])
        return has_product and version_count <= 1
