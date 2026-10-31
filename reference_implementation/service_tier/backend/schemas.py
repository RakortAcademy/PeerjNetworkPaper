"""API istek/yanıt şemaları."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

ScanStatus = Literal["THREAT", "SAFE", "UNCERTAIN", "NOT_FOUND"]
JobStatus = Literal["PENDING", "RUNNING", "DONE", "FAILED"]


class ScanItem(BaseModel):
    """Taranacak tek bir uygulama.

    `vendor` ve `operating_system` belirsiz adları çözer: "Calendar" tek başına
    onlarca satıcıda bulunur ve ikisi de verilmezse tarama UNCERTAIN döner.
    """

    product: str = Field(..., min_length=1, max_length=300, examples=["Apache Tomcat"])
    version: str = Field(..., min_length=1, max_length=100, examples=["9.0.1"])
    vendor: Optional[str] = Field(
        None, max_length=150, description="Üretici — jenerik adları ayırt eder",
        examples=["Apple"],
    )
    operating_system: Optional[str] = Field(
        None, max_length=80, description="Uç noktanın işletim sistemi",
        examples=["macOS"],
    )
    platform: Optional[str] = Field(
        None, max_length=50, description="windows | linux | macos ... (operating_system ile eşdeğer)"
    )

    @field_validator("product", "version")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("boş olamaz")
        return v

    @field_validator("vendor", "operating_system", "platform")
    @classmethod
    def _strip_optional(cls, v: Optional[str]) -> Optional[str]:
        return (v or "").strip() or None


class ScanRequest(BaseModel):
    """Tek ya da çoklu tarama isteği.

    `items` verilirse toplu tarama yapılır; verilmezse gövdenin kendisi tek
    kalem olarak değerlendirilir.
    """

    items: Optional[List[ScanItem]] = None
    product: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    platform: Optional[str] = None
    use_cache: bool = True

    def normalized_items(self) -> List[ScanItem]:
        if self.items:
            return self.items
        if self.product and self.version:
            return [
                ScanItem(
                    product=self.product,
                    version=self.version,
                    vendor=self.vendor,
                    operating_system=self.operating_system,
                    platform=self.platform,
                )
            ]
        return []


class RemediationLink(BaseModel):
    url: str
    #: vendor-advisory | patch | mitigation | release-notes | third-party-advisory
    kind: str
    name: Optional[str] = None


class Remediation(BaseModel):
    """Bir açık için "ne yapmalıyım" cevabı.

    `fixed_version` ile `after_version` bilerek AYRI: birincisi "bu sürüme
    çıkın" demektir, ikincisi yalnızca "bu sürüm hâlâ etkileniyor" bilgisidir.
    CVE `<= X` diyorsa düzeltmenin X+1 olduğunu varsayamayız — dal terk edilmiş
    de olabilir — ve uydurulmuş bir hedef müşteriyi hâlâ açık bir sürüme
    yönlendirir.
    """
    action: str
    summary_tr: str
    fixed_version: Optional[str] = None
    after_version: Optional[str] = None
    #: "osv" ise düzeltilmiş sürüm doğrudan yazılıydı; yoksa CVE sınırından türetildi.
    fix_source: Optional[str] = None
    solution: Optional[str] = None
    links: List[RemediationLink] = Field(default_factory=list)


class RecommendedUpgrade(BaseModel):
    """Açıkları kapatan hedef sürüm(ler).

    `target_version` müşterinin bakım dalında kalır (düşük riskli); `latest_version`
    dal değiştirerek daha çoğunu kapatır. İkisi ayrı çünkü farklı büyüklükte
    kararlar (üretimdeki düzeltme modülü bu pakette yok).
    """
    target_version: str
    closes: int
    unresolved: int
    summary_tr: str
    latest_version: Optional[str] = None
    latest_closes: Optional[int] = None


class ThreatRisk(BaseModel):
    """Önceliklendirme sinyalleri.

    Üçü de ayrı ayrı taşınır çünkü farklı şeyler söylerler: KEV bir GÖZLEM
    ("sömürülüyor"), EPSS bir TAHMİN ("sömürülebilir"), CVSS ise ŞİDDET
    ("sömürülürse ne olur"). Tek sayıya indirgemek bu ayrımı siler.
    """
    #: acil | yüksek | orta | düşük
    priority: str = "düşük"
    priority_reason_tr: str = ""

    #: CISA'nın "vahşi doğada sömürüldüğü bilinen" kataloğunda mı?
    kev: bool = False
    kev_due_date: Optional[str] = None
    kev_added: Optional[str] = None
    kev_action: Optional[str] = None
    ransomware: bool = False

    #: 30 gün içinde sömürülme olasılığı (0..1) ve diğer CVE'lere göre yüzdelik.
    epss: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None

    cvss: Optional[float] = None
    cvss_severity: Optional[str] = None
    #: Puanın NEDENİ: "AV:N/PR:N/UI:N" = ağdan, kimlik doğrulamasız, etkileşimsiz.
    cvss_vector: Optional[str] = None

    #: Zayıflık türü (CWE-89 = SQL enjeksiyonu vb.)
    cwes: List[str] = Field(default_factory=list)
    #: Referanslar arasında yayımlanmış sömürü kodu var mı?
    exploit_known: bool = False


class RiskSummary(BaseModel):
    """Ürün düzeyinde tek bakışta risk — "340 açık" yerine "3'ü acil"."""
    total: int = 0
    counts: Dict[str, int] = Field(default_factory=dict)
    kev: int = 0
    ransomware: int = 0
    top_cves: List[str] = Field(default_factory=list)
    earliest_due_date: Optional[str] = None
    summary_tr: str = ""


class SupportStatus(BaseModel):
    """Sürümün bulunduğu bakım dalı hâlâ destekleniyor mu?

    Bu bir CVE bilgisi değil ama çoğu zaman daha keskin: destek biten bir dalda
    kaç açık olduğunun önemi yok, hiçbiri kapanmayacak.

    `supported` üç değerlidir — `False` "destek bitti", `True` "sürüyor",
    `None` "satıcı bildirmemiş". Sonuncuyu `True` saymak biten desteği
    görünmez kılardı.
    """
    cycle: str
    supported: Optional[bool] = None
    eol_date: Optional[str] = None
    latest_in_cycle: Optional[str] = None
    lts: bool = False
    summary_tr: str = ""


class ThreatEntry(BaseModel):
    cve_id: str
    affected_product: Optional[str] = None
    constraint_type: Optional[str] = None
    constraint_version: Optional[str] = None
    your_version: Optional[str] = None
    match_score: Optional[float] = None
    reason: Optional[str] = None
    decision_explanation: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[Remediation] = None
    risk: Optional[ThreatRisk] = None


class ScanResult(BaseModel):
    product: str
    version: str
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    platform: Optional[str] = None
    ambiguous_product: bool = False
    status: ScanStatus
    safety_score: int
    scanned_cves: int = 0
    threats: List[ThreatEntry] = Field(default_factory=list)
    uncertain_items: List[Dict[str, Any]] = Field(default_factory=list)
    safe_reasons: List[Dict[str, Any]] = Field(default_factory=list)
    decision_summary: Optional[Dict[str, Any]] = None
    recommended_upgrade: Optional[RecommendedUpgrade] = None
    risk_summary: Optional[RiskSummary] = None
    support: Optional[SupportStatus] = None
    scanned_cve_ids: List[str] = Field(default_factory=list)
    model_version: Optional[str] = None
    cached: bool = False


class InventorySummary(BaseModel):
    """Gönderilen listede ne kadar tekrar olduğunu gösterir."""

    received: int = 0
    unique: int = 0
    duplicates: int = Field(0, description="Birebir aynı olduğu için tekrar taranmayan kalem")
    product_groups: int = Field(0, description="Hazırlığı paylaşan ürün sayısı")


class ScanResponse(BaseModel):
    results: List[ScanResult]
    elapsed_ms: int
    cached_count: int = 0
    inventory: Optional[InventorySummary] = None


class ScanQueued(BaseModel):
    """Asenkron tarama yanıtı — sonuç `result_url` ile alınır."""

    job_id: str
    status: JobStatus
    total: int
    poll_url: str
    result_url: str


class JobCreateRequest(BaseModel):
    items: List[ScanItem] = Field(..., min_length=1)


class JobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus
    total: int


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    total: int
    completed: int
    failed: int
    attempts: int = Field(
        0, description="Job kaç kez alındı — restart sonrası devam edildiyse 1'den büyük"
    )
    error: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class JobItemResult(BaseModel):
    position: int
    product: str
    version: str
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    platform: Optional[str] = None
    status: Optional[str] = None
    cached: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobResultResponse(BaseModel):
    job_id: str
    status: JobStatus
    total: int
    completed: int
    failed: int
    items: List[JobItemResult]


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    model_loaded: bool
    model_version: str
    database: bool
    cve_db: bool
    cve_store: Dict[str, Any] = Field(default_factory=dict)
    cache: Dict[str, Any] = Field(default_factory=dict)


# --- yönetim paneli --------------------------------------------------------

class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120, examples=["Example client"])
    note: str = Field("", max_length=500)
    expires_at: Optional[datetime] = None


class ApiKeyInfo(BaseModel):
    id: int
    name: str
    key_prefix: str
    active: bool
    note: str = ""
    request_count: int = 0
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None


class ApiKeyCreated(ApiKeyInfo):
    # Düz anahtar yalnızca oluşturma yanıtında döner; saklanmadığı için
    # tekrar gösterilemez.
    key: str


class ScanRecord(BaseModel):
    """Önbellekteki bir tarama kaydının özeti (panel listesi)."""

    id: int
    product: str
    version: str
    platform: str = ""
    status: str
    safety_score: int = 0
    threat_count: int = 0
    scanned_cves: int = 0
    hit_count: int = 0
    model_version: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class ScanListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: List[ScanRecord]


class ScanDetail(ScanRecord):
    """Bir taramanın ÖZETİ — bulgu listeleri hariç.

    Tek tarama binlerce bulgu taşıyabildiği için (yüksek CVE sayılı bir
    ürün: on binlerce kayıt, megabaytlarca JSON) listeler yanıtta taşınmaz; `/admin/scans/{id}/findings` ile sayfa
    sayfa okunur. `counts` her kovanın gerçek boyutunu verir.
    """

    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    product_cleaned: Optional[str] = None
    ambiguous_product: bool = False
    cve_candidates_total: Optional[int] = None
    decision_summary: Optional[Dict[str, Any]] = None
    recommended_upgrade: Optional[RecommendedUpgrade] = None
    risk_summary: Optional[RiskSummary] = None
    support: Optional[SupportStatus] = None
    counts: Dict[str, int] = Field(
        default_factory=dict, description="Kova başına toplam bulgu sayısı"
    )


class ManualScanItem(BaseModel):
    """Panelden yapılan taramanın kalem özeti — bulgular ayrı sayfalanır."""

    product: str
    version: str
    vendor: Optional[str] = None
    operating_system: Optional[str] = None
    status: ScanStatus
    safety_score: int = 0
    scanned_cves: int = 0
    ambiguous_product: bool = False
    cached: bool = False
    counts: Dict[str, int] = Field(default_factory=dict)
    decision_summary: Optional[Dict[str, Any]] = None
    recommended_upgrade: Optional[RecommendedUpgrade] = None
    risk_summary: Optional[RiskSummary] = None
    support: Optional[SupportStatus] = None
    scan_id: Optional[int] = Field(
        None, description="Bulguları /admin/scans/{id}/findings ile sayfalamak için"
    )


class ManualScanResponse(BaseModel):
    results: List[ManualScanItem]
    elapsed_ms: int
    cached_count: int = 0
    inventory: Optional[InventorySummary] = None


class FindingPage(BaseModel):
    """Bir taramanın bulgularından tek sayfa."""

    scan_id: int
    bucket: str
    total: int
    limit: int
    offset: int
    items: List[Dict[str, Any]] = Field(default_factory=list)


class CveListItem(BaseModel):
    """CVE deposu gezinme satırı — açıklama kısaltılmaz, panel kırpar."""

    cve_id: str
    description: str = ""
    published_at: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    affected_rows: int = 0
    products: Optional[str] = None


class CveListResponse(BaseModel):
    total: int
    total_estimated: bool = Field(
        False, description="Filtresiz sayım planlayıcı tahminidir; tam sayım değil"
    )
    limit: int
    offset: int
    items: List[CveListItem]


class CveAffectedRow(BaseModel):
    product: str = ""
    vendor: str = ""
    version: str = ""
    less_than: str = ""
    less_than_or_equal: str = ""
    greater_equal: str = ""


class CveDetail(BaseModel):
    cve_id: str
    description: str = ""
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    source: str = ""
    affected: List[CveAffectedRow] = Field(default_factory=list)
    #: Tek CVE'ye bakan kişi de "ne kadar acil / nasıl kapatılır" diye soruyor.
    risk: Optional[ThreatRisk] = None
    remediation: Optional[Remediation] = None


class LogResponse(BaseModel):
    name: str
    lines: List[str]
    available: List[str] = Field(default_factory=list)


class SyncRunInfo(BaseModel):
    id: int
    source: str
    status: str
    cves_seen: int = 0
    cves_added: int = 0
    cves_updated: int = 0
    rows_written: int = 0
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class OverviewResponse(BaseModel):
    usage: Dict[str, Any]
    cve_store: Dict[str, Any]
    cache: Dict[str, Any]
    jobs: Dict[str, Any]
    scan_totals: Dict[str, int] = Field(default_factory=dict)
    model_version: str = ""
