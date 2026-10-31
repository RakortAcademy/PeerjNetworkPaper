// Tarama motoru — ürün grupları GERÇEK paralellikte işlenir.
//
// Python tarafında bu döngü GIL yüzünden seri kalıyordu: ölçümde 12 çekirdeğin
// yalnızca 1,1'i kullanılıyordu. Go'da goroutine'ler CPU'ya gerçekten yayılıyor.
//
// Model çıkarımı önce `cve_extractions` tablosundan okunur: çıkarım CVE metnine
// bağlı, sürüme değil, bu yüzden bir kez hesaplanıp saklanıyor. Eksik kalanlar
// ONNX'e verilen modelle burada hesaplanır ve önbelleğe yazılır (bkz. model.go).
// Model yüklenmemişse tarama düşmez; eksikler `Missing` ile bildirilir.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Item, envanterden gelen tek bir kalem.
type Item struct {
	Product         string `json:"product"`
	Version         string `json:"version"`
	Vendor          string `json:"vendor,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

// Finding, tek bir CVE hakkındaki karar.
//
// Aynı yapı üç listede de kullanılır (tehdit / güvenli / belirsiz): alanların
// çoğu ortak ve üç ayrı tür tutmak Python'daki sözlük biçimiyle ayrışma riski
// yaratırdı.
type Finding struct {
	CVEID           string       `json:"cve_id"`
	Remediation     *Remediation `json:"remediation,omitempty"`
	AffectedProduct string       `json:"affected_product,omitempty"`
	ConstraintType  string       `json:"constraint_type,omitempty"`
	Constraint      string       `json:"constraint_version,omitempty"`
	YourVersion     string       `json:"your_version,omitempty"`
	Reason          string       `json:"reason,omitempty"`
	DecisionSource  string       `json:"decision_source,omitempty"`
	Risk            *Risk        `json:"risk,omitempty"`
	Description     string       `json:"description,omitempty"`
	// Belirsiz kayıtlarda gerekçe ayrı alanda taşınır — Python sözleşmesi böyle
	// ve panel `uncertain_reason` okuyor.
	UncertainReason string `json:"uncertain_reason,omitempty"`
	// "Farklı ürün" olduğu için elenen kayıt: ürünün BULUNDUĞUNA kanıt değil.
	NotApplicable bool `json:"not_applicable,omitempty"`
	// Sürüm şemaları kıyaslanamadı — belirsizlik SAYILMAZ (bkz. finalize).
	NonComparable bool `json:"non_comparable,omitempty"`
}

// Result, bir envanter kalemi için sonuç.
type Result struct {
	Product string `json:"product"`
	Version string `json:"version"`
	// İstek alanları yanıtta AYNEN geri döner: müşteri 500 kalemlik bir toplu
	// yanıtı kendi envanteriyle eşlerken ürün adı tek başına yetmiyor (aynı ad
	// farklı satıcı/platformda ayrı kalem).
	Vendor          string `json:"vendor,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	Platform        string `json:"platform,omitempty"`
	// Ad jenerik ve satıcı/OS verilmemiş: hangi ürün olduğu belirlenemedi.
	AmbiguousProduct bool `json:"ambiguous_product,omitempty"`

	Status       string    `json:"status"`
	SafetyScore  int       `json:"safety_score"`
	Threats      []Finding `json:"threats"`
	SafeReasons  []Finding `json:"safe_reasons"`
	UncertainRow []Finding `json:"uncertain_items"`
	SafeCount    int       `json:"n_safe"`
	Uncertain    int       `json:"n_uncertain"`
	Ignored      int       `json:"n_ignored"`
	Scanned      int       `json:"scanned_cves"`
	ScannedIDs   []string  `json:"scanned_cve_ids"`
	ModelVersion string    `json:"model_version,omitempty"`
	// Taranan TÜM adaylar ürün kimliği tutmadığı için elendi.
	AllRejected bool `json:"all_candidates_rejected,omitempty"`

	DecisionSummary *DecisionSummary `json:"decision_summary,omitempty"`
	// Kapılardan (satıcı/eklenti) elenenler ayrı sayılır: bunlar ürünün
	// BULUNDUĞUNA kanıt değil, farklı bir ürün oldukları için elendiler.
	gateSafeOther int
	gateSafeOS    int
	// Sürüm şemaları kıyaslanamadığı için karara varılamayanlar. Belirsizlik
	// sayılmazlar — bkz. `finalStatus`.
	nonComparable int
	Candidates    int `json:"cve_candidates_total"`
	// Çıkarımı olmayan CVE'ler — model henüz Go'da olmadığı için bildirilir.
	Missing            []string            `json:"needs_model,omitempty"`
	Note               string              `json:"note,omitempty"`
	RecommendedUpgrade *RecommendedUpgrade `json:"recommended_upgrade,omitempty"`
	Support            *SupportStatus      `json:"support,omitempty"`
	RiskSummary        *RiskSummary        `json:"risk_summary,omitempty"`

	// Düzeltme çıkarımı sınırlara ihtiyaç duyuyor; sonuçla birlikte taşınır.
	productNorm string
	bounds      map[string][]Bound
}

type Engine struct {
	db           *DB
	modelVersion string
	// Çıkarıcı İSTEĞE BAĞLI: yoksa eksik çıkarımlar `needs_model` ile
	// bildirilir ve tarama düşmez. Modelin yokluğu kararı bozmaz, yalnızca
	// o CVE'ler metin yolundan değerlendirilemez.
	extractor *Extractor
}

func NewEngine(db *DB, modelVersion string) *Engine {
	return &Engine{db: db, modelVersion: modelVersion}
}

// WithExtractor, model çıkarımını açar.
func (e *Engine) WithExtractor(ex *Extractor) *Engine {
	e.extractor = ex
	return e
}

// ScanBatch, kalemleri ÜRÜNE göre gruplar ve grupları paralel tarar.
//
// Paralellik grup düzeyindedir: aynı ürünün farklı sürümleri zaten tek hazırlığı
// paylaşıyor ve onları ayırmak o kazancı yok ederdi.
//
// Bir grup düşerse yalnızca o grup hata döner; kalan envanter taranmaya devam
// eder — tek bozuk ad yüzünden 150 kalemlik taramayı çöpe atmak orantısız.
func (e *Engine) ScanBatch(ctx context.Context, items []Item, workers int) []Result {
	type group struct {
		sample  Item
		targets []int
	}
	byProduct := map[string]*group{}
	order := []string{}
	for i, it := range items {
		key := strings.ToLower(strings.TrimSpace(it.Product)) + "|" +
			strings.ToLower(strings.TrimSpace(it.Vendor)) + "|" +
			strings.ToLower(strings.TrimSpace(it.OperatingSystem))
		g, ok := byProduct[key]
		if !ok {
			g = &group{sample: it}
			byProduct[key] = g
			order = append(order, key)
		}
		g.targets = append(g.targets, i)
	}

	out := make([]Result, len(items))
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, key := range order {
		g := byProduct[key]
		wg.Add(1)
		go func(g *group) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			prep, err := e.prepare(ctx, g.sample)
			for _, idx := range g.targets {
				if err != nil {
					out[idx] = Result{
						Product: items[idx].Product, Version: items[idx].Version,
						Status: "NOT_FOUND", Note: "scan_failed: " + err.Error(),
					}
					continue
				}
				// Her hedef KENDİ indeksine yazıyor; kilit gerekmiyor.
				decideDone := track("karar", 1)
				out[idx] = e.decide(prep, items[idx].Version)
				// Model damgası yanıtta: müşteri hangi model sürümünün karar
				// verdiğini görebilmeli, önbellek anahtarı da bunu taşıyor.
				out[idx].ModelVersion = e.modelVersion
				decideDone()
			}
		}(g)
	}
	wg.Wait()
	return out
}

// Enrich, taramadan SONRA çalışan zenginleştirmeler: risk sinyalleri, düzeltme
// önerisi ve destek durumu. Ayrı tutulmalarının nedeni hepsinin toplu sorgu
// yapması — kalem başına sormak aynı satırları defalarca çekerdi.
func (e *Engine) Enrich(ctx context.Context, results []Result, maxDetailed int) error {
	riskDone := track("risk sinyalleri", len(results))
	if err := e.AttachRisk(ctx, results); err != nil {
		riskDone()
		return err
	}
	riskDone()
	remDone := track("düzeltme önerisi", len(results))
	if err := e.AttachRemediation(ctx, results, maxDetailed); err != nil {
		remDone()
		return err
	}
	remDone()
	lifeDone := track("destek takvimi", len(results))
	defer lifeDone()
	today := time.Now().Format("2006-01-02")
	// Destek durumu ürün başına sorulur; aynı ürünün farklı sürümleri için
	// tekrar sormamak adına küçük bir önbellek tutulur.
	cache := map[string][]LifecycleCycle{}
	for i := range results {
		r := &results[i]
		r.RiskSummary = Summarize(r.Threats)
		cycles, ok := cache[r.productNorm]
		if !ok {
			var err error
			if cycles, err = e.db.LifecycleFor(ctx, r.productNorm); err != nil {
				return err
			}
			cache[r.productNorm] = cycles
		}
		// Destek durumu tehditlerden BAĞIMSIZ: destek biten bir dalda kaç açık
		// olduğunun önemi yok, hiçbiri kapanmayacak. SAFE sonuçlarda da bildirilir.
		r.Support = buildSupportStatus(cycles, CleanVersionString(r.Version), today)
	}
	// Açıklama metinleri ve karar özeti EN SONA kalır: özet baş referansı
	// açıklamanın şiddetine göre seçiyor, yani metinler yerine oturmadan
	// hesaplanamaz.
	if err := e.attachDescriptions(ctx, results, maxDetailed); err != nil {
		return err
	}
	for i := range results {
		results[i].DecisionSummary = BuildDecisionSummary(&results[i])
	}
	return nil
}

// attachDescriptions, satırlara CVE açıklamasını ekler.
//
// Yalnızca ilk `maxDetailed` satır: yüksek CVE sayılı bir ürün binlerce tehdit
// döndürebilir ve her satıra tam açıklama koymak yanıtı megabaytlara taşır. Karar özeti
// yalnızca baş referansın metnini kullandığı için bu sınır özeti bozmuyor.
func (e *Engine) attachDescriptions(ctx context.Context, results []Result, maxDetailed int) error {
	want := map[string]bool{}
	pick := func(rows []Finding) {
		for i := range rows {
			if maxDetailed > 0 && i >= maxDetailed {
				return
			}
			want[rows[i].CVEID] = true
		}
	}
	for i := range results {
		pick(results[i].Threats)
		pick(results[i].SafeReasons)
		pick(results[i].UncertainRow)
	}
	if len(want) == 0 {
		return nil
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	descs, err := e.db.DescriptionsFor(ctx, ids)
	if err != nil {
		return err
	}
	fill := func(rows []Finding) {
		for i := range rows {
			if maxDetailed > 0 && i >= maxDetailed {
				return
			}
			rows[i].Description = descs[rows[i].CVEID]
		}
	}
	for i := range results {
		fill(results[i].Threats)
		fill(results[i].SafeReasons)
		fill(results[i].UncertainRow)
	}
	return nil
}

// prepared, bir ürünün SÜRÜMDEN BAĞIMSIZ hazırlığı.
type prepared struct {
	item         Item
	productNorm  string
	soleFamily   string
	exactCatalog bool
	cleanName    string
	candidates   []Candidate
	bounds       map[string][]Bound
	extractions  map[string]Extraction
	missing      []string
	generic      bool
	updatePkg    bool
}

func (e *Engine) prepare(ctx context.Context, item Item) (*prepared, error) {
	p := &prepared{item: item}
	p.cleanName = CleanInventoryName(item.Product)
	if p.cleanName == "" {
		p.cleanName = item.Product
	}
	p.productNorm = NormalizeProductName(p.cleanName)

	if IsUpdatePackage(item.Product) {
		p.updatePkg = true
		return p, nil
	}
	// İşletim sisteminden satıcı çıkarımı YALNIZCA jenerik adlar içindir:
	// macOS'taki "Calendar" Apple'ın takvimidir, "Google Chrome" değildir.
	// Her ürüne uygulandığında Chrome'un tüm CVE'leri satıcı kapısından
	// eleniyordu.
	vendor := strings.TrimSpace(item.Vendor)
	if vendor == "" && IsGenericProductName(p.cleanName) {
		vendor = vendorFromOS(item.OperatingSystem)
		if vendor == "" {
			p.generic = true
			return p, nil
		}
	}
	p.item.Vendor = vendor

	searchDone := track("aday arama", 1)
	// Envanterdeki kısa adın katalogdaki TEK karşılığı. Envanterler ürün
	// adını CVE kataloğundan kısa yazar ("Acme" ↔ "Acme NAC") ve kimlik
	// tokenı kıyaslaması bunu FARKLI ürün sayıp tüm adayları eliyor.
	// Bağlamak yalnızca tek karşılık varsa güvenli — "MySQL" 17 ayrı ürüne
	// çözülüyor ve orada bağlamak bir bileşenin açığını tüm aileye yayardı.
	if names, err := e.db.ProductFamilyNames(ctx, p.productNorm); err == nil {
		for _, n := range names {
			if n == p.productNorm {
				// Katalog bu ürünü KENDİ adıyla tanıyor.
				p.exactCatalog = true
				break
			}
		}
		if !IsGenericProductName(p.cleanName) && len(names) == 1 && names[0] != p.productNorm {
			p.soleFamily = names[0]
		}
	}

	cands, err := e.db.SearchCandidates(ctx, p.productNorm, vendor)
	searchDone()
	if err != nil {
		return nil, err
	}
	p.candidates = cands
	if len(cands) == 0 {
		return p, nil
	}

	ids := make([]string, len(cands))
	for i, c := range cands {
		ids[i] = c.CVEID
	}
	boundsDone := track("CNA sınırları", len(ids))
	cna, err := e.db.BoundsFor(ctx, ids, p.productNorm)
	boundsDone()
	if err != nil {
		return nil, err
	}
	cpeDone := track("NVD/CPE sınırları", len(ids))
	cpe, err := e.db.CPEBoundsFor(ctx, ids, p.productNorm)
	cpeDone()
	if err != nil {
		return nil, err
	}
	// NVD satırları SONA eklenir: karar "herhangi bir aralık kapsıyorsa THREAT"
	// kuralıyla verildiği için sıra tehdidi etkilemez, ama CNA'nın SAFE
	// gerekçesi öne çıkar.
	for id, rs := range cpe {
		cna[id] = append(cna[id], rs...)
	}
	p.bounds = cna

	// Açıklama özetleri önbellek doğrulaması için gerekli; metinler zaten
	// aday satırlarıyla birlikte geldiği için ek sorgu yok.
	hashes := make(map[string]string, len(cands))
	for _, c := range cands {
		hashes[c.CVEID] = DescriptionHash(c.Description)
	}
	exDone := track("çıkarım önbelleği", len(ids))
	ex, missing, err := e.db.ExtractionsFor(ctx, ids, e.modelVersion, hashes)
	exDone()
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 && e.extractor != nil {
		modelDone := track("MODEL çıkarımı", len(missing))
		produced, err := e.runModel(ctx, missing, hashes)
		modelDone()
		if err != nil {
			// Çıkarım düşerse tarama DÜŞMEZ: eksikler `needs_model` ile
			// bildirilir, sınır tabanlı kararlar zaten alınmış olur.
			log.Printf("model çıkarımı başarısız (%d CVE): %v", len(missing), err)
		} else {
			still := missing[:0]
			for _, id := range missing {
				if x, ok := produced[id]; ok {
					ex[id] = x
				} else {
					still = append(still, id)
				}
			}
			missing = still
		}
	}
	p.extractions, p.missing = ex, missing
	return p, nil
}

// runModel, önbellekte olmayan CVE'lerin çıkarımını hesaplar ve KALICI yazar.
//
// Yazmak önemli: aynı CVE onlarca üründe aday çıkıyor ve her taramada yeniden
// hesaplamak modelin maliyetini gereksiz yere tekrarlar.
func (e *Engine) runModel(ctx context.Context, cveIDs []string,
	hashes map[string]string) (map[string]Extraction, error) {
	descs, err := e.db.DescriptionsFor(ctx, cveIDs)
	if err != nil {
		return nil, err
	}
	ids, texts := make([]string, 0, len(cveIDs)), make([]string, 0, len(cveIDs))
	for _, id := range cveIDs {
		if d := descs[id]; d != "" {
			ids = append(ids, id)
			texts = append(texts, d)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	preds, err := e.extractor.ExtractBatch(texts)
	if err != nil {
		return nil, err
	}
	out := make(map[string]Extraction, len(ids))
	for i, id := range ids {
		out[id] = BuildExtraction(preds[i], texts[i])
	}
	if err := e.db.SaveExtractions(ctx, out, e.modelVersion, hashes); err != nil {
		// Yazma hatası çıkarımı geçersiz kılmaz; yalnızca bir dahakine
		// yeniden hesaplanır.
		log.Printf("çıkarım önbelleğe yazılamadı: %v", err)
	}
	return out, nil
}

var osVendor = map[string]string{
	"macos": "apple", "mac": "apple", "osx": "apple", "ios": "apple",
	"ipados": "apple", "windows": "microsoft", "win": "microsoft",
	"android": "google", "chromeos": "google",
}

func vendorFromOS(os string) string {
	key := strings.ToLower(nonWordRe.ReplaceAllString(os, ""))
	for prefix, vendor := range osVendor {
		if strings.HasPrefix(key, prefix) {
			return vendor
		}
	}
	return ""
}

func (e *Engine) decide(p *prepared, rawVersion string) Result {
	version := CleanVersionString(rawVersion)
	if version == "" {
		version = rawVersion
	}
	res := Result{Product: p.item.Product, Version: rawVersion, Status: "SAFE",
		Vendor: p.item.Vendor, OperatingSystem: p.item.OperatingSystem,
		Platform:   p.item.Platform,
		Candidates: len(p.candidates), Missing: p.missing,
		productNorm: p.productNorm, bounds: p.bounds}

	// Aşağıdaki üç erken çıkışın durum + puan değerleri Python `_decide` ile
	// BİREBİR aynı olmalı: puan API sözleşmesinde ve panelde görünüyor.
	if p.updatePkg {
		// Kurulu bir yama, açığın kendisi değil çözümüdür. Ürün sanılırsa adı
		// "Windows" ile eşleşir ve güncelleyicinin sürümü Windows derleme
		// numaralarıyla kıyaslanır.
		res.Status, res.SafetyScore = "NOT_FOUND", 0
		res.Note = "kurulu güncelleme/yama kaydı — ürün değil"
		res.DecisionSummary = plainSummary(res.Status, fmt.Sprintf(
			"'%s' bir uygulama değil, kurulu bir güncelleme/yama kaydı. "+
				"Yamaların kendi CVE'leri olmaz; taranacak ürün işletim sisteminin kendisidir.",
			p.item.Product))
		return res
	}
	if p.generic {
		res.Status, res.SafetyScore = "UNCERTAIN", 50
		res.AmbiguousProduct = true
		res.Note = "jenerik ad; vendor ya da operating_system gerekli"
		res.DecisionSummary = plainSummary(res.Status, fmt.Sprintf(
			"'%s' adı tek başına hangi ürün olduğunu belirlemiyor; birçok satıcıda "+
				"aynı adla uygulama var. Doğru tarama için vendor ya da "+
				"operating_system bilgisi gerekli.", p.item.Product))
		return res
	}
	if len(p.candidates) == 0 {
		res.Status, res.SafetyScore = "NOT_FOUND", 0
		return res
	}

	customerVendor := p.item.Vendor
	customerMajor := 0
	if pv := ParseVersion(version); pv != nil {
		customerMajor = pv.Major()
	}
	for _, c := range p.candidates {
		res.Scanned++
		res.ScannedIDs = append(res.ScannedIDs, c.CVEID)
		catalog := c.QualifiedProduct()
		trace := traced(c.CVEID)
		if trace {
			log.Printf("[iz] %s aday: katalog=%q satıcı=%q", c.CVEID, catalog, c.Vendor)
		}

		// 1. Ürün kimliği — bu CVE bu ürüne mi ait?
		//
		// Önce KATALOG adı (yapısal, güvenilir). Tutmazsa MODELİN metinden
		// çıkardığı ada düşülür: Quill++ CVE'leri katalogda
		// `quill-plus-plus` yazarken model "Quill++" çıkarıyor ve eşleşme
		// oradan geliyor. Bu yol olmadan böyle tehditlerin çoğu kaçar.
		matchName := catalog
		matchSource := "catalog"
		if !e.productMatches(catalog, p.cleanName, p.productNorm, p.soleFamily) {
			matchSource = "extracted"
			ex := p.extractions[c.CVEID]
			ok, _ := MatchExtractedName(ex.AppName, p.cleanName)
			if !ok {
				if trace {
					log.Printf("[iz] %s ELENDİ: ne katalog (%q) ne çıkarım (%q) '%s' ile eşleşti",
						c.CVEID, catalog, ex.AppName, p.cleanName)
				}
				res.Ignored++
				continue
			}
			matchName = strings.TrimSpace(ex.AppName)
		}

		// Katalog bu ürünü KENDİ adıyla tanıyorsa, CVE en az o kadar SPESİFİK
		// adlandırmalı. "inkwell notes" katalogda ayrı bir ürün olarak
		// var — yani CNA ayrımı yapabiliyor ve daha genel bir ad
		// ("Inkwell") kullanması o ürünü kastetmediği anlamına gelir.
		//
		// Denetim İKİ yola da uygulanır; yalnızca katalog yoluna bağlanırsa
		// eşleşmeler model çıkarımı yoluna kaçar.
		//
		// İki istisna:
		//   - Bitişik aile ("Woodgrove BrightwaveLinux" ↔ "Brightwave")
		//     token düzeyinde kapsamıyor; istisna olmasa gerçek tehditler düşer.
		//   - Platform tokenları aranmaz: "Proseware Driftguard Backup For Mac"
		//     kaydındaki "mac" CVE adında geçmez ama aynı üründür.
		// Jenerik adlarda CVE'nin ADI da BİREBİR tutmalı. "Music Player" gibi
		// bir ad zaten belirsiz; CVE'nin "Halcyon Music Player" demesi başka bir
		// satıcının ürününü kastettiği anlamına gelir. Kapsama ölçütü burada
		// yetmiyor: "halcyon music player" kimlik olarak "music player"ı kapsıyor.
		if IsGenericProductName(p.cleanName) && matchName != "" &&
			NormalizeProductName(matchName) != p.productNorm {
			if trace {
				log.Printf("[iz] %s ELENDİ (jenerik ad, CVE daha spesifik): %q ≠ %q",
					c.CVEID, matchName, p.cleanName)
			}
			res.Ignored++
			continue
		}

		if p.exactCatalog && !SameCompoundFamily(matchName, p.cleanName) &&
			!identityCovers(matchName, p.cleanName) {
			if trace {
				log.Printf("[iz] %s ELENDİ (katalog spesifikliği): %q, %q kadar spesifik değil",
					c.CVEID, matchName, p.cleanName)
			}
			res.Ignored++
			continue
		}
		// 2. Sürüm kararı — iki kaynak, ÖNCELİK sırası önemli.
		//
		//   a) yapısal sınırlar (CNA + NVD CPE) — en güvenilir
		//   b) model çıkarımı + açıklama regex katmanı
		//
		// İkisi de hesaplanır çünkü yapısal kaynaktan gelen "sürüm tam-sürüm
		// listesinde yok" (neq) kararı ZAYIFtır: CNA/NVD listeyi eksik
		// bırakmış olabilir. Böyle bir SAFE, metinden gelen THREAT'i
		// DÜŞÜREMEZ. Örnek: CPE kaydı yalnızca "quill++ 8.9.6.1" tam
		// sürümünü listeliyor, 8.8.9 listede yok diye SAFE denir, oysa
		// açıklama açıkça "This vulnerability is fixed in 8.9.6.2" diyor.
		boundsRes := ResolveBounds(version, p.bounds[c.CVEID])

		ex := p.extractions[c.CVEID]
		base := Constraints{LessThan: ex.LessThan, LessThanOrEqual: ex.LessThanOrEqual,
			GreaterEqual: ex.GreaterEqual, AppVersion: ex.AppVersion}
		merged := MergeConstraints(base, c.Description, c.VersionHint, customerMajor)
		// Sürüm ŞEMALARI farklıysa METİNden çıkan kısıt kıyaslanamaz:
		// "Automator 2.10" ile "ConnectWise Automate 2020.5.178" aynı sistemde
		// numaralanmıyor. Sayısal kıyas tehdit üretir.
		//
		// Ama bu YALNIZCA metin yolunu susturur — yapısal sınır kararı geçerli
		// kalır. İlk denemede burada `continue` edip sınırı da atmıştım ve
		// kaçan tehdit 20'den 34'e çıkmıştı.
		schemeMismatch := false
		var textRes *Resolution
		if merged.HasBounds() {
			if pv := ParseVersion(version); pv != nil {
				ref := merged.LessThan
				for _, alt := range []string{merged.LessThanOrEqual, merged.GreaterEqual, merged.AppVersion} {
					if ref != "" {
						break
					}
					ref = alt
				}
				if pr := ParseVersion(ref); pr != nil && VersionSchemeMismatch(pv, pr) {
					schemeMismatch = true
				}
			}
			if !schemeMismatch {
				textRes = ResolveSingleRange(version, merged.ToBound())
			}
		}

		// 3. Uygulanabilirlik kapıları (OS / web-eklenti / satıcı).
		//
		// Kapılar sürüm kararından SONRA çalışır ve sıra keyfî değil: metin
		// yolu zaten SAFE demişse kapı o kararı "farklı ürün" diye yeniden
		// etiketlemez, yalnızca yapısal sınırın THREAT'e YÜKSELTMESİNİ
		// engeller. Kapıyı önce çalıştırdığımda "Time Machine" ve "Stocks"
		// taramaları SAFE yerine NOT_FOUND dönüyordu: tek çözülmüş SAFE
		// kayıtları kapı kovasına düşüyor ve "hiç uygulanabilir CVE yok"
		// sayılıyorlardı.
		//
		// Kapılara YAPISAL ürün adı verilir, model çıktısı değil. Sınır
		// kaydındaki ad platform bilgisini taşıyor ("Microsoft Edge for
		// Android"); model metinden "Microsoft Edge (Chromium-based)"
		// çıkarıyor ve o adla OS kapısı yanmıyordu.
		gateProduct := matchName
		gateVendor := c.Vendor
		if bs := p.bounds[c.CVEID]; len(bs) > 0 && bs[0].Product != "" {
			gateProduct = bs[0].Product
			if bs[0].Vendor != "" {
				gateVendor = bs[0].Vendor
			}
			// Ürün alanı TEK BAŞINA kimlik taşımıyorsa satıcı öne eklenir.
			// Bazı kayıtlarda alan yalnızca "server" yazar (satıcı ayrı
			// sütunda, ör. "ravenmail"); kapıya "server" gidince hiçbir
			// kimlik kuralı çalışamaz ve sunucu CVE'leri masaüstü
			// istemcisine yazılır.
			if len(IdentityTokens(gateProduct)) == 0 && gateVendor != "" {
				gateProduct = gateVendor + " " + gateProduct
			}
		} else if catalog != "" {
			gateProduct = catalog
		}
		if g := ApplyGates(gateProduct, gateVendor, c.Description, p.item.Product,
			customerVendor, p.item.OperatingSystem); g != nil {
			if trace {
				log.Printf("[iz] %s KAPI %s: %s (ürün=%q satıcı=%q)",
					c.CVEID, g.Kind, g.Reason, gateProduct, gateVendor)
			}
			row := Finding{
				CVEID: c.CVEID, AffectedProduct: gateProduct, YourVersion: version,
				Reason: g.Reason, DecisionSource: "applicability_" + g.Kind,
			}
			switch {
			case textRes != nil && textRes.Verdict == "SAFE":
				// Çözülmüş SAFE olduğu gibi kalır — ürün BULUNDU ve sürüm
				// etkilenmiyor. Kovalanan tek şey yükseltmenin engellenmesi.
				row.Reason = textRes.Reason
				row.ConstraintType = textRes.ConstraintType
				row.Constraint = textRes.Constraint
				row.DecisionSource = "range_matcher"
			case g.Kind == "os":
				res.gateSafeOS++
				// OS uyuşmazlığı AYNI ürünü ilgilendirir; "farklı ürün" değil.
			default:
				res.gateSafeOther++
				row.NotApplicable = true
			}
			res.SafeReasons = append(res.SafeReasons, row)
			continue
		}

		if trace {
			log.Printf("[iz] %s sınır=%d kayıt, sınırKararı=%v metinKararı=%v şemaUyuşmazlığı=%v",
				c.CVEID, len(p.bounds[c.CVEID]), verdictOf(boundsRes), verdictOf(textRes), schemeMismatch)
		}
		// Yapısal sınır müşteri sürümünü etkilenen aralıkta gösteriyor olabilir;
		// ama METİN yolu THREAT demiyorsa bu bir YÜKSELTMEdir ve yükseltme
		// yalnızca ürün kimliği + platform kapılarını geçerse yapılır. Gevşek
		// eşleşmeler ("Agent", "Manager", "for Android") yükseltilmez —
		// bu kapı olmadan "Inkwell Notes" sorgusu "Litware Inkwell 2024"
		// CVE'lerini tehdit gösterir.
		if boundsRes != nil && boundsRes.Verdict == "THREAT" &&
			(textRes == nil || textRes.Verdict != "THREAT") {
			// Kapılara HAM envanter adı verilir, temizlenmiş hâli değil:
			// temizleme platform kelimesini atabiliyor ("Android Photo
			// Courier" → "photo courier") ve o zaman "müşterinin kendi
			// platformu metinde geçiyor" muafiyeti çalışmıyor ve gerçek
			// tehditler kaçar.
			raw := p.item.Product
			if !ProductIdentityOK(gateProduct, raw) ||
				PlatformMismatch(gateProduct, c.Description, raw, p.item.OperatingSystem) {
				if trace {
					log.Printf("[iz] %s YÜKSELTME ENGELLENDİ: kimlik=%v platform=%v",
						c.CVEID, ProductIdentityOK(gateProduct, raw),
						PlatformMismatch(gateProduct, c.Description, raw, p.item.OperatingSystem))
				}
				boundsRes = nil
			}
		}

		final, source := pickResolution(boundsRes, textRes)
		if trace {
			log.Printf("[iz] %s SONUÇ: %v (kaynak=%s)", c.CVEID, verdictOf(final), source)
		}
		if final == nil {
			// Şema uyuşmazlığı "risk bilinmiyor"dan çok "kıyaslanamaz"dır.
			// Python bu kayıtları `non_comparable` işaretleyip nihai durum
			// hesabından DIŞLIYOR; tek başlarına kaldıklarında çözülmüş SAFE
			// kararlarını gölgeleyip her sonucu UNCERTAIN yapıyorlardı.
			row := Finding{
				CVEID: c.CVEID, AffectedProduct: matchName, YourVersion: version,
				NonComparable: schemeMismatch,
			}
			if schemeMismatch {
				res.nonComparable++
				row.UncertainReason = "CVE'nin sürüm şeması envanterdeki sürümle " +
					"kıyaslanamıyor; bu kayıttan risk çıkarılamaz"
			} else {
				row.UncertainReason = "CVE metninden kesin bir sürüm kısıtı " +
					"çıkarılamadı; ürün eşleşti ama karar verilemedi"
			}
			res.UncertainRow = append(res.UncertainRow, row)
			continue
		}
		if final.Verdict == "THREAT" {
			// THREAT politikası: kimliği yapısal olarak doğrulanamayan ya da
			// sürüm çıkarımı şüpheli adaylar THREAT olarak YAYINLANMAZ,
			// UNCERTAIN'e düşer. Bu katman olmadan "Inkwell Notes" sorgusu
			// "Litware Inkwell 2024" CVE'lerini, "Corvane" sorgusu
			// "Corvane Relay" CVE'sini tehdit gösterir.
			//
			// Kapı YALNIZCA metin yoluna uygulanır. Yapısal sınır (CNA/NVD)
			// zaten kanonik ürün alanıyla geliyor ve Python da politikayı
			// orada çalıştırmıyor: `enforce_outcome_policy` metin yolunun
			// sonunda, yapısal yükseltme ise ondan SONRA. Kapıyı ikisine de
			// uyguladığımda kaçan tehdit 6'dan 28'e çıktı.
			if b := policyBlockFor(source, p.productNorm, c.Description, version,
				final.Constraint, final.ConstraintType, matchSource); b != nil {
				if trace {
					log.Printf("[iz] %s POLİTİKA %s: %s", c.CVEID, b.Tag, b.Reason)
				}
				res.UncertainRow = append(res.UncertainRow, Finding{
					CVEID: c.CVEID, AffectedProduct: matchName, YourVersion: version,
					Constraint: final.Constraint, ConstraintType: final.ConstraintType,
					UncertainReason: b.Reason, DecisionSource: "policy_" + b.Tag,
				})
				continue
			}
			res.Threats = append(res.Threats, Finding{
				CVEID: c.CVEID, AffectedProduct: matchName,
				ConstraintType: final.ConstraintType, Constraint: final.Constraint,
				YourVersion: version, Reason: final.Reason, DecisionSource: source,
			})
		} else {
			res.SafeReasons = append(res.SafeReasons, Finding{
				CVEID: c.CVEID, AffectedProduct: matchName,
				ConstraintType: final.ConstraintType, Constraint: final.Constraint,
				YourVersion: version, Reason: final.Reason, DecisionSource: source,
			})
		}
	}

	finalize(&res)
	return res
}

// productMatches: katalog adı envanterdeki ürünü gösteriyor mu?
//
// Python `_match_product`'ın katalog dalıyla AYNI olmak zorunda. İlk yazımda
// yalnızca tam nitelikli ad (satıcı + ürün) deneniyordu ve gerçek kayıtlarda
// bu yetmiyor: CVE kataloğu "relaydesk-server-pro Relaydesk Server Pro" yazıyor,
// envanter "Relaydesk". Ne dizi benzerliği ne token kapsaması tutar; o ürünün
// gerçek tehditleri bu yüzden kaçar.
//
// Denenen biçimler:
//   - kataloğun kendisi
//   - satıcı öneki atılmış KUYRUK ("Google Chrome" → "Chrome"), ama yalnızca
//     kuyruk envanterle çelişmiyorsa ("Google ChromeOS" → "ChromeOS" tuzağı)
//   - paket/bileşen takma adları ("Microsoft Office Word 2016" → "Microsoft Word")
//
// Hedef tarafında da takma adlar denenir: envanter paketi, CVE bileşeni
// adlandırmış olabilir.
func (e *Engine) productMatches(catalog, customerProduct, productNorm, soleFamily string) bool {
	if catalog == "" {
		return false
	}
	target := customerProduct
	if target == "" {
		target = productNorm
	}

	// Kardeş bileşen çakışması varsa (Word ↔ Excel) katalog adı eşleşse bile
	// bu CVE bu ürüne ait değildir.
	if ComponentConflict(catalog, target) != "" {
		return false
	}

	candidates := []string{catalog}
	if head, tail, found := strings.Cut(catalog, " "); found && tail != "" {
		_ = head
		if !NamesConflict(tail, target) {
			candidates = append(candidates, tail)
		}
	}
	candidates = append(candidates, MatchAliases(catalog)...)

	targets := []string{productNorm}
	targets = append(targets, MatchAliases(target)...)

	matched := false
	for _, name := range candidates {
		norm := NormalizeProductName(name)
		if norm == "" {
			continue
		}
		for _, t := range targets {
			if FuzzyMatch(norm, t).Matched {
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	// Dizi benzerliği tür kelimeleri yüzünden eşiği geçemiyor ("MySQL Server"
	// ↔ "MySQL" = 0,59). Kimlik tokenları düzeyinde kapsama varsa kabul edilir.
	if !matched && CoversProduct(catalog, target) {
		matched = true
	}
	// Bitişik yazılmış aile ("BrightwaveLinux" ↔ "Brightwave Agent"): TÜM
	// aday biçimler denenir, çünkü satıcı öneki ortak kökü bozuyor.
	if !matched {
		for _, name := range candidates {
			if SameCompoundFamily(name, target) {
				matched = true
				break
			}
		}
	}
	// Envanter adı kataloğa göre kısa yazılmış ve katalogda TEK karşılığı var.
	// Ters yön (CVE daha spesifik) normalde reddedilir; belirsizlik olmadığı
	// SORGUYLA ölçüldüğü için burada kabul edilir. Katalog adı satıcıyla
	// birleşik gelebildiğinden eşitlik değil kimlik-token kapsaması aranır.
	if !matched && soleFamily != "" {
		familyTokens := IdentityTokens(soleFamily)
		if len(familyTokens) > 0 && subset(familyTokens, IdentityTokens(catalog)) {
			matched = true
		}
	}
	if !matched {
		return false
	}

	// Kimlik çelişkisi eşleşmeyi GEÇERSİZ kılar ve bu denetim en SONDA olmalı:
	// alt-dize yöntemi "google chrome"u "google chromeos" içinde bulup %86,7
	// ile kabul eder ve bir işletim sistemi çekirdeği açığı tarayıcı taramasında
	// tehdit çıkar.
	return !NamesConflict(catalog, target)
}

// finalStatus, Python `_finalize_status` ile AYNI önceliği uygular.
//
// Sıra sezgisel değil: UNCERTAIN, SAFE'ten ÖNCE gelir. Bir tek CVE bile
// kararlaştırılamamışsa "güvenli" demek, bilmediğimizi biliyormuş gibi
// sunmaktır.
// finalize, nihai durumu ve güven puanını hesaplar.
//
// Python `_finalize_status` ile AYNI olmak zorunda: puan API sözleşmesinde ve
// panelde görünüyor, ayrışması sessiz bir hata olurdu.
func finalize(r *Result) {
	r.SafeCount = len(r.SafeReasons)
	r.Uncertain = len(r.UncertainRow)

	// Taranan HER aday ürün kimliği tutmadığı için elendiyse envanterdeki ürün
	// veritabanında yok demektir. "SAFE" demek yanıltıcı olurdu: ürünü
	// tanıyamadık, güvenli olduğunu bilmiyoruz.
	if r.Scanned > 0 && r.Ignored == r.Scanned {
		r.Status, r.SafetyScore, r.AllRejected = "NOT_FOUND", 0, true
		return
	}

	// Tüm "safe" kararları FARKLI BİR ÜRÜN olduğu için elenmişse (satıcı /
	// web-eklenti), bu ürünün bulunduğuna kanıt değildir. Alakasız bir CVE'yi
	// sergileyen yanıltıcı SAFE yerine NOT_FOUND. OS uyuşmazlıkları hariç:
	// onlar hâlâ AYNI ürünü ilgilendiriyor.
	diffProductOnly := r.SafeCount > 0 && r.gateSafeOther == r.SafeCount

	// Kıyaslanamayan kayıtlar tek başına belirsizlik sayılmaz: CVE'nin sürüm
	// sistemi müşterininkiyle aynı değil, yani o CVE'den bir risk çıkarılamaz.
	// Aday üst sınırı kalktıktan sonra binlerce olabiliyorlar ve tek
	// başlarına kaldıklarında çözülmüş SAFE kararlarını gölgeliyorlardı.
	decidable := 0
	for _, u := range r.UncertainRow {
		if !u.NonComparable {
			decidable++
		}
	}

	switch {
	case len(r.Threats) > 0:
		r.Status, r.SafetyScore = "THREAT", 0
	case decidable > 0 && r.SafeCount == 0:
		r.Status, r.SafetyScore = "UNCERTAIN", max(30, 100-decidable*5)
	case decidable > 0:
		r.Status, r.SafetyScore = "UNCERTAIN", max(50, 100-decidable*3)
	case diffProductOnly:
		r.Status, r.SafetyScore = "NOT_FOUND", 100
	default:
		r.Status, r.SafetyScore = "SAFE", 100
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AttachRisk, tehditlere önceliklendirme sinyallerini ekler ve listeyi risk
// sırasına dizer. Sıralama isteğe bağlı değil: yanıt kırpılıyor ve panel sayfa
// sayfa okuyor; sıralanmazsa aktif sömürülen açık son sayfada kalıyordu.
func (e *Engine) AttachRisk(ctx context.Context, results []Result) error {
	ids := map[string]bool{}
	for _, r := range results {
		for _, t := range r.Threats {
			ids[t.CVEID] = true
		}
	}
	if len(ids) == 0 {
		return nil
	}
	list := make([]string, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	risks, err := e.db.RiskFor(ctx, list)
	if err != nil {
		return err
	}
	for i := range results {
		for j := range results[i].Threats {
			results[i].Threats[j].Risk = risks[results[i].Threats[j].CVEID]
		}
		sort.SliceStable(results[i].Threats, func(a, b int) bool {
			ra, rb := results[i].Threats[a], results[i].Threats[b]
			pa, pb := priorityRank(ra.Risk), priorityRank(rb.Risk)
			if pa != pb {
				return pa < pb
			}
			ea, eb := epssOf(ra.Risk), epssOf(rb.Risk)
			if ea != eb {
				return ea > eb
			}
			return ra.CVEID < rb.CVEID // kesin sıralama
		})
	}
	return nil
}

// pickResolution, yapısal ve metinsel kararlar arasında ÖNCELİK kurar.
//
// Python `_apply_gates` ile aynı kural: yapısal sınır kazanır, TEK istisna
// "tam sürüm listesinde yok" (neq) kararıdır. O zayıftır ve metinden gelen
// THREAT'i düşüremez — liste eksik bırakılmış olabilir.
func pickResolution(bounds, text *Resolution) (*Resolution, string) {
	if bounds != nil {
		if bounds.Verdict == "THREAT" || bounds.ConstraintType != "neq" {
			return bounds, "structured_bounds"
		}
		if text != nil && text.Verdict == "THREAT" {
			return text, "range_matcher"
		}
		return bounds, "structured_bounds"
	}
	if text != nil {
		return text, "range_matcher"
	}
	return nil, ""
}

// traced: bu CVE için karar yolu loglanacak mı? GOSCAN_TRACE ile virgülle
// ayrılmış CVE kimlikleri verilir. Parity farklarını "neden bu CVE kayboldu"
// diye tahmin etmek yerine görmek için var.
func traced(cveID string) bool {
	if len(traceIDs) == 0 {
		return false
	}
	return traceIDs[cveID]
}

var traceIDs = func() map[string]bool {
	out := map[string]bool{}
	for _, id := range strings.Split(os.Getenv("GOSCAN_TRACE"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}()

func verdictOf(r *Resolution) string {
	if r == nil {
		return "yok"
	}
	return r.Verdict + "/" + r.ConstraintType + "/" + r.Constraint
}

// policyBlockFor, THREAT politikasını YALNIZCA metin yolunda çalıştırır.
func policyBlockFor(source, inventory, description, version, constraint,
	constraintType, matchSource string) *PolicyBlock {
	if source != "range_matcher" {
		return nil
	}
	return EnforceThreatPolicy(inventory, description, version, constraint,
		constraintType, matchSource)
}

// identityCovers: `name`, `target`ın tüm ayırt edici tokenlarını taşıyor mu?
// Platform tokenları aranmaz — ürün kimliğinin parçası değiller.
func identityCovers(name, target string) bool {
	have := IdentityTokens(name)
	for t := range IdentityTokens(target) {
		if platformTokens[t] {
			continue
		}
		if !have[t] {
			return false
		}
	}
	return true
}
