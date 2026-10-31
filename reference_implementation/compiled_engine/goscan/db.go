// PostgreSQL erişimi.
//
// Üretimdeki korpus deposu modülünün (bu pakette yok; bellek içi karşılığı `refimpl/corpus.py`) sorgularının karşılığı. Sorgular
// birebir aynı tutulmalı — özellikle `ORDER BY` kuyrukları: eksik sıralamada
// PostgreSQL beraberlikleri rastgele çözer ve aynı tarama iki kez farklı sonuç
// verir. Bu hata bir kez yaşandı.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct{ pool *pgxpool.Pool }

// OpenDB, .env ile aynı değişkenleri okur; Python servisiyle aynı veritabanına
// bağlanır. Havuz goroutine sayısından büyük tutulmalı, yoksa paralellik
// bağlantı beklemesine dönüşür.
func OpenDB(ctx context.Context, maxConns int32) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("PGHOST", "127.0.0.1"), env("PGPORT", "5432"),
		env("PGUSER", "postgres"), env("PGPASSWORD", ""),
		env("PGDATABASE", "refimpl"))
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &DB{pool: pool}, pool.Ping(ctx)
}

func (d *DB) Close() { d.pool.Close() }

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// Candidate, taranmaya aday bir CVE kaydı.
type Candidate struct {
	CVEID       string
	Description string
	VersionHint string
	Product     string
	Vendor      string
}

// QualifiedProduct, satıcı adıyla nitelenmiş ürün adı ("Google Chrome").
func (c Candidate) QualifiedProduct() string {
	v, p := strings.TrimSpace(c.Vendor), strings.TrimSpace(c.Product)
	if v != "" && p != "" && !strings.Contains(strings.ToLower(p), strings.ToLower(v)) {
		return v + " " + p
	}
	return p
}

const productLimit = 25000
const textLimit = 5000

// SearchCandidates, iki kolu HER ZAMAN birleştirir: yapısal ürün alanı araması
// ve açıklama tam-metin araması. İkincisi isteğe bağlı değil — CVE kayıtlarının
// %41'inde yapısal `affected` girdisi yok ve yalnızca açıklamadan bulunabiliyorlar.
func (d *DB) SearchCandidates(ctx context.Context, productNorm, vendor string) ([]Candidate, error) {
	anchor := anchorToken(productNorm)

	// "CVE'nin ürün adı müşterinin ad metninde geçiyor mu" koşulu AYRI
	// sorulur. Ana sorguya OR olarak konduğunda sütun operatörün sağında
	// kalıyor, hiçbir indeks kullanılamıyor ve PostgreSQL tabloyu tam
	// tarıyordu — tarama süresinin büyük kısmı buradaydı. Aynı soru FARKLI
	// adlara ayrı sorulunca çok daha kısa sürüyor.
	//
	// Alt sorgu olarak gömmek DENENDİ ve 3 kat yavaşlattı: PostgreSQL onu
	// satır başına yeniden değerlendiriyor. İkinci gidiş şart.
	namesDone := track("ad alt kümesi", 1)
	names, err := d.substringNames(ctx, productNorm)
	namesDone()
	if err != nil {
		return nil, err
	}

	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT ON (a.cve_id)
		       a.cve_id, a.product, a.vendor, a.version, c.description
		  FROM cve_affected a
		  JOIN cves c ON c.cve_id = a.cve_id
		 WHERE a.product_norm = ANY($1)
		    OR a.product_norm LIKE $2
		    OR ($3 <> '' AND a.product_norm ~ $4)
		    OR ($5 <> '' AND lower(a.vendor) = $5)
		 ORDER BY a.cve_id,
		          (a.product_norm = $6) DESC,
		          (a.less_than <> '' OR a.less_than_or_equal <> ''
		           OR a.greater_equal <> '') DESC,
		          a.id
		 LIMIT $7`,
		names, "%"+productNorm+"%", anchor, `\m`+anchor,
		strings.ToLower(strings.TrimSpace(vendor)), productNorm, productLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seen := map[string]bool{}
	out := []Candidate{}
	for rows.Next() {
		var c Candidate
		if err := rows.Scan(&c.CVEID, &c.Product, &c.Vendor, &c.VersionHint, &c.Description); err != nil {
			return nil, err
		}
		if !accepts(productNorm, vendor, c) {
			continue
		}
		seen[c.CVEID] = true
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	tokens := []string{}
	for _, t := range strings.Fields(productNorm) {
		if len(t) > 2 {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		return out, nil
	}
	trows, err := d.pool.Query(ctx, `
		SELECT DISTINCT ON (c.cve_id)
		       c.cve_id, coalesce(a.product,''), coalesce(a.vendor,''),
		       coalesce(a.version,''), c.description
		  FROM cves c
		  LEFT JOIN cve_affected a ON a.cve_id = c.cve_id
		 WHERE to_tsvector('english', c.description) @@ to_tsquery('english', $1)
		 ORDER BY c.cve_id,
		          (a.less_than <> '' OR a.less_than_or_equal <> ''
		           OR a.greater_equal <> '') DESC,
		          a.id
		 LIMIT $2`, strings.Join(tokens, " & "), textLimit)
	if err != nil {
		return nil, err
	}
	defer trows.Close()
	for trows.Next() {
		var c Candidate
		if err := trows.Scan(&c.CVEID, &c.Product, &c.Vendor, &c.VersionHint, &c.Description); err != nil {
			return nil, err
		}
		if seen[c.CVEID] || !accepts(productNorm, vendor, c) {
			continue
		}
		seen[c.CVEID] = true
		out = append(out, c)
	}
	return out, trows.Err()
}

// exactVersionSQL: tam sürüm gibi görünen `version` — en az bir nokta şart.
// "12" gibi tek sayılar bakım DALI anlamına gelebiliyor ve eşitlik kıyası orada
// yanlış tehdit üretirdi.
const exactVersionSQL = `^[vV]?[0-9]+(\.[0-9]+)+[A-Za-z0-9.\-+_:]*$`

// BoundsFor, CNA'nın bildirdiği aralıklar. Sınır sütunları boş ama `version`
// tam bir sürümse o satır da döner: depodaki 1,09M satırın 535 bini hiç yapısal
// sınır taşımıyor ve eskiden tamamen eleniyorlardı.
func (d *DB) BoundsFor(ctx context.Context, cveIDs []string, productNorm string) (map[string][]Bound, error) {
	if len(cveIDs) == 0 {
		return map[string][]Bound{}, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT a.cve_id, a.product, a.vendor, a.version, a.default_status,
		       a.less_than, a.less_than_or_equal, a.greater_equal,
		       (a.less_than <> '' OR a.less_than_or_equal <> ''
		        OR a.greater_equal <> '') AS has_bounds,
		       left(c.description, 600)
		  FROM cve_affected a
		  JOIN cves c ON c.cve_id = a.cve_id
		 WHERE a.cve_id = ANY($1)
		   AND (a.less_than <> '' OR a.less_than_or_equal <> ''
		        OR a.greater_equal <> '' OR a.version ~ $2)
		 ORDER BY a.cve_id,
		          (a.product_norm = $3) DESC,
		          (a.less_than <> '' OR a.less_than_or_equal <> ''
		           OR a.greater_equal <> '') DESC,
		          a.id`, cveIDs, exactVersionSQL, productNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]Bound{}
	for rows.Next() {
		var id, prod, vend, ver, ds, lt, lte, ge, text string
		var hasBounds bool
		if err := rows.Scan(&id, &prod, &vend, &ver, &ds, &lt, &lte, &ge, &hasBounds, &text); err != nil {
			return nil, err
		}
		if len(out[id]) >= 200 {
			continue
		}
		exact := ver
		if hasBounds {
			// Sınır varsa `version` zaten alt sınır olarak kopyalanmıştır.
			exact = ""
		}
		out[id] = append(out[id], Bound{
			LessThan: lt, LessThanOrEqual: lte, GreaterEqual: ge,
			ExactVersion: exact, DefaultStatus: ds,
			Product: prod, Vendor: vend, Text: text,
		})
	}
	return out, rows.Err()
}

// CPEBoundsFor, NVD'nin CPE analizinden aralıklar.
//
// Ürün süzgeci CNA satırlarındakinden KATIdır: bir CVE birden çok ürünü
// kapsayabilir (ör. hem BrightwaveOS hem BrightwaveRouter) ve süzülmezse
// BrightwaveRouter'ın aralığı BrightwaveOS sorgusunda karar verirdi.
func (d *DB) CPEBoundsFor(ctx context.Context, cveIDs []string, productNorm string) (map[string][]Bound, error) {
	if len(cveIDs) == 0 {
		return map[string][]Bound{}, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT cve_id, product, product_norm, vendor, version,
		       less_than, less_than_or_equal, greater_equal, greater_than
		  FROM cve_cpe
		 WHERE cve_id = ANY($1)
		 ORDER BY cve_id, (product_norm = $2) DESC, id`, cveIDs, productNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]Bound{}
	for rows.Next() {
		var id, prod, pnorm, vend, ver, lt, lte, ge, gt string
		if err := rows.Scan(&id, &prod, &pnorm, &vend, &ver, &lt, &lte, &ge, &gt); err != nil {
			return nil, err
		}
		if productNorm != "" && !CoversProduct(pnorm, productNorm) {
			continue
		}
		if len(out[id]) >= 60 {
			continue
		}
		out[id] = append(out[id], Bound{
			LessThan: lt, LessThanOrEqual: lte, GreaterEqual: ge, GreaterThan: gt,
			ExactVersion: ver, Product: prod, Vendor: vend, Source: "nvd-cpe",
			// CPE listesi NVD tarafından kapatılmış kabul edilir; CNA'nın
			// defaultStatus'ü buraya geçmez.
		})
	}
	return out, rows.Err()
}

// Extraction, modelin bir CVE metninden çıkardığı ürün/sürüm bilgisi.
type Extraction struct {
	AppName         string
	AppVersion      string
	LessThan        string
	LessThanOrEqual string
	GreaterEqual    string
	VersionScheme   string
}

// ExtractionsFor, model çıktısının ÖNBELLEĞİNİ okur.
//
// Bu, Go tarafının modele hiç ihtiyaç duymadan karar verebilmesinin nedeni:
// çıkarım CVE metnine ve model sürümüne bağlı, sürüme değil — bir kez
// hesaplanıp PostgreSQL'de saklanıyor. Ölçüm: taranan ürünlerde adayların
// %100'ünün çıkarımı hazırdı.
//
// İkinci dönen değer, çıkarımı OLMAYAN CVE kimlikleridir; onlar Python
// servisine gider.
func (d *DB) ExtractionsFor(ctx context.Context, cveIDs []string, modelVersion string,
	hashes map[string]string) (map[string]Extraction, []string, error) {
	out := map[string]Extraction{}
	if len(cveIDs) == 0 {
		return out, nil, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT cve_id, description_hash, payload FROM cve_extractions
		 WHERE cve_id = ANY($1) AND model_version = $2`, cveIDs, modelVersion)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, hash string
		var payload map[string]any
		if err := rows.Scan(&id, &hash, &payload); err != nil {
			return nil, nil, err
		}
		// Açıklama özeti tutmuyorsa kayıt YOK sayılır: CVE revize edilmiş ve
		// çıkarım eski metne ait. Python tarafı da aynı ölçütü kullanıyor;
		// burada gevşetmek iki motorun farklı karar vermesine yol açardı.
		if want, ok := hashes[id]; ok && want != hash {
			continue
		}
		out[id] = Extraction{
			AppName:         str(payload["app_name"]),
			AppVersion:      str(payload["app_version"]),
			LessThan:        str(payload["less_than"]),
			LessThanOrEqual: str(payload["less_than_or_equal"]),
			GreaterEqual:    str(payload["greater_equal"]),
			VersionScheme:   str(payload["version_scheme"]),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	missing := []string{}
	for _, id := range cveIDs {
		if _, ok := out[id]; !ok {
			missing = append(missing, id)
		}
	}
	return out, missing, nil
}

// Risk, önceliklendirme sinyalleri.
type Risk struct {
	KEV          bool     `json:"kev"`
	KEVDueDate   string   `json:"kev_due_date,omitempty"`
	Ransomware   bool     `json:"ransomware"`
	EPSS         *float64 `json:"epss,omitempty"`
	CVSS         *float64 `json:"cvss,omitempty"`
	CVSSSeverity string   `json:"cvss_severity,omitempty"`
	CVSSVector   string   `json:"cvss_vector,omitempty"`
	CWEs         []string `json:"cwes,omitempty"`
	ExploitKnown bool     `json:"exploit_known"`
	Priority     string   `json:"priority"`
}

func (d *DB) RiskFor(ctx context.Context, cveIDs []string) (map[string]*Risk, error) {
	out := map[string]*Risk{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT c.cve_id, c.cvss_score, c.cvss_severity, c.cvss_vector,
		       k.due_date, k.ransomware, (k.cve_id IS NOT NULL) AS kev,
		       e.score,
		       EXISTS (SELECT 1 FROM cve_references r
		                WHERE r.cve_id = c.cve_id AND r.tags LIKE '%exploit%'),
		       ARRAY(SELECT w.cwe_id FROM cve_weaknesses w
		              WHERE w.cve_id = c.cve_id ORDER BY w.cwe_id)
		  FROM cves c
		  LEFT JOIN cve_kev  k ON k.cve_id = c.cve_id
		  LEFT JOIN cve_epss e ON e.cve_id = c.cve_id
		 WHERE c.cve_id = ANY($1)`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var cvss, epss *float64
		var severity, vector, ransom *string
		var dueDate *time.Time
		var kev, exploit bool
		var cwes []string
		if err := rows.Scan(&id, &cvss, &severity, &vector, &dueDate, &ransom,
			&kev, &epss, &exploit, &cwes); err != nil {
			return nil, err
		}
		r := &Risk{KEV: kev, EPSS: epss, CVSS: cvss, CWEs: cwes, ExploitKnown: exploit}
		if severity != nil {
			r.CVSSSeverity = *severity
		}
		if vector != nil {
			r.CVSSVector = *vector
		}
		if dueDate != nil {
			r.KEVDueDate = dueDate.Format("2006-01-02")
		}
		if ransom != nil && *ransom == "known" {
			r.Ransomware = true
		}
		r.Priority = PriorityFor(r)
		out[id] = r
	}
	return out, rows.Err()
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Fix, OSV'den gelen (dal_başlangıcı, düzeltilmiş_sürüm) çifti.
type Fix struct {
	Introduced string
	Fixed      string
	Product    string
}

// FixesFor, OSV düzeltilmiş sürümleri. Ürün süzgeci CPE'dekiyle aynı gerekçeyle
// katıdır: başka paketin düzeltmesini önermek yanlış yönlendirme olur.
func (d *DB) FixesFor(ctx context.Context, cveIDs []string, productNorm string) (map[string][]Fix, error) {
	out := map[string][]Fix{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT cve_id, product, product_norm, introduced, fixed
		  FROM cve_fixes
		 WHERE cve_id = ANY($1)
		 ORDER BY cve_id, (product_norm = $2) DESC, id`, cveIDs, productNorm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, prod, pnorm, intro, fixed string
		if err := rows.Scan(&id, &prod, &pnorm, &intro, &fixed); err != nil {
			return nil, err
		}
		if productNorm != "" && !CoversProduct(pnorm, productNorm) {
			continue
		}
		out[id] = append(out[id], Fix{Introduced: intro, Fixed: fixed, Product: prod})
	}
	return out, rows.Err()
}

// RemediationExtra, satıcı çözüm metni ve düzeltme bağlantıları.
type RemediationExtra struct {
	Solution string
	Links    []RemediationLink
}

// Referans etiketlerinin "ne işe yarar" sırası. Müşteriye önce satıcının kendi
// bülteni gösterilir; 'exploit' etiketli bağlantıyı "çözüm" diye göstermektense
// hiç göstermemek yeğdir.
var referenceKinds = []string{
	"vendor-advisory", "patch", "mitigation", "release-notes", "third-party-advisory",
}

func (d *DB) RemediationFor(ctx context.Context, cveIDs []string) (map[string]*RemediationExtra, error) {
	out := map[string]*RemediationExtra{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx,
		`SELECT cve_id, solution FROM cves WHERE cve_id = ANY($1) AND solution <> ''`, cveIDs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, sol string
		if err := rows.Scan(&id, &sol); err != nil {
			rows.Close()
			return nil, err
		}
		out[id] = &RemediationExtra{Solution: sol}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	lrows, err := d.pool.Query(ctx, `
		SELECT cve_id, url, tags, name FROM cve_references
		 WHERE cve_id = ANY($1) ORDER BY cve_id, url`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer lrows.Close()
	buckets := map[string][]RemediationLink{}
	for lrows.Next() {
		var id, url, tags, name string
		if err := lrows.Scan(&id, &url, &tags, &name); err != nil {
			return nil, err
		}
		kind := ""
		for _, k := range referenceKinds {
			for _, t := range strings.Split(tags, ",") {
				if t == k {
					kind = k
					break
				}
			}
			if kind != "" {
				break
			}
		}
		if kind == "" {
			continue
		}
		buckets[id] = append(buckets[id], RemediationLink{URL: url, Kind: kind, Name: name})
	}
	if err := lrows.Err(); err != nil {
		return nil, err
	}
	order := map[string]int{}
	for i, k := range referenceKinds {
		order[k] = i
	}
	for id, links := range buckets {
		sort.SliceStable(links, func(i, j int) bool {
			if order[links[i].Kind] != order[links[j].Kind] {
				return order[links[i].Kind] < order[links[j].Kind]
			}
			return links[i].URL < links[j].URL
		})
		if len(links) > 4 {
			links = links[:4]
		}
		if out[id] == nil {
			out[id] = &RemediationExtra{}
		}
		out[id].Links = links
	}
	return out, nil
}

// LifecycleCycle, bir ürünün bakım dalı ve destek bitiş tarihi.
type LifecycleCycle struct {
	Slug     string
	Cycle    string
	EOLDate  string // "2027-03-31" — boşsa bildirilmemiş
	EOLKnown bool
	Latest   string
	LTS      bool
}

// LifecycleFor, ürünün destek takvimi. Eşleşme `CoversProduct` ile yapılır:
// endoflife.date kısa slug kullanıyor ('tomcat'), envanter uzun ad
// ('Apache Tomcat').
func (d *DB) LifecycleFor(ctx context.Context, productNorm string) ([]LifecycleCycle, error) {
	if productNorm == "" {
		return nil, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT slug, product_norm, cycle, eol_date, eol_known, latest, lts
		  FROM product_lifecycle
		 WHERE product_norm = $1
		    OR $1 LIKE '%' || product_norm || '%'
		    OR product_norm LIKE $2
		 ORDER BY slug, id`, productNorm, "%"+productNorm+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LifecycleCycle{}
	for rows.Next() {
		var slug, pnorm, cycle, latest string
		var eol *time.Time
		var known, lts bool
		if err := rows.Scan(&slug, &pnorm, &cycle, &eol, &known, &latest, &lts); err != nil {
			return nil, err
		}
		if !CoversProduct(pnorm, productNorm) {
			continue
		}
		c := LifecycleCycle{Slug: slug, Cycle: cycle, EOLKnown: known, Latest: latest, LTS: lts}
		if eol != nil {
			c.EOLDate = eol.Format("2006-01-02")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DescriptionsFor, çıkarımı eksik CVE'lerin metnini getirir.
func (d *DB) DescriptionsFor(ctx context.Context, cveIDs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx,
		`SELECT cve_id, COALESCE(description, '') FROM cves WHERE cve_id = ANY($1)`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, desc string
		if err := rows.Scan(&id, &desc); err != nil {
			return nil, err
		}
		out[id] = desc
	}
	return out, rows.Err()
}

// SaveExtractions, model çıktısını önbelleğe yazar.
//
// Çakışmada GÜNCELLENİR, atlanmaz: çakışan satır büyük olasılıkla ESKİ metne
// ait bir çıkarımdır (CVE revize edilmiş), ve `DO NOTHING` onu sonsuza dek
// yerinde bırakır — her tarama aynı CVE'yi yeniden hesaplar (ör. yazma
// `description_hash` eksikliğinden düşerse önbellek hiç dolmaz).
func (d *DB) SaveExtractions(ctx context.Context, rows map[string]Extraction,
	modelVersion string, hashes map[string]string) error {
	if len(rows) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for id, e := range rows {
		payload := map[string]any{
			"cve_id": id, "app_name": nullable(e.AppName),
			"app_version": nullable(e.AppVersion), "less_than": nullable(e.LessThan),
			"less_than_or_equal": nullable(e.LessThanOrEqual),
			"greater_equal":      nullable(e.GreaterEqual),
			"version_scheme":     e.VersionScheme,
			"extraction_method":  "bilstm-crf-onnx-go",
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO cve_extractions (cve_id, model_version, description_hash, payload)
		             VALUES ($1, $2, $3, $4)
		             ON CONFLICT (cve_id, model_version) DO UPDATE
		                SET description_hash = EXCLUDED.description_hash,
		                    payload = EXCLUDED.payload,
		                    created_at = now()`,
			id, modelVersion, hashes[id], raw)
	}
	br := d.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range rows {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// nullable, boş metni SQL NULL'a çevirir — Python tarafı `None` bekliyor ve
// boş dizgiyi "ad var ama boş" diye yorumluyor.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// DescriptionHash, Python `storage.extractions.description_hash` ile AYNI
// olmalı: sha256'nın ilk 16 onaltılık hanesi. Farklı hesaplarsak iki motor
// birbirinin önbelleğini geçersiz görür ve modeli boşuna tekrar çalıştırır.
func DescriptionHash(description string) string {
	sum := sha256.Sum256([]byte(description))
	return hex.EncodeToString(sum[:])[:16]
}

// substringNames, CVE deposundaki ürün adlarından müşterinin ad metninde
// GEÇENleri döndürür. Aranan adın kendisi her zaman listeye girer: görünüm
// tazelenmemiş olsa bile eşitlik dalı çalışmalı.
func (d *DB) substringNames(ctx context.Context, productNorm string) ([]string, error) {
	names := []string{productNorm}
	rows, err := d.pool.Query(ctx,
		`SELECT product_norm FROM cve_product_norms
		  WHERE $1 LIKE '%' || product_norm || '%'`, productNorm)
	if err != nil {
		return names, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return names, err
		}
		if n != productNorm {
			names = append(names, n)
		}
	}
	return names, rows.Err()
}

// ProductFamilyNames, bu adla BAŞLAYAN katalog ürün adları.
//
// Envanterler ürün adını CVE kataloğundan kısa yazar ("Acme" ↔ "Acme
// NAC"). Kısa adı spesifik bir ürüne bağlamak ancak katalogda TEK karşılığı
// varsa güvenli:
//
//	acme → ['acme nac']                  tek  → bağlanabilir
//	mysql  → ['mysql', 'mysql cluster', ...] 17   → bağlanamaz
//
// `limit` küçük: çağıran yalnızca "tek mi, birden çok mu" bilgisini kullanır.
func (d *DB) ProductFamilyNames(ctx context.Context, productNorm string) ([]string, error) {
	q := strings.TrimSpace(productNorm)
	if q == "" {
		return nil, nil
	}
	rows, err := d.pool.Query(ctx, `
		SELECT DISTINCT product_norm
		  FROM cve_affected
		 WHERE product_norm = $1 OR product_norm LIKE $2
		 ORDER BY product_norm
		 LIMIT 6`, q, q+" %")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
