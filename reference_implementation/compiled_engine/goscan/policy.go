// THREAT politikası — Python `refimpl/policy.py` + `refimpl/identity.py` karşılığı.
//
// Bir THREAT kararı yayınlanmadan önce geçmesi gereken kapılar. Bu katman
// PRECISION içindir: ürün kimliği yapısal olarak doğrulanamayan ya da sürüm
// çıkarımı şüpheli görünen adaylar THREAT yerine UNCERTAIN işaretlenir.
//
// Bu katman olmadan bir ürünün taraması, adını paylaşan başka bir ürünün
// ("Corvane" ↔ "Corvane Relay") CVE'lerini tehdit gösterir. Bilinen yanlış
// tehdit sınıflarının her biri bu kapılardan birine takılır.
//
// Aşağıdaki tablolar yöntemin BİLGİ TABANIDIR: dağıtımda doğrulanmış çiftlerle
// doldurulur. Bu araştırma paketinde içerikleri tamamen KURGUSALDIR ve
// `refimpl/identity.py` ile birebir aynıdır.
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Ürün kimliğini TEK BAŞINA belirlemeyen adlar. Buradakiler bir CVE
// açıklamasında geçse bile o CVE'nin envanterdeki ürünle ilgili olduğunu
// göstermez — çoğu birden çok satıcıda aynı adla var.
var identityGenericTokens = set(
	"brindle", "corvane", "tessary", "mirrowick", "halden", "manager", "client", "runtime", "application", "installer",
	"update", "windows", "x64", "x86")

// (envanter ipucu, CVE metninde olmaması gereken yabancı ürün, gerekçe)
var knownCrossProduct = []struct {
	inv     []string
	foreign []string
	reason  string
}{
	{[]string{"brindle"}, []string{"brindle cloud console", "brindlecloud"}, "Brindle masaüstü ≠ Brindle Cloud Console"},
	{[]string{"quillon"}, []string{"quillon-py", "pypi package"}, "Quillon editörü ≠ quillon-py Python paketi"},
	{[]string{"corvane"}, []string{"corvane relay"}, "Corvane görüntüleyici ≠ Corvane Relay sunucusu"},
	{[]string{"tessary", "tessary-cli"}, []string{"tessary hosted"}, "Tessary CLI ≠ Tessary Hosted hizmeti"},
	{[]string{"mirrowick"}, []string{"mirrowick connector", "helpdesk add-on"}, "Mirrowick ≠ Mirrowick Connector eklentisi"},
}

var distinctSubproducts = [][2]string{
	{"brindle", "brindlecloud"},
	{"corvane", "corvane relay"},
	{"quillon", "quillon-py"},
}

// Sürüm sınırı BAŞKA ürün satırına ait olabileceğini gösteren işaretler.
var foreignMarkers = []string{
	"brindlecloud", "brindle cloud console", "quillon-py", "corvane relay",
	"tessary hosted", "mirrowick connector",
}

// Tek başına ürün kimliği belirlemeyen yaygın kelimeler.
var commonWords = set(
	"unity", "studio", "server", "client", "player", "viewer", "editor",
	"reader", "writer", "manager", "monitor", "center", "central", "console",
	"portal", "gateway", "bridge", "connect", "connector", "access", "secure",
	"security", "defender", "guard", "shield", "protect", "backup", "restore",
	"sync", "cloud", "drive", "share", "point", "team", "teams", "meeting",
	"office", "suite", "tools", "utility", "helper", "assistant", "agent",
	"service", "system", "platform", "engine", "framework", "library",
	"package", "module", "plugin", "driver", "update", "updater", "installer",
	"setup", "launcher", "runtime", "desktop", "mobile", "online", "express",
	"professional", "enterprise", "standard", "premium", "basic", "core",
	"print", "printer", "scanner", "camera", "audio", "video", "media",
	"music", "photo", "image", "graphic", "design", "paint", "draw",
	"mail", "message", "chat", "phone", "voice", "call", "contact",
	"calendar", "note", "notes", "task", "project", "board", "report",
	"data", "base", "table", "query", "search", "index", "cache", "store",
	"shop", "market", "pay", "wallet", "money", "bank", "finance",
	"health", "fitness", "sport", "game", "play", "learn", "study", "book",
	"news", "weather", "clock", "timer", "alarm", "world", "home", "work")

var (
	wsRe          = regexp.MustCompile(`\s+`)
	idTokenSplit  = regexp.MustCompile(`[\s_./\-():]+`)
	parenRe       = regexp.MustCompile(`\s*\([^)]*\)\s*`)
	trailingVerRe = regexp.MustCompile(`\s+\d+(\.\d+){1,3}.*$`)
	linePrefixRe  = regexp.MustCompile(`(?i)LINE#\d+`)
	ltIntRe       = regexp.MustCompile(`^<=?\s*\d+$`)
	leadingIntRe  = regexp.MustCompile(`^(\d+)`)
	dottedNumRe   = regexp.MustCompile(`\d+\.\d+`)
	kernelRe      = regexp.MustCompile(`(?i)linux kernel`)
)

func normText(s string) string {
	return wsRe.ReplaceAllString(strings.TrimSpace(strings.ToLower(s)), " ")
}

// identityTokenSet: 2 karakterden UZUN parçalar. Kısa parçalar ("os", "ui")
// kimlik kanıtı sayılmaz.
func identityTokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range idTokenSplit.Split(normText(s), -1) {
		if len(t) > 2 {
			out[t] = true
		}
	}
	return out
}

// inventoryCore: parantezli ekler ve sondaki sürüm atılır.
func inventoryCore(name string) string {
	p := parenRe.ReplaceAllString(normText(name), " ")
	p = trailingVerRe.ReplaceAllString(p, "")
	return strings.TrimSpace(p)
}

func knownCrossProductMismatch(inventory, description string) string {
	inv := inventoryCore(inventory)
	desc := normText(description)
	for _, rule := range knownCrossProduct {
		hit := false
		for _, k := range rule.inv {
			if strings.Contains(inv, k) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		for _, k := range rule.foreign {
			if strings.Contains(desc, k) {
				return rule.reason
			}
		}
	}
	for _, pair := range distinctSubproducts {
		a, b := pair[0], pair[1]
		if strings.Contains(inv, a) && strings.Contains(desc, b) && !strings.Contains(inv, b) {
			return "envanterdeki '" + a + "' ile CVE'deki '" + b + "' farklı ürün aileleri"
		}
	}
	return ""
}

// stripBound, "<= 1.2.3" gibi bir kısıttan sayıyı ayıklar. Aralıklarda ÜST
// sınır alınır: yabancı ürün bağı üst sınırdan anlaşılıyor.
func stripBound(constraint string) string {
	b := strings.TrimSpace(constraint)
	for _, p := range []string{"<= ", "< ", ">= ", "> ", "== "} {
		if strings.HasPrefix(b, p) {
			b = strings.TrimSpace(b[len(p):])
			break
		}
	}
	if i := strings.Index(b, " .. "); i >= 0 {
		b = strings.TrimSpace(b[i+4:])
	}
	return b
}

// foreignVersionBinding: CVE'deki sürüm sınırı BAŞKA bir ürün satırına mı ait?
//
// "Quillon 4.x" sorgusunda quillon-py 0.9 sınırı böyle yakalanır. Ölçüt
// yakınlık: sınır metinde yabancı ürün adının 120 karakter yakınında geçiyorsa
// o satıra aittir.
func foreignVersionBinding(inventory, yourVersion, constraint, description string) string {
	desc := normText(description)
	inv := inventoryCore(inventory)
	bound := stripBound(constraint)
	if bound == "" || strings.TrimSpace(yourVersion) == "" {
		return ""
	}
	invFlat := strings.ReplaceAll(inv, " ", "")
	for _, marker := range foreignMarkers {
		if !strings.Contains(desc, marker) {
			continue
		}
		// Envanterin KENDİSİ o ürünse çelişki yok.
		if strings.Contains(invFlat, strings.ReplaceAll(marker, " ", "")) {
			continue
		}
		im, ib := strings.Index(desc, marker), strings.Index(desc, bound)
		if im >= 0 && ib >= 0 && abs(im-ib) < 120 {
			return "CVE sürüm sınırı (" + bound + ") '" + marker +
				"' ürününe ait; envanterdeki '" + inventory + "' farklı bir ürün"
		}
	}
	return ""
}

// versionSchemeMismatchText: aynı ürün ailesinde farklı sürüm şeması
// (envanter 3.6 ile CVE'nin "up to 21.5" satırı). Ana sürümler 8'den fazla
// ayrışıyor ve biri tek haneli, öteki iki haneliyse aynı numaralandırma değil.
func versionSchemeMismatchText(yourVersion, constraint, description string) string {
	yv := normText(yourVersion)
	desc := normText(description)
	bound := stripBound(constraint)
	if bound == "" || !strings.ContainsAny(yv, "0123456789") {
		return ""
	}
	ym, ok1 := leadingInt(yv)
	bm, ok2 := leadingInt(bound)
	if !ok1 || !ok2 || abs(ym-bm) < 8 {
		return ""
	}
	if ym >= 10 || bm < 10 {
		return ""
	}
	re := regexp.MustCompile(`(up to|before|through|prior to|versions?\s+)[^.;]{0,40}` + regexp.QuoteMeta(bound))
	if re.MatchString(desc) {
		return "CVE sürüm satırı (" + bound + ") envanterdeki sürümle (" +
			yourVersion + ") aynı numaralandırma şemasında değil"
	}
	return ""
}

func leadingInt(s string) (int, bool) {
	m := leadingIntRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// strongTokenOverlap: envanter adının ayırt edici tokenları CVE metninde
// geçiyor mu?
//
// İki token eşleşmesi yeterli. Tek token da kabul edilir ama YALNIZCA yaygın
// bir yazılım kelimesi değilse. Sabit bir "güvenilir ürün" listesi tutmak
// sürdürülemez: listede olmayan tek kelimelik adların tüm CVE'leri UNCERTAIN'e
// düşer.
func strongTokenOverlap(inventory, description string) bool {
	inv := inventoryCore(inventory)
	desc := normText(description)
	hits := []string{}
	for t := range identityTokenSet(inv) {
		if identityGenericTokens[t] || len(t) < 4 {
			continue
		}
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(t) + `\b`).MatchString(desc) {
			hits = append(hits, t)
		}
	}
	if len(hits) >= 2 {
		return true
	}
	for _, t := range hits {
		if !commonWords[t] {
			return true
		}
	}
	return false
}

// IdentityVerdict, kimlik denetiminin sonucu.
type IdentityVerdict struct {
	Confirmed bool
	Reason    string // doluysa AÇIK reddetme
	Method    string // catalog | structural | rejected | unverified
}

// AssessThreatIdentity, bir THREAT adayının ürün kimliğini doğrular.
//
// `inventory` GERÇEK envanter kimliğidir; CVE'nin kendi ürün adı BURAYA
// GİRMEZ. Girseydi CVE kendi açıklamasıyla karşılaştırılırdı (döngüsel onay)
// ve "Home"/"Preview" gibi normalize edilemeyen jenerik adlar her CVE'ye
// tehdit olurdu.
func AssessThreatIdentity(inventory, description, yourVersion, constraint, matchSource string) IdentityVerdict {
	inventory = strings.TrimSpace(inventory)
	if inventory == "" {
		return IdentityVerdict{false,
			"envanter ürün adı normalize edilemedi (çok jenerik); ürün kimliği doğrulanamıyor",
			"rejected"}
	}
	if r := knownCrossProductMismatch(inventory, description); r != "" {
		return IdentityVerdict{false, "ürün kimliği çelişkisi: " + r, "rejected"}
	}
	if r := foreignVersionBinding(inventory, yourVersion, constraint, description); r != "" {
		return IdentityVerdict{false, r, "rejected"}
	}
	if r := versionSchemeMismatchText(yourVersion, constraint, description); r != "" {
		return IdentityVerdict{false, r, "rejected"}
	}

	// CVE'nin YAPISAL ürün alanıyla eşleştiysek kimlik zaten doğrulanmıştır:
	// bu alan CNA'nın bildirdiği kanonik addır ve serbest metinden çıkarımdan
	// güvenilirdir. Token örtüşmesi yolu yalnızca yapısal alanı olmayan
	// kayıtlar için kalır (CVE'lerin ~%40'ı).
	if matchSource == "catalog" {
		return IdentityVerdict{true, "", "catalog"}
	}

	if strongTokenOverlap(inventory, description) {
		core := inventoryCore(inventory)
		// Bu adlar birden çok satıcıda aynı adla var; metin örtüşmesi tek
		// başına kimlik kanıtı değil.
		for _, g := range []string{"brindle", "corvane", "tessary", "mirrowick"} {
			if strings.Contains(core, g) {
				return IdentityVerdict{false, "", "unverified"}
			}
		}
		return IdentityVerdict{true, "", "structural"}
	}
	return IdentityVerdict{false, "", "unverified"}
}

// --- şüpheli sürüm çıkarımı kapıları --------------------------------------

// IsKernelInventoryMismatch: "Journal 2.0" ile Linux kernel CVE'si gibi
// bariz alan kayması.
func IsKernelInventoryMismatch(description, inventory string) bool {
	if !kernelRe.MatchString(description) {
		return false
	}
	inv := strings.ToLower(inventory)
	for _, k := range []string{"linux", "kernel", "ubuntu", "debian", "rhel", "centos"} {
		if strings.Contains(inv, k) {
			return false
		}
	}
	return true
}

// IsSuspectLineNumberConstraint: model kaynak kod satır numarasını sürüm
// sanmış ("< 48", "LINE#1794").
func IsSuspectLineNumberConstraint(constraint, yourVersion, description string) bool {
	cv := strings.TrimSpace(constraint)
	yv := strings.TrimSpace(yourVersion)
	if cv == "" || yv == "" {
		return false
	}
	if linePrefixRe.MatchString(description) && ltIntRe.MatchString(cv) {
		return true
	}
	// Kısıt noktasız bir tam sayı ama müşteri sürümü noktalıysa: aynı
	// numaralandırma olamaz.
	if m := regexp.MustCompile(`^<\s*(\d+)$`).FindStringSubmatch(cv); m != nil && dottedNumRe.MatchString(yv) {
		if n, err := strconv.Atoi(m[1]); err == nil && n >= 10 {
			return true
		}
	}
	return false
}

// IsSuspectBroadRange: modelin ürettiği "1 .. 10.x" gibi geniş aralıklar.
// Böyle bir aralık pratikte "her sürüm etkilenmiş" demektir ve neredeyse her
// zaman yanlış çıkarımdır.
//
// Ölçüt ALT SINIRIN KENDİSİ, kısıt metninin ön eki değil. İlk yazımda Python'ın
// metin biçimi ("1 .. 10.0.0") aranıyordu ama Go aralığı "[1, 10.0.0)" olarak
// yazıyor: kural hiç yanmaz ve 9.0.90 gibi bir sürüme 9.0.0.M1–9.0.37
// aralığındaki bir CVE tehdit olarak yazılır, oysa kurulu sürüm etkilenmiyor.
func IsSuspectBroadRange(constraintType, constraint string) bool {
	if constraintType != "range" {
		return false
	}
	switch rangeLowerBound(constraint) {
	case "0", "0.0", "1", "1.0":
		return true
	}
	return false
}

// rangeLowerBound, bir aralık kısıtının alt sınırını ayıklar. Üç biçim de
// tanınır: Go'nun "[1, 10.0.0)" / "(1, 10.0.0)" yazımı, Python'ın "1 .. 10.0.0"
// yazımı ve "1 <= x" gibi karşılaştırma metni.
func rangeLowerBound(constraint string) string {
	cv := strings.ToLower(strings.TrimSpace(constraint))
	cv = strings.TrimLeft(cv, "[(")
	if i := strings.Index(cv, ".."); i >= 0 {
		cv = cv[:i]
	} else if i := strings.Index(cv, ","); i >= 0 {
		cv = cv[:i]
	} else if i := strings.Index(cv, "<"); i >= 0 {
		cv = cv[:i]
	}
	return strings.TrimSpace(cv)
}

// PolicyBlock, bir THREAT adayının UNCERTAIN'e düşme gerekçesi. Boşsa geçti.
type PolicyBlock struct {
	Tag    string
	Reason string
}

// EnforceThreatPolicy, THREAT adayını politika kapılarından geçirir.
func EnforceThreatPolicy(inventory, description, yourVersion, constraint,
	constraintType, matchSource string) *PolicyBlock {
	if IsKernelInventoryMismatch(description, inventory) ||
		IsSuspectLineNumberConstraint(constraint, yourVersion, description) {
		return &PolicyBlock{"domain_mismatch",
			"ürün/CVE alanı uyuşmuyor ya da sürüm çıkarımı hatalı " +
				"(ör. kaynak kod satır numarası); THREAT güvenilir değil"}
	}
	if IsSuspectBroadRange(constraintType, constraint) {
		return &PolicyBlock{"broad_range",
			"CVE sürüm aralığı fazla geniş (büyük olasılıkla hatalı çıkarım); " +
				"yapısal doğrulama güvenilir değil"}
	}
	v := AssessThreatIdentity(inventory, description, yourVersion, constraint, matchSource)
	if v.Confirmed {
		return nil
	}
	if v.Reason != "" {
		return &PolicyBlock{"product_identity", v.Reason + " — THREAT güvenilir değil"}
	}
	// Yapısal kanıt yok. Ürün adı çakışmaları (Autodesk ↔ NetIQ "Identity
	// Manager", Visual J# ↔ Redis) burada elenir.
	return &PolicyBlock{"needs_structural",
		"ürün kimliği yapısal olarak doğrulanamadı; ad çakışmasından yanlış " +
			"pozitif riski"}
}

// --- yapısal sınır yolundaki kimlik kapıları -------------------------------
//
// Bu kapılar YAPISAL sınır (CNA/NVD) kararlarına uygulanır. Metin yolundaki
// politika katmanı buraya değmiyor (Python'da da değmiyor); bu kapılar o
// yoldan gelen kimlik hatalarını kapatır.

// İşletim sistemi adları. Bir CVE'nin ürünü işletim sisteminin KENDİSİyse, o
// sistem üzerinde çalışan bir UYGULAMAYA uygulanamaz.
var osProductNames = set(
	"android", "windows", "macos", "mac", "osx", "ios", "ipados", "tvos",
	"watchos", "linux", "chromeos", "unix", "solaris", "aix", "freebsd")

// IsOperatingSystemProduct: CVE'nin ürün alanı bir işletim sistemi mi?
//
// Satıcı ve tür kelimeleri atıldıktan sonra geriye yalnızca işletim sistemi
// adı (ve sürüm parçaları) kalıyorsa evet. "Google Android", "Microsoft, Inc
// Windows 11", "Apple macOS" böyledir.
func IsOperatingSystemProduct(cveProduct string) bool {
	ids := IdentityTokens(cveProduct)
	if len(ids) == 0 {
		return false
	}
	sawOS := false
	for t := range ids {
		switch {
		case osProductNames[t]:
			sawOS = true
		case isVersionish(t):
			// "11", "7.0" gibi sürüm parçaları ürünü değiştirmez.
		default:
			return false
		}
	}
	return sawOS
}

// isVersionish: "11", "7.0" gibi sürüm parçaları ürün kimliğini değiştirmez.
func isVersionish(t string) bool { return versionishRe.MatchString(t) }

// IsSameOperatingSystem: envanterdeki kalem o işletim sisteminin KENDİSİ mi?
//
// Ölçüt adın TAMAMI: "Windows App" (Microsoft'un uzak masaüstü istemcisi)
// kimlik tokenı olarak {windows}'a iniyor ama işletim sistemi değil.
func IsSameOperatingSystem(inventoryProduct string) bool {
	name := strings.ToLower(strings.TrimSpace(inventoryProduct))
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if !osProductNames[f] && !isVersionish(f) && f != "os" {
			return false
		}
	}
	return true
}

// OnlyCommonWordIdentity: CVE ürününün kimliği YALNIZCA yaygın kelimelerden mi
// oluşuyor?
//
// "IBM Secure Gateway" satıcı atılınca {secure, gateway}'e iner ve
// `CoversProduct` onu "Kestrel Secure Gateway"in alt kümesi sayar; o ürünün
// CVE'leri ilgisiz bir ürüne tehdit olarak yazılır. Yaygın bir kelime tek başına ürün
// kimliği kanıtı değildir.
func OnlyCommonWordIdentity(cveProduct string) bool {
	ids := IdentityTokens(cveProduct)
	if len(ids) == 0 {
		return false
	}
	for t := range ids {
		if !commonWords[t] {
			return false
		}
	}
	return true
}

// StructuredIdentityOK, yapısal sınırdan gelen bir THREAT'in ürün kimliğini
// denetler. Boş dize = geçti; doluysa ret gerekçesi.
func StructuredIdentityOK(cveProduct, inventoryProduct string) string {
	if cveProduct == "" {
		return ""
	}
	if IsOperatingSystemProduct(cveProduct) && !IsSameOperatingSystem(inventoryProduct) {
		return "CVE işletim sisteminin kendisine ait ('" + cveProduct +
			"'); envanterdeki '" + inventoryProduct + "' onun üzerinde çalışan bir uygulama"
	}
	// Adlar normalize edilmiş hâlde AYNIYSA kural işlemez: "Weather" ile
	// "Weather" gerçekten aynı üründür, yaygın kelime olması durumu değiştirmez.
	if NormalizeProductName(cveProduct) != NormalizeProductName(inventoryProduct) &&
		OnlyCommonWordIdentity(cveProduct) {
		return "CVE ürün kimliği yalnızca yaygın kelimelerden oluşuyor ('" +
			cveProduct + "'); ad çakışması"
	}
	return ""
}

// Doğrulanmış AYRI ürün çiftleri — envanter adı ile CVE ürün adı arasında.
//
// `knownCrossProduct` CVE METNİNE bakar; bu tablo CVE'nin ÜRÜN ALANINA bakar.
// İkisi ayrı: aşağıdaki çiftlerde açıklama bir çelişki işareti taşımıyor,
// ürün adları farklı olduğu hâlde kimlik-token kapsaması eşleşiyor.
//
// Dağıtımda her satır doğrulanmış bir çifttir; bu paketteki satırlar KURGUSALDIR.
var distinctProductPairs = []struct {
	inv    string // envanter adında geçmeli
	cve    string // CVE ürün adında geçmeli
	reason string
}{
	{"ravenmail", "ravenmail server", "Ravenmail istemcisi ≠ Ravenmail Server"},
	{"ravenmail", "ravenmail sdk", "Ravenmail istemcisi ≠ Ravenmail SDK kitaplığı"},
	{"pinecrest studio", "pinecrest", "Pinecrest Studio ≠ Pinecrest (eski bağımsız ürün)"},
	{"orchardsync", "orchardsync enterprise", "OrchardSync ≠ OrchardSync Enterprise sunucusu"},
	{"glasswing reader", "glasswing publisher", "Glasswing Reader ≠ Glasswing Publisher"},
}

// DistinctProductPair: envanter kalemi ile CVE ürünü bilinen AYRI ürünler mi?
func DistinctProductPair(cveProduct, inventoryProduct string) string {
	inv := inventoryCore(inventoryProduct)
	cve := normText(cveProduct)
	for _, p := range distinctProductPairs {
		if !strings.Contains(inv, p.inv) || !strings.Contains(cve, p.cve) {
			continue
		}
		// Envanterin KENDİSİ o ürünse çelişki yok ("OrchardSync Enterprise"
		// taranıyorsa o sunucunun CVE'si doğrudan onu ilgilendirir).
		//
		// Ölçüt TAM AD: `Contains` kullanmak "Pinecrest Studio" envanterini
		// "Pinecrest"ın kendisi sayar ve kuralı iptal eder.
		if inv == p.cve {
			continue
		}
		return p.reason
	}
	return ""
}
