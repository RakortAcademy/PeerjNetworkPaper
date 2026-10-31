// Ürün adı normalizasyonu, kimlik karşılaştırması ve uygulanabilirlik kapıları.
//
// Python karşılığı: `refimpl/fuzzy/matcher.py`, `refimpl/disambiguation.py`,
// `refimpl/applicability.py`. Buradaki kuralların HEPSİ gerçek bir yanlış karardan
// doğdu; `parity_test.go` ikisinin aynı sonucu verdiğini doğrular.
package main

import (
	"regexp"
	"sort"
	"strings"
)

// --- normalizasyon --------------------------------------------------------

var (
	trademarkRe     = regexp.MustCompile(`(?i)\((?:tm|r|c)\)|[™®©]`)
	fileExtRe       = regexp.MustCompile(`(?i)\.(exe|msi|dmg|pkg|deb|rpm|appx|msix|jar|zip)\b`)
	parentheticalRe = regexp.MustCompile(`\([^)]*\)`)
	forPlatformRe   = regexp.MustCompile(`(?i)\s+for\s+(windows|linux|mac|macos|android|ios)\b`)
	turkishSuffixRe = regexp.MustCompile(`(?i)\s+(Çalışma Zamanı|Yazılımı|Uygulaması|Programı|Sürümü|İstemcisi|Sunucusu)$`)
	nonWordRe       = regexp.MustCompile(`[^\w]`)
	// Kimlik çekirdeğinde tam sürümler atılır.
	versionishRe = regexp.MustCompile(`^v?\d+(\.\d+)*$`)
	// Normalizasyonda YALNIZCA noktalı sürümler atılır: "2015" bir yıl/edisyon
	// işaretidir ve ürünü ayırt eder ("Visual C++ 2015" ≠ "Visual Studio").
	dottedVersionRe = regexp.MustCompile(`^\d+\.\d+`)
	// Python yalnızca "(64-bit)" ve "(x64)" parantezlerini atıyor; hepsini
	// atmak "Quill++ (64-bit x64)" dışındaki anlamlı ekleri de siliyordu.
	bitParenRe = regexp.MustCompile(`(?i)\s*\(\s*(?:64|32)\s*[-]?\s*bit\s*\)`)
	x64ParenRe = regexp.MustCompile(`(?i)\s*\(\s*x64\s*\)`)
	yearRe     = regexp.MustCompile(`^(19|20)\d{2}$`)
	// `StripEditionTokens` nokta ve tireyi KORUR (sürüm/edisyon ayıklarken
	// "14.40.33810" tek parça kalmalı).
	splitRe = regexp.MustCompile(`[^a-z0-9.+#-]+`)
	// `IdentityTokens` ise nokta ve tireden DE böler. Python'da bu iki regex
	// farklı; aynı sanmak "relaydesk-client"ı tek kimlik tokenı yapıyordu ve
	// "relaydesk-client Relaydesk Client" ile "Relaydesk" eşleşmiyordu —
	// tehditler böyle kaçar.
	identitySplitRe = regexp.MustCompile(`[^a-z0-9+#]+`)
	camelRe         = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	segSplitRe      = regexp.MustCompile(`[\s_/\\-]+`)
)

var installerTokens = set(
	"setup", "installer", "install", "uninstall", "x64", "x86", "amd64",
	"arm64", "win32", "win64", "32bit", "64bit", "bit", "msi", "exe",
	"package", "bundle", "redist", "redistributable", "offline", "online")

// KİMLİK çekirdeği için atılan tokenlar (Python `disambiguation._EDITION_TOKENS`).
// Bu küme GENİŞtir ve yalnızca `StripEditionTokens` içinde kullanılır.
var editionTokens = set(
	"professional", "pro", "plus", "standard", "home", "enterprise", "business",
	"premium", "basic", "starter", "ultimate", "essentials", "express",
	"ltsc", "ltsb", "dc", "classic", "legacy", "preview", "beta", "rc",
	"x64", "x86", "amd64", "arm64", "win32", "win64", "32bit", "64bit",
	"bit", "edition", "version", "setup", "installer", "runtime", "redistributable",
	"tr-tr", "en-us", "language", "pack", "update", "kb")

// NORMALİZASYON için atılan tokenlar (Python `fuzzy/matcher.py`). Yukarıdakinden
// AYRI ve çok daha DAR — ikisini karıştırmak "Microsoft Visual C++ 2015-2022
// Redistributable" adını "microsoft visual"a indiriyor ve o da "Microsoft
// Visual Studio" ile eşleşip yanlış tehdit üretiyordu.
var normalizeDropTokens = set(
	// mimari
	"x86", "x64", "x86_64", "arm", "arm64", "aarch64",
	"32-bit", "64-bit", "32bit", "64bit", "win32", "win64",
	// kanal
	"beta", "rc", "canary", "dev", "insider", "nightly", "preview",
	"alpha", "technical", "stable", "release",
	// paketleme
	"installer", "msi", "exe", "pkg", "dmg", "deb", "rpm", "setup",
	"appx", "snap", "flatpak",
	// dil
	"en-us", "en_us", "tr-tr", "tr_tr", "english", "türkçe", "turkce",
	"german", "de-de", "french", "fr-fr", "spanish", "japanese", "chinese",
	// edisyon
	"professional", "pro", "enterprise", "standard", "community",
	"education", "home", "ultimate", "ltsc", "ltsb", "lts", "dc")

var stopwords = set("the", "a", "an", "for", "by", "with", "in", "on", "at", "of",
	"and", "inc", "llc", "ltd", "corp", "corporation", "company", "co")

// Ürün TÜRÜNÜ belirten, kimliği değiştirmeyen kelimeler.
var typeWords = set(
	"server", "client", "service", "services", "software", "suite", "platform",
	"edition", "runtime", "framework", "sdk", "desktop", "application", "app",
	"system", "core", "base", "standard", "professional", "pro", "community",
	"enterprise", "open", "source", "product", "tool", "tools", "package",
	// satıcılar
	"apache", "oracle", "microsoft", "google", "adobe", "ibm", "cisco", "eclipse",
	"mozilla", "redhat", "vmware", "atlassian", "sun", "novell", "hp", "hpe",
	"dell", "sap", "corporation", "corp", "inc", "ltd", "gmbh", "foundation",
	"project", "the", "of", "for", "and")

var corporateSuffixes = set(
	"inc", "inc.", "ltd", "ltd.", "llc", "corp", "corp.", "corporation",
	"gmbh", "sa", "sas", "ag", "bv", "nv", "plc", "co", "company",
	"foundation", "project", "projects", "group", "development", "global",
	"software", "technologies", "technology", "systems", "solutions", "labs",
	"team", "community", "org", "the", "and", "of")

// Ortak kökten SONRA gelebilecek, ürünü DEĞİŞTİRMEYEN ekler.
var platformSuffixes = set(
	"windows", "win", "mac", "macos", "osx", "linux", "unix", "android",
	"ios", "ipados", "server", "desktop", "mobile", "web", "cloud",
	"vpn", "client", "agent", "standalone", "portable")

var vendorFiller = set(
	"apache", "microsoft", "oracle", "google", "ibm", "cisco", "adobe", "mozilla",
	"red", "hat", "redhat", "the", "inc", "ltd", "corp", "corporation", "gmbh",
	"foundation", "software", "project", "org", "team", "and", "for", "server",
	"client", "core", "edition", "suite", "platform")

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

// CleanInventoryName, envanterden gelen ham adı eşleştirilebilir hâle getirir.
// "TOMCAT9.EXE x64 setup" → "TOMCAT9"
func CleanInventoryName(name string) string {
	raw := strings.TrimSpace(name)
	if raw == "" {
		return ""
	}
	raw = trademarkRe.ReplaceAllString(raw, " ")
	raw = fileExtRe.ReplaceAllString(raw, " ")
	raw = parentheticalRe.ReplaceAllString(raw, " ")
	kept := []string{}
	for _, t := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '_' || r == '/' || r == '\\'
	}) {
		if !installerTokens[strings.ToLower(t)] {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		return strings.TrimSpace(raw)
	}
	return strings.Join(kept, " ")
}

// NormalizeProductName, arama ve önbellek anahtarının temeli.
func NormalizeProductName(name string) string {
	if name == "" {
		return ""
	}
	name = turkishSuffixRe.ReplaceAllString(name, "")
	name = forPlatformRe.ReplaceAllString(name, "")
	name = bitParenRe.ReplaceAllString(name, "")
	name = x64ParenRe.ReplaceAllString(name, "")
	name = strings.ToLower(name)
	name = strings.NewReplacer("_", " ", "/", " ", "\\", " ", "-", " ").Replace(name)
	out := []string{}
	for _, t := range strings.Fields(name) {
		if stopwords[t] {
			continue
		}
		if normalizeDropTokens[strings.ToLower(nonWordRe.ReplaceAllString(t, ""))] {
			continue
		}
		if dottedVersionRe.MatchString(t) {
			continue
		}
		t = nonWordRe.ReplaceAllString(t, "")
		if len(strings.TrimSpace(t)) > 1 {
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// StripEditionTokens, yıl/edisyon/mimari tokenlarını atarak kimlik çekirdeğini
// bırakır.
func StripEditionTokens(name string) []string {
	out := []string{}
	for _, t := range splitRe.Split(strings.ToLower(name), -1) {
		if t == "" || editionTokens[t] || yearRe.MatchString(t) || versionishRe.MatchString(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// IdentityTokens, adın kimliğini belirleyen tokenlar.
func IdentityTokens(name string) map[string]bool {
	out := map[string]bool{}
	for _, t := range identitySplitRe.Split(strings.Join(StripEditionTokens(name), " "), -1) {
		if len(t) >= 2 && !typeWords[t] {
			out[t] = true
		}
	}
	return out
}

// --- bitişik ürün aileleri ------------------------------------------------

// compoundSegments, adı hem CamelCase hem ayraç sınırlarında böler.
// "SkyDeskMac" → [sky desk mac]
func compoundSegments(name string) []string {
	spaced := camelRe.ReplaceAllString(name, "$1 $2")
	out := []string{}
	for _, p := range segSplitRe.Split(spaced, -1) {
		c := strings.ToLower(nonWordRe.ReplaceAllString(p, ""))
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// SameCompoundFamily: iki ad aynı ürün ailesinin farklı yapıları mı?
//
// Satıcıların bir bölümü ürün ailesini bitişik yazar (BrightwaveLinux,
// BrightwaveMac). Envanterde "Brightwave Agent" durur ve token kıyaslaması
// ortak TEK bir token bulamaz.
//
// İki şart: ortak bir ön ek olmalı VE ondan sonra kalan parçaların HEPSİ
// platform/edisyon eki olmalı. İkincisi olmadan "ChromeOS" ile "Chrome" aynı
// sayılırdı (biri tarayıcı, öteki işletim sistemi).
func SameCompoundFamily(first, second string) bool {
	a, b := compoundSegments(first), compoundSegments(second)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	// Katalog adı satıcıyla birleşik gelebiliyor ("Woodgrove BrightwaveLinux");
	// baştaki bir parçayı atarak da denenir.
	pairs := [][2][]string{{a, b}}
	if len(a) > 1 {
		pairs = append(pairs, [2][]string{a[1:], b})
	}
	if len(b) > 1 {
		pairs = append(pairs, [2][]string{a, b[1:]})
	}
	for _, pair := range pairs {
		if matchCompound(pair[0], pair[1]) {
			return true
		}
	}
	return false
}

func matchCompound(a, b []string) bool {
	pa, pb := prefixTails(a), prefixTails(b)
	root, best := "", -1
	for p := range pa {
		if _, ok := pb[p]; ok && len(p) > best {
			root, best = p, len(p)
		}
	}
	if root == "" {
		return false
	}
	tail := append(append([]string{}, pa[root]...), pb[root]...)
	if len(tail) == 0 {
		return false
	}
	for _, t := range tail {
		if !platformSuffixes[t] {
			return false
		}
	}
	return true
}

func prefixTails(segments []string) map[string][]string {
	out := map[string][]string{}
	acc := ""
	for i, s := range segments {
		acc += s
		out[acc] = segments[i+1:]
	}
	return out
}

// NamesConflict: iki ad farklı ürünleri mi anlatıyor?
func NamesConflict(first, second string) bool {
	a, b := stems(first), stems(second)
	if len(a) == 0 || len(b) == 0 {
		return false // karar verecek bilgi yok; engelleme
	}
	for t := range a {
		if b[t] {
			return false
		}
	}
	return !SameCompoundFamily(first, second)
}

var trailingDigitsRe = regexp.MustCompile(`\d+$`)

func stems(name string) map[string]bool {
	out := map[string]bool{}
	for t := range IdentityTokens(name) {
		s := trailingDigitsRe.ReplaceAllString(t, "")
		if s == "" {
			s = t
		}
		out[s] = true
	}
	return out
}

// CoversProduct: CVE ürünü envanterdeki ürünü kapsıyor mu?
// CoversProduct: CVE ürünü envanterdeki ürünü KAPSIYOR mu?
//
// Ölçüt YÖNLÜdür: CVE'nin kimlik tokenları envanterinkilerin ALT KÜMESİ olmalı.
// CVE daha genel adlandırma kullanabilir ("MySQL Server" ⊆ "MySQL"), ama ters
// yön kabul edilmez — bir bileşenin açığını tüm ürüne yaymak yanlış pozitif
// üretir. İki yönlü yapmak "InTouch Edge HMI"yi "Microsoft Edge" ile
// eşleştiriyordu.
func CoversProduct(cveProduct, inventoryProduct string) bool {
	cve, inv := IdentityTokens(cveProduct), IdentityTokens(inventoryProduct)
	if len(cve) == 0 || len(inv) == 0 {
		return false
	}
	return subset(cve, inv)
}

func subset(small, large map[string]bool) bool {
	for t := range small {
		if !large[t] {
			return false
		}
	}
	return true
}

// VendorsConflict: iki satıcı adı FARKLI satıcıları mı gösteriyor?
// Yalnızca kurumsal ekler atılır; "PostgreSQL" ile "PostgreSQL Global
// Development Group" aynı satıcıdır.
func VendorsConflict(first, second string) bool {
	a, b := vendorCore(first), vendorCore(second)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	for t := range a {
		if b[t] {
			return false
		}
	}
	return true
}

func vendorCore(name string) map[string]bool {
	out := map[string]bool{}
	for _, t := range regexp.MustCompile(`[^a-z0-9]+`).Split(strings.ToLower(name), -1) {
		if t != "" && !corporateSuffixes[t] {
			out[t] = true
		}
	}
	return out
}

// VendorNotApplicable: CVE'nin satıcısı envanterdekiyle ÇELİŞİYOR mu?
//
// Üç tuzak elenir: bilinmeyen satıcıdan çelişki çıkarılmaz; kurumsal ekler
// atılır; ve CNA satıcı alanına ÜRÜN adını yazmış olabilir (vendor="Glimmerpost",
// product="Glimmerpost") — böyle bir alan bilgi taşımaz.
//
// Son kuralın ölçütü ÖRTÜŞME değil ÖZDEŞLİKtir: "Fabrikam" ile "Fabrikam
// Calendar" token paylaşır ama satıcı alanı orada gerçek bilgi taşıyor.
func VendorNotApplicable(cveVendor, customerVendor, cveProduct string) bool {
	if strings.TrimSpace(customerVendor) == "" {
		return false
	}
	cveVendor = strings.TrimSpace(cveVendor)
	low := strings.ToLower(cveVendor)
	if cveVendor == "" || low == "n/a" || low == "na" || low == "unknown" || low == "-" {
		return false
	}
	if cveProduct != "" {
		vc := IdentityTokens(cveVendor)
		if len(vc) > 0 && sameSet(vc, IdentityTokens(cveProduct)) {
			return false
		}
	}
	return VendorsConflict(cveVendor, customerVendor)
}

func sameSet(a, b map[string]bool) bool {
	return len(a) == len(b) && subset(a, b)
}

// --- envanter kalemi türleri ----------------------------------------------

// Windows envanterleri kurulu YAMALARI da uygulama gibi listeliyor.
// Ürün sanılırsa adı "Windows" ile eşleşir ve güncelleyicinin sürümü
// Windows derleme numaralarıyla kıyaslanır ve yamanın kendisi açık görünür.
var updatePackageRe = regexp.MustCompile(
	`(?i)(\(\s*KB\d{5,}\s*\)|^\s*(security\s+)?update\s+for\b|^\s*hotfix\b|` +
		`^\s*cumulative\s+update\b|^\s*servicing\s+stack\s+update\b|` +
		`^\s*güvenlik\s+güncelleştirmesi\b|^\s*güncelleştirme\b)`)

func IsUpdatePackage(name string) bool { return updatePackageRe.MatchString(name) }

// Tek başına hiçbir ürünü tanımlamayan adlar — satıcı ya da OS şart.
var genericAppNames = set(
	"calendar", "notes", "photos", "mail", "messages", "maps", "music",
	"news", "podcasts", "reminders", "contacts", "clock", "weather",
	"calculator", "camera", "files", "gallery", "home", "health", "wallet",
	"books", "shortcuts", "stocks", "tips", "voice memos", "freeform",
	"terminal", "console", "settings", "preferences", "finder", "explorer",
	"store", "help", "search", "chat", "phone", "video", "player", "viewer",
	"editor", "browser", "monitor", "dashboard", "portal", "client", "agent",
	// "Apps" / "App Store": macOS envanterinde Apple'ın yer tutucu kayıtları.
	// Satıcı olmadan "Microsoft 365 Apps for Enterprise" ile eşleşiyorlardı.
	"app", "apps",
	"server", "manager", "updater", "installer", "launcher", "sync", "backup",
	"print", "scan", "paint", "screen", "keyboard", "mouse", "display")

func IsGenericProductName(name string) bool {
	core := StripEditionTokens(name)
	if len(core) == 0 {
		return true
	}
	if genericAppNames[strings.Join(core, " ")] {
		return true
	}
	if len(core) > 2 {
		return false
	}
	for _, t := range core {
		if !genericAppNames[t] {
			return false
		}
	}
	return true
}

// --- arama yardımcıları ---------------------------------------------------

func anchorToken(productNorm string) string {
	best := ""
	for _, t := range strings.Fields(productNorm) {
		if vendorFiller[t] {
			continue
		}
		t = trailingDigitsRe.ReplaceAllString(t, "")
		t = regexp.MustCompile(`[^a-z0-9]`).ReplaceAllString(t, "")
		if len(t) >= 4 && len(t) > len(best) {
			best = t
		}
	}
	return best
}

func discriminative(name string) []string {
	out := []string{}
	for _, t := range strings.Fields(strings.ToLower(name)) {
		s := trailingDigitsRe.ReplaceAllString(t, "")
		if len(s) >= 3 && !vendorFiller[s] {
			out = append(out, s)
		}
	}
	return out
}

// accepts: kayıt sorguyla ayırt edici bir sinyal paylaşıyor mu?
func accepts(productNorm, vendor string, c Candidate) bool {
	if productTokenOverlap(productNorm, c.Product) {
		return true
	}
	// Satıcı karşılaştırması birebir EŞİTLİK değil: envanter "Tailspin
	// Technologies Inc" yazıyor, CVE kaydı "Tailspin".
	if strings.TrimSpace(vendor) == "" || strings.TrimSpace(c.Vendor) == "" {
		return false
	}
	return !VendorsConflict(c.Vendor, vendor)
}

func productTokenOverlap(queryNorm, product string) bool {
	q := discriminative(queryNorm)
	if len(q) == 0 {
		return true
	}
	p := discriminative(NormalizeProductName(product))
	if len(p) == 0 {
		return true
	}
	for _, qt := range q {
		for _, pt := range p {
			if qt == pt {
				return true
			}
			short, long := qt, pt
			if len(pt) < len(qt) {
				short, long = pt, qt
			}
			if len(short) >= 4 && len(long)-len(short) <= 2 && strings.HasPrefix(long, short) {
				return true
			}
		}
	}
	// Bitişik yazılmış aileler buraya kadar gelir ("BrightwaveLinux" tek
	// token olduğu için uzunluk farkı kuralına takılır).
	return SameCompoundFamily(product, queryNorm)
}

// Paket ↔ bileşen tabloları. Envanter adları paketi ve bileşeni birlikte
// yazar ("Microsoft Office Word 2016"), CVE kayıtları ise ya bileşeni
// ("Microsoft Word") ya paketi ("Microsoft Office 2016") adlandırır.
var suites = []struct {
	name       string
	components map[string]bool
}{
	{"microsoft office", set("word", "excel", "powerpoint", "outlook", "access",
		"publisher", "onenote", "visio", "project", "skype", "teams", "sharepoint",
		"infopath", "lync", "groove")},
	{"adobe creative cloud", set("photoshop", "illustrator", "indesign", "premiere",
		"after effects", "acrobat", "lightroom", "animate", "audition", "dreamweaver")},
	{"libreoffice", set("writer", "calc", "impress", "draw", "base", "math")},
}

// SuiteComponent: ad bir paket bileşeniyse (paket, bileşen) döndürür. Bileşen
// boşsa ad PAKETİN KENDİSİDİR ve her bileşeni kapsar.
func SuiteComponent(name string) (suite, component string, ok bool) {
	core := strings.Join(StripEditionTokens(name), " ")
	if core == "" {
		return "", "", false
	}
	tokens := strings.Fields(core)
	for _, s := range suites {
		hit := strings.Contains(core, s.name)
		if !hit {
			for _, t := range tokens {
				if s.components[t] {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		// Birden çok bileşen geçiyorsa alfabetik ilki — Python ile aynı olmak
		// için; seçim keyfî ama İKİ tarafta da aynı olmak zorunda.
		present := []string{}
		for _, t := range tokens {
			if s.components[t] {
				present = append(present, t)
			}
		}
		if len(present) == 0 {
			return s.name, "", true
		}
		sort.Strings(present)
		return s.name, present[0], true
	}
	return "", "", false
}

// ComponentConflict: iki ad aynı paketin FARKLI bileşenleri mi?
//
// Word ↔ Excel adlarının çoğunu paylaşır ve bulanık eşleme onları aynı ürün
// sanar. Paketin kendisi (bileşensiz) her bileşeni kapsadığı için çakışma
// sayılmaz.
func ComponentConflict(cveProduct, customerProduct string) string {
	cveSuite, cveComp, ok1 := SuiteComponent(cveProduct)
	custSuite, custComp, ok2 := SuiteComponent(customerProduct)
	if !ok1 || !ok2 || cveSuite != custSuite {
		return ""
	}
	if cveComp == "" || custComp == "" || cveComp == custComp {
		return ""
	}
	return "CVE '" + cveProduct + "' bileşenini hedefliyor; envanterdeki ürün '" +
		customerProduct + "' aynı paketin farklı bir bileşeni (" +
		custComp + " ≠ " + cveComp + ")"
}

// MatchAliases, bir ürün adının eşleşmede denenecek eşdeğer biçimleri.
//
//	"Microsoft Office Word 2016" →
//	    ["microsoft office word", "microsoft word", "microsoft office"]
//
// Çıplak bileşen adı ("word") BİLEREK üretilmez: "WordPress" gibi ilgisiz
// ürünlere eşleşecek kadar jeneriktir.
func MatchAliases(name string) []string {
	core := strings.Join(StripEditionTokens(name), " ")
	out := []string{}
	if core != "" {
		out = append(out, core)
	}
	if suite, comp, ok := SuiteComponent(name); ok {
		if comp != "" {
			if head := strings.Fields(suite); len(head) > 0 {
				out = append(out, head[0]+" "+comp)
			}
		}
		out = append(out, suite)
	}
	seen := map[string]bool{}
	uniq := []string{}
	for _, a := range out {
		if a = strings.TrimSpace(a); a != "" && !seen[a] {
			seen[a] = true
			uniq = append(uniq, a)
		}
	}
	return uniq
}
