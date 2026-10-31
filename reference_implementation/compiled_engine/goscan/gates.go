// Uygulanabilirlik kapıları — Python `refimpl/applicability.py` karşılığı.
//
// Ürün eşleşse bile CVE bu uç noktaya uygulanamayabilir: bu kapılar olmadan
// bir tarayıcı sorgusu "Google Chrome on Android" gibi başka platforma özgü
// kayıtları da tehdit olarak sayar.
package main

import (
	"regexp"
	"strings"
)

// OS ailesi kalıpları. Bir metinde BİRDEN ÇOK aile geçiyorsa karar
// verilmez — "Windows ve Linux'ta" diyen bir CVE ikisini de etkiler.
var osFamilyPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"windows", regexp.MustCompile(`(?i)\b(windows|win32|win64|winexec|windir|powershell|\.exe)\b`)},
	{"macos", regexp.MustCompile(`(?i)\b(macos|mac os|os x|osx|darwin|macintosh|\.dmg)\b`)},
	{"linux", regexp.MustCompile(`(?i)\b(linux|ubuntu|debian|red\s?hat|centos|fedora|glibc|\.deb|\.rpm)\b`)},
	{"android", regexp.MustCompile(`(?i)\b(android)\b`)},
	{"ios", regexp.MustCompile(`(?i)\b(ios|iphone|ipad|ipados)\b`)},
}

// OSFamily, metinden TEK bir OS ailesi saptanırsa onu döndürür.
func OSFamily(text string) string {
	found := ""
	n := 0
	for _, p := range osFamilyPatterns {
		if p.re.MatchString(text) {
			found = p.name
			n++
		}
	}
	if n == 1 {
		return found
	}
	return ""
}

// Web/CMS eklenti CVE'leri bir uç-nokta uygulama envanterine uygulanamaz.
var (
	webCMSRe     = regexp.MustCompile(`(?i)\b(wordpress|woocommerce|wp|drupal|joomla|typo3|magento|prestashop|elementor|jenkins|moodle|phpmyadmin|shopify|bigcommerce)\b`)
	pluginWordRe = regexp.MustCompile(`(?i)\b(plugin|add-?on|theme|widget)\b`)
	patchstackRe = regexp.MustCompile(`(?i)from n/?a through`)
)

// IsWebCMSPlugin: CVE bir web/CMS eklentisine mi ait?
//
// Dört sinyalden HERHANGİ biri yeterli — ölçüt ürün adında "plugin" kelimesi
// aramak DEĞİL. İlk yazımda öyleydi ve kapı neredeyse hiç yanmıyordu: "The
// MapSVG WordPress plugin before 6.2.20" kaydında ürün adı yalnızca "MapSVG";
// "plugin" kelimesi açıklamada. Aynı adlı bir masaüstü uygulamasında bu CVE
// tehdit olarak çıkar.
//
// İki muafiyet var ve ikisi de gerçek hatadan doğdu:
//   - Taranan ürünün KENDİSİ o CMS ise (WordPress taraması) kapı yanmamalı
//   - Taranan ürün eklentinin KENDİSİ ise (Formcrafter) kapı yanmamalı
func IsWebCMSPlugin(cveProduct, cveText, cveVendor, customerProduct string) bool {
	prod := strings.ToLower(cveProduct)
	customer := strings.ToLower(customerProduct)

	// Envanter ürünü CMS'in KENDİSİ ise çekirdek CVE'leri uygulanabilir;
	// aksi hâlde WordPress taraması kendi açıklarını eliyordu.
	if customer != "" && prod != "" && webCMSRe.MatchString(customer) && isHostCore(prod, customer) {
		return false
	}
	// Taranan ürün eklentinin TA KENDİSİyse yayılma yok, CVE doğrudan onu
	// ilgilendirir ("Formcrafter 4.2.9" sorgusu bu yüzden "etkilenmiyor"
	// diyordu).
	//
	// Ölçüt ÖZDEŞLİK, önek DEĞİL. Önek ölçütü çok gevşek: "Recipe Box" adı
	// "Recipe Box Importer"ın önekini oluşturur ve aynı adlı bir masaüstü
	// uygulaması bir WordPress eklentisinin CVE'lerini alır ("Weather" ↔
	// "Weather Widget Deluxe" aynı desen).
	//
	// CVE'nin TÜR kelimesi eklemesi ("... Plugin") özdeşliği bozmaz; ürün adı
	// eklemesi bozar.
	if customer != "" && prod != "" && samePluginIdentity(cveProduct, customerProduct) {
		return false
	}

	if webCMSRe.MatchString(prod + " " + strings.ToLower(cveText)) {
		return true
	}
	if pluginWordRe.MatchString(prod) {
		return true
	}
	if patchstackRe.MatchString(cveText) {
		return true
	}
	return webPluginVendors[strings.ToLower(strings.TrimSpace(cveVendor))]
}

// Yalnızca WordPress/CMS eklentisi üreten, bu yüzden masaüstü uygulamalarıyla
// ad çakışması yaratan satıcılar.
var webPluginVendors = set(
	"miniorange", "expresstechsoftware", "uncanny owl", "wpdeveloper",
	"themeisle", "wpmudev", "cyberlord92", "tmsproducts", "wpchill")

// Bir ürünün BAŞKA bir ürüne eklenti olduğunu gösteren ifadeler. "X for
// WordPress" kalıbı çekirdeği değil, ona takılan bileşeni adlandırır.
var addonPhraseRe = regexp.MustCompile(
	`(?i)\b(for|plugin|add-?on|theme|widget|extension|integration|connector|module)\b`)

// isHostCore: CVE ürünü, envanterdeki host uygulamanın KENDİSİ mi?
//
// "WordPress", "Automattic WordPress", "Drupal core" çekirdektir; "GetResponse
// for WordPress" ayrı bir eklentidir. Ayırt edici tokenlar host adından ÖNCE
// gelmeli — yani yalnızca satıcı öneki olmalı.
func isHostCore(cveProduct, customerProduct string) bool {
	if addonPhraseRe.MatchString(cveProduct) {
		return false
	}
	cveTokens := splitAlnum(cveProduct)
	hostTokens := splitAlnum(customerProduct)
	if len(hostTokens) == 0 {
		return false
	}
	hostSet := map[string]bool{}
	for _, t := range hostTokens {
		hostSet[t] = true
	}
	inCVE := map[string]bool{}
	for _, t := range cveTokens {
		inCVE[t] = true
	}
	for _, t := range hostTokens {
		if !inCVE[t] {
			return false
		}
	}
	// Host adı birden çok kez geçebilir ("WordPress.org WordPress"); kuyruk
	// hesabı SON geçtiği yerden başlar.
	last := -1
	for i, t := range cveTokens {
		if hostSet[t] {
			last = i
		}
	}
	for _, t := range cveTokens[last+1:] {
		if !genericProductTokens[t] {
			return false
		}
	}
	return true
}

func splitAlnum(s string) []string {
	out := []string{}
	for _, t := range nonAlnumRe.Split(strings.ToLower(s), -1) {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

var nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)

// SameProductHead: envanterdeki ad, CVE ürün adının BAŞINI mı oluşturuyor?
// Alt küme yerine ÖNEK aranır: adın kuyruğunda geçmesi aynı ürün olduğunu
// göstermez ("WordPress Countdown Timer" bir eklentidir).
func SameProductHead(cveProduct, inventoryProduct string) bool {
	cve := identitySequence(cveProduct)
	inv := identitySequence(inventoryProduct)
	if len(cve) == 0 || len(inv) == 0 || len(inv) > len(cve) {
		return false
	}
	for i, t := range inv {
		if cve[i] != t {
			return false
		}
	}
	return true
}

// identitySequence, `IdentityTokens` ile aynı bölmeyi kullanır ama SIRAYI korur
// (önek kıyaslaması için gerekli).
func identitySequence(name string) []string {
	out := []string{}
	for _, t := range identitySplitRe.Split(strings.Join(StripEditionTokens(name), " "), -1) {
		if len(t) >= 2 && !typeWords[t] {
			out = append(out, t)
		}
	}
	return out
}

// Bir ürünü diğerinden ayırmayan jenerik tokenlar — Python
// `GENERIC_PRODUCT_TOKENS` ile AYNI olmalı.
//
// Platform adları ("android", "windows", "macos") BİLEREK yok. Onları jenerik
// saymak "Android" CVE'sinin kimlik kanıtını sıfırlar ve "Android Photo
// Courier" gibi bir ürünün gerçek tehditleri kaçar: ürün adı da CVE adı da
// yalnızca "android" tokenını taşıyor ve o token atılınca ortak hiçbir şey
// kalmıyor. Platform ayrımı OS kapısının işi, kimlik kapısının değil.
var genericProductTokens = set(
	"additional", "agent", "and", "app", "application", "based", "browser",
	"chromium", "client", "common", "component", "components", "console",
	"core", "driver", "edition", "editor", "engine", "enterprise", "extension",
	"for", "framework", "health", "home", "host", "hub", "installer",
	"library", "manager", "manager.", "minimum", "module", "of", "package",
	"platform", "player", "plugin", "pro", "redist", "redistributable",
	"runtime", "sdk", "server", "service", "services", "shared", "software",
	"studio", "suite", "support", "system", "the", "tool", "tools", "update",
	"updates", "utilities", "utility", "viewer")

// ProductIdentityOK: CVE ürünü müşteri ürünüyle en az bir SPESİFİK token
// paylaşıyor mu? Yalnızca jenerik token içeren CVE ürünleri ("Agent",
// "Manager") kimlik kanıtı sayılmaz.
func ProductIdentityOK(cveProduct, customerProduct string) bool {
	cve := tokenize(cveProduct)
	cust := tokenize(customerProduct)
	specific := map[string]bool{}
	for t := range cve {
		if !genericProductTokens[t] {
			specific[t] = true
		}
	}
	if len(specific) == 0 {
		return false
	}
	for t := range specific {
		if cust[t] {
			return true
		}
	}
	return false
}

func tokenize(name string) map[string]bool {
	out := map[string]bool{}
	for _, t := range regexp.MustCompile(`[^a-z0-9]+`).Split(strings.ToLower(name), -1) {
		if t != "" {
			out[t] = true
		}
	}
	return out
}

// GateResult, bir kapının verdiği ret gerekçesi. Boşsa kapı yanmadı.
type GateResult struct {
	Kind   string
	Reason string
}

// ApplyGates, CVE'nin bu uç noktaya uygulanabilirliğini denetler.
//
// `endpointOS` çağırandan gelen işletim sistemidir; boşsa OS kapısı
// çalışmaz — bilinmeyen ortamdan çelişki çıkarılamaz.
func ApplyGates(cveProduct, cveVendor, cveText, customerProduct, customerVendor, endpointOS string) *GateResult {
	if endpointOS != "" {
		epFam := OSFamily(endpointOS + " " + customerProduct)
		cveFam := OSFamily(cveProduct + " " + cveText)
		if epFam != "" && cveFam != "" && epFam != cveFam {
			return &GateResult{"os",
				"CVE " + cveFam + " platformuna özgü; uç nokta " + epFam}
		}
		if PlatformDeclaredUnaffected(cveText, endpointOS) {
			return &GateResult{"os",
				"CVE metni bu platformu açıkça etkilenmiyor ilan ediyor"}
		}
	}
	// Ürün kimliği kapısı: CVE'nin adlandırdığı şey ile envanterdeki kalem
	// FARKLI ürünler mi? Bu denetim sürüm yolundan BAĞIMSIZ olmalı — yalnızca
	// yapısal yükseltmeye bağlanırsa metin yolu THREAT dediğinde atlanır ve
	// "Brightfield Weather Monitor"a başka bir satıcının "Weather Monitor"
	// CVE'si yazılmaya devam eder.
	if r := StructuredIdentityOK(cveProduct, customerProduct); r != "" {
		return &GateResult{"identity", r}
	}
	if r := DistinctProductPair(cveProduct, customerProduct); r != "" {
		return &GateResult{"identity", r}
	}
	if IsWebCMSPlugin(cveProduct, cveText, cveVendor, customerProduct) {
		return &GateResult{"web_plugin",
			"CVE bir web/CMS eklentisine ait ('" + cveProduct + "')"}
	}
	if VendorNotApplicable(cveVendor, customerVendor, cveProduct) {
		return &GateResult{"vendor",
			"CVE satıcısı '" + cveVendor + "' ürün satıcısıyla çelişiyor"}
	}
	return nil
}

// "... are not affected" ifadesinden ÖNCE gelen kısım. Satıcı bültenleri
// etkilenmeyen platformları böyle sayıyor ve bu cümle `OSFamily`'yi işlevsiz
// bırakıyor: tek metinde altı işletim sistemi geçtiği için "birden çok aile →
// karar verme" kuralı devreye giriyor ve kapı hiç yanmıyor.
var notAffectedRe = regexp.MustCompile(`(?i)([^.;]{0,240}?)\b(?:are|is)\s+not\s+affected`)

// PlatformDeclaredUnaffected: CVE metni uç noktanın platformunu AÇIKÇA
// etkilenmiyor ilan ediyor mu?
//
// "...in the Woodgrove Sync Agent for Windows ... Woodgrove Sync Agent for
// macOS, Linux, iOS and Android is not affected." — macOS uç noktasında bu
// bir tehdit değil.
//
// Ölçüt dar: yalnızca ifadeden ÖNCEKİ kısımda uç noktanın ailesi geçiyorsa
// yanar. "Versions before 3.2 are not affected" gibi cümlelerde platform tokenı
// olmadığı için kapı sessiz kalır.
func PlatformDeclaredUnaffected(cveText, endpointPlatform string) bool {
	if cveText == "" || endpointPlatform == "" {
		return false
	}
	fam := OSFamily(endpointPlatform)
	if fam == "" {
		return false
	}
	var famRe *regexp.Regexp
	for _, p := range osFamilyPatterns {
		if p.name == fam {
			famRe = p.re
			break
		}
	}
	if famRe == nil {
		return false
	}
	for _, m := range notAffectedRe.FindAllStringSubmatch(cveText, -1) {
		if famRe.MatchString(strings.ToLower(m[1])) {
			return true
		}
	}
	return false
}

// Başka bir platforma özgülüğü belli eden işaretler.
var otherPlatformTokens = []string{
	"android", "ios", "iphone", "ipad", "ipados", "macos", "mac os",
	"linux", "ubuntu", "debian", "android.", "for android", "for ios",
}

// PlatformMismatch: CVE açıkça başka bir platforma özgü ve müşteri kaydında o
// platform ipucu yok mu? True ise YAPISAL SINIRDAN yükseltme engellenir.
//
// Metin müşterinin KENDİ platformunu da anıyorsa uyuşmazlık YOKTUR. Bazı
// bültenler bir açığın düzeltildiği tüm platformları tek cümlede sayıyor
// ("fixed in Orbital Browser 12.5, iOS 18.7, macOS 15.5"); yalnızca
// "başka platform geçiyor mu" diye bakmak burada "ios" görüp macOS uç noktası
// için uyuşmazlık ilan eder ve gerçek tehditleri kaçırır.
func PlatformMismatch(cveProduct, cveText, customerProduct, customerPlatform string) bool {
	hay := strings.ToLower(cveProduct + " " + cveText)
	cust := strings.ToLower(customerProduct + " " + customerPlatform)
	for _, tok := range otherPlatformTokens {
		if strings.Contains(cust, tok) && strings.Contains(hay, tok) {
			return false
		}
	}
	for _, tok := range otherPlatformTokens {
		if strings.Contains(hay, tok) && !strings.Contains(cust, tok) {
			return true
		}
	}
	return false
}

// Platform tokenları ürün kimliğinin PARÇASI değildir: envanter "Proseware Driftguard
// Backup For Mac" yazarken CVE yalnızca "Proseware Driftguard Backup" der.
var platformTokens = set(
	"windows", "win", "win32", "win64", "mac", "macos", "osx", "linux",
	"unix", "android", "ios", "ipados", "x64", "x86", "arm64", "aarch64",
	"32bit", "64bit")

// samePluginIdentity: CVE ürünü ile envanter kalemi AYNI eklenti mi?
//
// Tür ve eklenti kelimeleri atıldıktan sonra kimlik tokenları birebir aynı
// olmalı. Kapsama yeterli değil — kapsama, envanterdeki kısa jenerik adı
// eklentinin kendisi sayıyordu.
func samePluginIdentity(cveProduct, customerProduct string) bool {
	strip := func(name string) map[string]bool {
		out := map[string]bool{}
		for t := range IdentityTokens(name) {
			if pluginWordRe.MatchString(t) {
				continue
			}
			out[t] = true
		}
		return out
	}
	a, b := strip(cveProduct), strip(customerProduct)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	return sameSet(a, b)
}
