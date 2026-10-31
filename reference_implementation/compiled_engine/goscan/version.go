// Sürüm ayrıştırma ve sınır çözümü.
//
// Bu dosya Python tarafındaki `refimpl/versioning/parser.py` ile
// `refimpl/scanner.py::_resolve_single_range` kurallarının birebir karşılığıdır.
// Buradaki her kural gerçek bir yanlış karardan doğdu; `parity_test.go` ikisinin
// aynı sonucu verdiğini altın küme üzerinde doğrular. Kuralı değiştirirken
// Python tarafını da değiştirin, yoksa iki uygulama sessizce ayrışır.
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Version, noktayla ayrılmış sürüm bileşenleri + SemVer ön sürüm eki +
// OpenSSL tarzı sondaki harf (1.0.1f).
type Version struct {
	Parts      []int
	Letter     string // "f" — harfsiz sürüm harflidan ÖNCE gelir
	PreRelease string // "rc1" — ön sürüm, harfsizden ÖNCE gelir
	Raw        string
}

var (
	// Sürüm gibi görünmeyen sınır değerlerini elemek için (URL, "unspecified").
	versionLikeRe = regexp.MustCompile(`^[vV]?\d[\w.\-+:]*$`)

	// Linux kernel CNA'sı sınır olarak GIT COMMIT HASH'i bildiriyor. Rakamla
	// başlayan bir hash sürüm kalıbına uyuyor; sürüm sanılınca "4.14.0 iki hash
	// arasında" gibi anlamsız kararlar üretir.
	commitHashRe = regexp.MustCompile(`^[0-9a-f]{12,40}$`)
	hexLetterRe  = regexp.MustCompile(`[a-f]`)

	releaseLineRe   = regexp.MustCompile(`^\d+(\.\d+)*$`)
	versionInTextRe = regexp.MustCompile(`\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.]+)?`)

	versionCoreRe = regexp.MustCompile(`^[vV]?(\d+(?:\.\d+)*)([a-zA-Z])?(?:-([0-9A-Za-z.]+))?`)
)

// looksLikeCommitHash: noktasız, 12+ karakterlik, en az bir a-f harfi taşıyan
// saf onaltılık dizge. Saf rakamdan oluşan build numaraları ("202401011200")
// bu kurala takılmaz.
func looksLikeCommitHash(text string) bool {
	lowered := strings.ToLower(text)
	return !strings.Contains(lowered, ".") &&
		commitHashRe.MatchString(lowered) &&
		hexLetterRe.MatchString(lowered)
}

// CleanBound, sürüm gibi görünmeyen sınır değerlerini eler.
func CleanBound(value string) string {
	text := strings.TrimSpace(value)
	if text == "" || len(text) > 40 || looksLikeCommitHash(text) {
		return ""
	}
	if !versionLikeRe.MatchString(text) {
		return ""
	}
	return text
}

// CleanVersionString, envanter sürüm alanından karşılaştırılabilir sürümü
// çıkarır: AnyDesk "ad 9.7.3" yazıyor. Tek başına duran sayılar ("2026") kasten
// kabul edilmez — yıl ya da derleme olabilir.
func CleanVersionString(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" || releaseLineRe.MatchString(text) {
		return text
	}
	if m := versionInTextRe.FindString(text); m != "" {
		return m
	}
	return text
}

// ParseVersion, sürüm dizgesini karşılaştırılabilir hâle getirir.
// Ayrıştırılamıyorsa nil döner — karar verilmez, uydurulmaz.
func ParseVersion(raw string) *Version {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	m := versionCoreRe.FindStringSubmatch(text)
	if m == nil {
		return nil
	}
	parts := []int{}
	for _, seg := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(seg)
		if err != nil {
			return nil
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return nil
	}
	return &Version{
		Parts:      parts,
		Letter:     strings.ToLower(m[2]),
		PreRelease: m[3],
		Raw:        text,
	}
}

// Compare: -1, 0, +1.
//
// Eksik bileşen SIFIR sayılır ("9.0" ile "9.0.0" aynı sürümdür). Bu, kayıt
// biçimleri arasındaki farkı yutmak için gerekli; derleme numarası taşıyan
// sürümler (5.2.8.3141) ise gerçekten daha büyüktür ve `IsBuildOf` ile ayrıca
// ele alınır.
func (v *Version) Compare(other *Version) int {
	n := len(v.Parts)
	if len(other.Parts) > n {
		n = len(other.Parts)
	}
	for i := 0; i < n; i++ {
		a, b := 0, 0
		if i < len(v.Parts) {
			a = v.Parts[i]
		}
		if i < len(other.Parts) {
			b = other.Parts[i]
		}
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	// OpenSSL tarzı harf: harfsiz < harfli (1.0.1 < 1.0.1a < 1.0.1f).
	if v.Letter != other.Letter {
		if v.Letter < other.Letter {
			return -1
		}
		return 1
	}
	// SemVer: ön sürümlü, ön sürümsüzden ÖNCE gelir (1.0.0-rc1 < 1.0.0).
	if v.PreRelease != other.PreRelease {
		if v.PreRelease != "" && other.PreRelease == "" {
			return -1
		}
		if v.PreRelease == "" && other.PreRelease != "" {
			return 1
		}
		if v.PreRelease < other.PreRelease {
			return -1
		}
		return 1
	}
	return 0
}

func (v *Version) Less(o *Version) bool    { return v.Compare(o) < 0 }
func (v *Version) LessEq(o *Version) bool  { return v.Compare(o) <= 0 }
func (v *Version) Equal(o *Version) bool   { return v.Compare(o) == 0 }
func (v *Version) Major() int              { return v.Parts[0] }

// IsBuildOf: `version`, `release` sürümünün bir DERLEMESİ mi?
//
// Windows envanterleri sürümü derleme numarasıyla bildirebilir: envanter
// "5.2.8.3141" der, CVE kaydı "5.2.8 ve altı" der. Saf sayısal kıyas
// 5.2.8.3141'i üstte görür ve sürümü etkilenmiyor sayar.
//
// Ölçüt NOKTA SINIRINDA ön ek olmak: "5.2.80" bu kurala takılmaz. Yalnızca
// kapsayıcı üst sınırlarda (`<=`) kullanılır; dışlayıcı sınırda (`< 5.2.8`)
// 5.2.8 zaten düzeltilmiş sürümdür.
func IsBuildOf(version, release string) bool {
	version = strings.TrimSpace(version)
	release = strings.TrimSpace(release)
	if version == "" || release == "" || version == release {
		return false
	}
	if !releaseLineRe.MatchString(version) || !releaseLineRe.MatchString(release) {
		return false
	}
	return strings.HasPrefix(version, release+".")
}

// Bound, bir CVE'nin tek bir etkilenen aralığı.
type Bound struct {
	LessThan        string
	LessThanOrEqual string
	GreaterEqual    string
	GreaterThan     string // NVD versionStartExcluding — sınırın KENDİSİ etkilenmiyor
	ExactVersion    string // sınır yoksa `version` TAM SÜRÜM kısıtıdır
	DefaultStatus   string // "affected" ise sayılmayan sürümler de etkilenmiştir
	Product         string
	Vendor          string
	Source          string // "" (CNA) | "nvd-cpe"
	Text            string
}

// Resolution, bir aralığın verdiği karar.
type Resolution struct {
	Verdict        string // THREAT | SAFE
	Reason         string
	ConstraintType string // lt | le | ge | range | eq | neq
	Constraint     string
}

// resolveExact: üst sınır yok, elde tam sürüm var — eşitlik kıyası.
//
// CNA'ların bir bölümü etkilenen sürümleri aralık yerine tek tek sayıyor
// ("BrightwaveOS 4.8.3, 4.6.7"). Sürüm listede yoksa SAFE denir, ama YALNIZCA
// defaultStatus 'affected' DEĞİLSE — 'affected' olduğunda liste bir örnektir
// ve aynı çıkarım kaçan tehdit üretir.
func resolveExact(version string, pv *Version, b Bound) *Resolution {
	exact := CleanBound(b.ExactVersion)
	if exact == "" {
		return nil
	}
	pe := ParseVersion(exact)
	if pe == nil {
		return nil
	}
	if pv.Equal(pe) {
		return &Resolution{"THREAT", version + " == " + exact + " (listed as affected)", "eq", exact}
	}
	if strings.ToLower(b.DefaultStatus) == "affected" {
		return nil
	}
	return &Resolution{"SAFE", version + " != " + exact + " (not in affected list)", "neq", exact}
}

// ResolveSingleRange, tek bir aralıkla deterministik karar verir.
func ResolveSingleRange(version string, b Bound) *Resolution {
	pv := ParseVersion(version)
	if pv == nil {
		return nil // müşteri sürümü ayrıştırılamıyor → karar verme
	}

	upper := CleanBound(b.LessThan)
	upperExcl := upper != ""
	if upper == "" {
		upper = CleanBound(b.LessThanOrEqual)
	}
	if upper == "" {
		return resolveExact(version, pv, b)
	}
	pu := ParseVersion(upper)
	if pu == nil {
		return nil
	}

	var belowUpper bool
	if upperExcl {
		belowUpper = pv.Less(pu)
	} else {
		belowUpper = pv.LessEq(pu) || IsBuildOf(version, upper)
	}
	if !belowUpper {
		op, ct := ">", "le"
		if upperExcl {
			op, ct = ">=", "lt"
		}
		return &Resolution{"SAFE", version + " " + op + " " + upper + " (fixed)", ct, upper}
	}

	lower := CleanBound(b.GreaterEqual)
	lowerExcl := false
	if lower == "" {
		lower = CleanBound(b.GreaterThan)
		lowerExcl = lower != ""
	}
	pl := ParseVersion(lower)
	// Geçerli aralık lower < upper gerektirir. Bazı satırlar bitiş sürümünü
	// greater_equal'e de kopyalayıp [X, X) gibi BOŞ aralık üretiyor; bu, X'ten
	// küçük her sürümü yanlışlıkla SAFE yapardı.
	if pl != nil && pl.Compare(pu) >= 0 {
		pl = nil
	}
	span := "[" + lower + ", " + upper + ")"
	if lowerExcl {
		span = "(" + lower + ", " + upper + ")"
	}
	if pl != nil {
		below := pv.Less(pl)
		if lowerExcl {
			below = pv.LessEq(pl)
		}
		if below {
			op := "<"
			if lowerExcl {
				op = "<="
			}
			return &Resolution{"SAFE", version + " " + op + " " + lower +
				" (affected range starts at " + lower + ")", "range", span}
		}
		op := "<="
		if lowerExcl {
			op = "<"
		}
		return &Resolution{"THREAT", lower + " " + op + " " + version + " < " + upper, "range", span}
	}
	ct := "le"
	if upperExcl {
		ct = "lt"
	}
	return &Resolution{"THREAT", version + " < " + upper, ct, upper}
}

func sameBranch(version, bound string) bool {
	pv, pb := ParseVersion(version), ParseVersion(bound)
	return pv != nil && pb != nil && pv.Major() == pb.Major()
}

// branchSpecificRanges, çok dallı CVE'lerde müşterinin dalına ait aralıkları
// seçer. Alt sınırsız bir satırı ("<= 11.0.14") başka dalın sürümüyle
// kıyaslamak 9.0.90'ı da etkilenmiş sayardı.
func branchSpecificRanges(version string, ranges []Bound) []Bound {
	if len(ranges) <= 1 {
		return ranges
	}
	same := make([]Bound, 0, len(ranges))
	for _, b := range ranges {
		ref := CleanBound(b.LessThan)
		for _, alt := range []string{b.LessThanOrEqual, b.GreaterEqual, b.ExactVersion} {
			if ref != "" {
				break
			}
			ref = CleanBound(alt)
		}
		if sameBranch(version, ref) {
			same = append(same, b)
		}
	}
	if len(same) > 0 {
		return same
	}
	return ranges
}

// ResolveBounds, bir CVE'nin TÜM aralıklarına bakarak karar verir.
//
// Sürüm herhangi bir aralığa düşüyorsa ürün etkilenmiştir; ilk THREAT kazanır.
// Aralıktan gelen SAFE, tam sürüm listesinden gelen SAFE'ten ("neq") güçlüdür.
func ResolveBounds(version string, ranges []Bound) *Resolution {
	if len(ranges) == 0 {
		return nil
	}
	var safe, weakSafe *Resolution
	for _, b := range branchSpecificRanges(version, ranges) {
		r := ResolveSingleRange(version, b)
		if r == nil {
			continue
		}
		if r.Verdict == "THREAT" {
			return r
		}
		if r.ConstraintType == "neq" {
			if weakSafe == nil {
				weakSafe = r
			}
		} else if safe == nil {
			safe = r
		}
	}
	if safe != nil {
		return safe
	}
	return weakSafe
}

// VersionSchemeMismatch: iki sürüm FARKLI numaralandırma sistemleri kullanıyor
// ve kıyaslanmamalı mı?
//
// Python `version_scheme_mismatch` karşılığı. Gerçek örnek: envanterdeki
// "Automator 2.10" ile CVE'deki "ConnectWise Automate 2020.5.178". Sayısal
// kıyas 2.10 < 2020.5.178 diyor ve tehdit üretiyor; oysa ikisi aynı sistemde
// numaralanmıyor bile. Böyle durumlarda karar verilmez — UNCERTAIN doğru cevap.
func VersionSchemeMismatch(a, b *Version) bool {
	if a == nil || b == nil {
		return false
	}
	lo, hi := a.Major(), b.Major()
	if lo > hi {
		lo, hi = hi, lo
	}
	if lo == 0 {
		return hi >= 500 // "0.8" ile "8684" (build numarası)
	}
	// Küçük major (< 20) ile büyük major (>= 50): 1.0.0 ile 111.0.x
	if (a.Major() < 20 && b.Major() >= 50) || (b.Major() < 20 && a.Major() >= 50) {
		return true
	}
	ratio := float64(hi) / float64(lo+1)
	if ratio <= 50 {
		return false
	}
	part := func(v *Version, i int) int {
		if i < len(v.Parts) {
			return v.Parts[i]
		}
		return 0
	}
	bigSingle := (a.Major() >= 500 && part(a, 1) == 0 && part(a, 2) == 0) ||
		(b.Major() >= 500 && part(b, 1) == 0 && part(b, 2) == 0)
	smallSemantic := (a.Major() < 100 && (part(a, 1) != 0 || part(a, 2) != 0)) ||
		(b.Major() < 100 && (part(b, 1) != 0 || part(b, 2) != 0))
	return bigSingle || smallSemantic
}
