// Model çıktısının işlenmesi — Python `extractor._convert_to_json` karşılığı.
//
// Ağ ham etiket dizisi verir ("şu tokenlar ÜRÜN, şunlar SÜRÜM"). Tarayıcının
// istediği ise yapılandırılmış kısıt: `less_than`, `less_than_or_equal`,
// `greater_equal`, `app_version` ve karşılaştırılabilirliği belirleyen
// `version_scheme`. Dönüşüm burada.
package main

import (
	"regexp"
	"strconv"
	"strings"
)

// Extraction alanları `cve_extractions.payload` ile birebir aynı adlarda
// olmalı: Go bu satırları YAZIYOR ve Python aynı önbelleği okuyor.

// Sürüm kısıtı kalıpları. SIRA ÖNEMLİ ve rastgele değil:
//
//   - Tarih kalıpları en başta: "before 8/29/2019" sürüm kalıbına da uyar ve
//     8/29/2019 sürüm sanılırsa 8.0'dan büyük her sürüm tehdit görünür.
//   - Dar kalıplar ("affecting versions prior to X") genel olandan önce:
//     genel kalıp cümlenin başka bir yerindeki sayıyı yakalayabilir.
//   - "and later" ile "and earlier" ayrı: yönü ters çevirmek kararı ters çevirir.
var versionPatterns = []struct {
	re    *regexp.Regexp
	field string
}{
	{regexp.MustCompile(`(?i)(?:before|prior\s+to)\s+(\d{1,2}/\d{1,2}/\d{4})`), "less_than"},
	{regexp.MustCompile(`(?i)(?:before|prior\s+to)\s+(\d{4}-\d{2}-\d{2})`), "less_than"},
	{regexp.MustCompile(`(?i)affecting\s+versions?\s+(?:prior\s+to|before)\s+([vV]?[\d.]+)`), "less_than"},
	{regexp.MustCompile(`(?i)in\s+versions?\s+(?:prior\s+to|before)\s+([vV]?[\d.]+)`), "less_than"},
	{regexp.MustCompile(`(?i)(?:before|prior\s+to)\s+(?:version\s+)?([vV]?[\d.]+)`), "less_than"},
	{regexp.MustCompile(`(?i)([vV]?[\d.]+)\s+and\s+prior\s+versions?`), "less_than_or_equal"},
	{regexp.MustCompile(`(?i)versions?\s+([vV]?[\d.]+)\s+and\s+earlier`), "less_than_or_equal"},
	{regexp.MustCompile(`<=\s*([vV]?[\d.]+)`), "less_than_or_equal"},
	{regexp.MustCompile(`<\s*([vV]?[\d.]+)`), "less_than"},
	{regexp.MustCompile(`(?i)(?:through|up\s+to)\s+([vV]?[\d.]+)`), "less_than_or_equal"},
	{regexp.MustCompile(`(?i)([vV]?[\d.]+)\s+and\s+earlier`), "less_than_or_equal"},
	{regexp.MustCompile(`(?i)([vV]?[\d.]+)\s+and\s+later`), "greater_equal"},
}

var (
	geFromRe      = regexp.MustCompile(`(?i)(?:>=|from)\s+([vV]?[\d.]+)`)
	dottedRe      = regexp.MustCompile(`[vV]?[\d]+\.[\d]+(?:\.[\d]+)*`)
	leadingVRe    = regexp.MustCompile(`^[vV]`)
	trailingParen = regexp.MustCompile(`\)[,\s].*$`)
	trailingDots  = regexp.MustCompile(`\.+$`)
	trailingWord  = regexp.MustCompile(`(?i)\.(This|The|It|In|An|A)$`)
	intOnlyRe     = regexp.MustCompile(`^\d+$`)
	datePatterns  = []*regexp.Regexp{
		regexp.MustCompile(`^\d{1,2}/\d{1,2}/\d{4}$`),
		regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`),
		regexp.MustCompile(`^\d{1,2}\.\d{1,2}\.\d{4}$`),
		regexp.MustCompile(`^\d{4}/\d{2}/\d{2}$`),
	}
	monthDayRe = regexp.MustCompile(`(?i)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}`)
	year4Re    = regexp.MustCompile(`\d{4}`)
)

// BuildExtraction, model tahminini tarayıcının kullandığı kısıt yapısına çevirir.
func BuildExtraction(pred Prediction, description string) Extraction {
	e := Extraction{AppName: cleanProductName(pred.Product)}
	fillVersionInfo(&e, pred.Version, description)
	e.VersionScheme = inferVersionScheme(e)
	return e
}

// cleanProductName, cümle sonu artıklarını atar. Model son tokenı ürüne dahil
// ettiğinde "Foo.This" gibi adlar çıkıyor ve arama hiçbir şey bulmuyor.
func cleanProductName(name string) string {
	name = trailingWord.ReplaceAllString(strings.TrimSpace(name), "")
	return strings.Trim(name, " .,;:")
}

// fillVersionInfo, önce modelin SÜRÜM olarak etiketlediği metne, sonra tüm
// açıklamaya bakar.
//
// Neden açıklamaya da bakılıyor: model çoğu kez sayıyı buluyor ama YÖNÜ
// ("prior to" mu "and later" mı) etiketlemiyor — yön cümlenin kelimelerinde.
func fillVersionInfo(e *Extraction, versionText, description string) {
	full := strings.TrimSpace(versionText + " " + description)
	if full == "" {
		return
	}
	for _, p := range versionPatterns {
		m := p.re.FindStringSubmatch(full)
		if m == nil {
			continue
		}
		v := normalizeVersion(m[1])
		switch p.field {
		case "less_than":
			e.LessThan = v
		case "less_than_or_equal":
			e.LessThanOrEqual = v
		case "greater_equal":
			e.GreaterEqual = v
		}
		// İlk eşleşen kalıp kazanır: kalıplar dardan genele sıralı, sonraki
		// eşleşmeler cümlenin başka yerinden gelir ve daha zayıftır.
		return
	}
	if m := geFromRe.FindStringSubmatch(full); m != nil {
		e.GreaterEqual = normalizeVersion(m[1])
	}
	// Kesin sürüm YALNIZCA modelin sürüm olarak etiketlediği metinden alınır
	// ve hiçbir aralık bulunmadıysa. Açıklamadan alınsaydı cümledeki herhangi
	// bir sayı (CVSS puanı, yıl) kesin sürüm sanılırdı.
	if e.LessThan == "" && e.LessThanOrEqual == "" && e.GreaterEqual == "" {
		if m := dottedRe.FindString(versionText); m != "" {
			e.AppVersion = normalizeVersion(m)
		}
	}
}

func normalizeVersion(s string) string {
	s = leadingVRe.ReplaceAllString(s, "")
	s = trailingParen.ReplaceAllString(s, "")
	s = trailingDots.ReplaceAllString(s, "")
	if len(s) > 20 {
		s = s[:20]
	}
	return strings.TrimSpace(s)
}

// inferVersionScheme, kısıtın hangi türde olduğunu söyler.
//
// Neden gerekli: "8684" bir yapı numarası, "1.6" anlamsal sürüm, "8/29/2019"
// tarih. Bunları birbiriyle KARŞILAŞTIRMAK anlamsız — yapı numaralı bir CVE'yi
// anlamsal sürümle kıyaslamak her müşteriyi tehdit gösterirdi.
func inferVersionScheme(e Extraction) string {
	v := e.LessThanOrEqual
	if v == "" {
		v = e.LessThan
	}
	if v == "" {
		v = e.AppVersion
	}
	if v == "" {
		v = e.GreaterEqual
	}
	v = leadingVRe.ReplaceAllString(strings.TrimSpace(v), "")
	if v == "" {
		return "unknown"
	}
	if looksLikeDate(v) {
		return "date"
	}
	if intOnlyRe.MatchString(v) {
		n, err := strconv.Atoi(v)
		if err != nil {
			return "unknown"
		}
		// 500 eşiği: "2" ya da "11" gibi küçük sayılar ana sürüm olabilir,
		// dört haneli sayılar pratikte yapı numarası.
		if n >= 500 {
			return "build"
		}
		return "semantic"
	}
	if strings.Contains(v, ".") {
		return "semantic"
	}
	return "unknown"
}

func looksLikeDate(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 30 {
		return false
	}
	for _, p := range datePatterns {
		if p.MatchString(s) {
			return true
		}
	}
	return year4Re.MatchString(s) && monthDayRe.MatchString(s)
}
