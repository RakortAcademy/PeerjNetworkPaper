// CVE açıklamasından sürüm kısıtı çıkarımı — regex katmanı.
//
// Python karşılığı: `refimpl/extraction/constraints.py`. Bu katman modelin
// YEDEĞİ değil, TAMAMLAYICISIdır: model metindeki sürüm ifadesini bir varlık
// olarak etiketliyor, buradaki kalıplar o ifadenin ANLAMINI veriyor ("before X"
// üst sınır, "X and later" alt sınır). Model sürüm bulamadığında da devreye
// giriyor.
//
// Ölçüm: 600 CVE metninde model %70,2'sinde sürüm kısıtı verdi, bu katman
// %2,0'sini daha ekledi, %27,8'inde ikisi de veremedi.
//
// Bu dosya goscan'ın Python'la eşdeğerliği için ŞART: bu katman olmadan
// Bu katman olmadan böyle bir ürünün tehditlerinin çoğu kaçar.
//
// SIRA ANLAMLIDIR. Kesin ifadeler ("before", "prior to", aralık) düzeltme
// dilinden ("fixed in", "upgrade to") ÖNCE gelir ve İLK eşleşen kazanır:
// kesin bilgi tavsiyeden önceliklidir.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Constraints, bir CVE metninden çıkarılan sürüm kısıtları.
type Constraints struct {
	LessThan        string
	LessThanOrEqual string
	GreaterEqual    string
	AppVersion      string
	Source          string
}

func (c Constraints) HasBounds() bool {
	return c.LessThan != "" || c.LessThanOrEqual != "" ||
		c.GreaterEqual != "" || c.AppVersion != ""
}

// ToBound, kısıtları sürüm çözücüsünün anladığı yapıya çevirir.
func (c Constraints) ToBound() Bound {
	return Bound{
		LessThan: c.LessThan, LessThanOrEqual: c.LessThanOrEqual,
		GreaterEqual: c.GreaterEqual, ExactVersion: c.AppVersion,
	}
}

var normVerPrefixRe = regexp.MustCompile(`^[vV]`)
var normVerSuffixRe = regexp.MustCompile(`\.+$`)

// normVer, yakalanan sürüm dizgesini sadeleştirir ("V4.1.4." → "4.1.4").
func normVer(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ""
	}
	s = normVerPrefixRe.ReplaceAllString(s, "")
	s = normVerSuffixRe.ReplaceAllString(s, "")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// Sıralı kalıp listesi — İLK eşleşen kazanır.
type descPattern struct {
	re  *regexp.Regexp
	key string
}

var (
	// Aralık: "9.0.0.M1 to 9.0.0.M9"
	rangeToRe = regexp.MustCompile(`(?i)([\d][\w.]*)\s+to\s+([\d][\w.]*)`)
	// OpenSSL biçimi: "(Affected 1.1.1-1.1.1k)". Ölçümde kısıt çıkarılamayan
	// açıklamaların %20'si bu kalıptaydı.
	affectedDashRe = regexp.MustCompile(`(?i)affected\s+v?([\d][\w.]*?)\s*[-–]\s*v?([\d][\w.]*)`)
	// "Fixed in OpenSSL 1.1.1l" — düzeltme cümlesinde ürün adı araya giriyor;
	// sürümü doğrudan izleyen kalıplar bunu yakalayamıyordu (%26).
	fixedInProductRe = regexp.MustCompile(
		`(?i)fixed\s+in\s+[A-Za-z][\w.\-]*(?:\s+[A-Za-z][\w.\-]*){0,3}?\s+v?([\d]+\.[\d][\w.]*)`)
	affectsEarlierRe = regexp.MustCompile(`(?i)affects\s+[^.]{0,80}?\s+([\d][\w.]*)\s+and\s+earlier`)
	plainEarlierRe   = regexp.MustCompile(`(?i)([\d]+\.[\d]+(?:\.[\d]+)*)\s+and\s+earlier`)

	descPatterns = []descPattern{
		{regexp.MustCompile(`(?i)versions?\s+prior\s+to\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)versions?\s+before\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)prior\s+to\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)before\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)up\s+to\s+([\d][\w.]*)`), "le"},
		{regexp.MustCompile(`(?i)through\s+([\d][\w.]*)`), "le"},
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+and\s+earlier`), "le"},
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+and\s+prior`), "le"},
		{regexp.MustCompile(`(?i)<=\s*([\d][\w.]*)`), "le"},
		{regexp.MustCompile(`(?i)<\s*([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)>=\s*([\d][\w.]*)`), "ge"},
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+and\s+later`), "ge"},

		// Düzeltme dili: "fixed in 4.2.1" — düzeltmenin GELDİĞİ sürüm, öncesi
		// etkilenir. Kesin ifadelerden SONRA gelir.
		{regexp.MustCompile(`(?i)(?:has\s+been\s+)?fixed\s+in\s+(?:version\s+)?([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)(?:is\s+)?patched\s+in\s+(?:version\s+)?([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)(?:is\s+)?(?:resolved|addressed|corrected)\s+in\s+(?:version\s+)?([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)(?:upgrade|update|upgrading|updating)\s+to\s+(?:version\s+)?([\d][\w.]*)`), "lt"},

		// Eşdeğer üst sınır ifadeleri
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+or\s+earlier`), "le"},
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+or\s+(?:below|older|lower)`), "le"},
		{regexp.MustCompile(`(?i)earlier\s+than\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)older\s+than\s+([\d][\w.]*)`), "lt"},
		{regexp.MustCompile(`(?i)([\d][\w.]*)\s+or\s+(?:above|newer|higher|later)`), "ge"},
	}
)

// ParseDescriptionConstraints, açıklamadan lt/le/ge çıkarır.
//
// `customerMajor` verilirse önce müşterinin bakım dalına ait ifade aranır:
// "9.x before 9.0.0.M12" gibi çok dallı cümlelerde yanlış dalın sınırını almak
// yanlış karar üretir.
func ParseDescriptionConstraints(description string, customerMajor int) Constraints {
	if strings.TrimSpace(description) == "" {
		return Constraints{}
	}
	text := strings.ReplaceAll(description, "\n", " ")

	if customerMajor > 0 {
		for _, pat := range []string{
			fmt.Sprintf(`(?i)\b%d\.x\s+before\s+([\d][\w.]*)`, customerMajor),
			fmt.Sprintf(`(?i)\b%d(?:\.\d+)?\s+before\s+([\d][\w.]*)`, customerMajor),
		} {
			if m := regexp.MustCompile(pat).FindStringSubmatch(text); m != nil {
				return Constraints{LessThan: normVer(m[1]), Source: "description_regex"}
			}
		}
	}

	if m := rangeToRe.FindStringSubmatch(text); m != nil {
		return Constraints{GreaterEqual: normVer(m[1]), LessThanOrEqual: normVer(m[2]),
			Source: "description_regex"}
	}
	if m := affectedDashRe.FindStringSubmatch(text); m != nil {
		return Constraints{GreaterEqual: normVer(m[1]), LessThanOrEqual: normVer(m[2]),
			Source: "description_regex"}
	}
	if m := fixedInProductRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThan: normVer(m[1]), Source: "description_regex"}
	}

	for _, p := range descPatterns {
		if m := p.re.FindStringSubmatch(text); m != nil {
			c := Constraints{Source: "description_regex"}
			switch p.key {
			case "lt":
				c.LessThan = normVer(m[1])
			case "le":
				c.LessThanOrEqual = normVer(m[1])
			case "ge":
				c.GreaterEqual = normVer(m[1])
			}
			return c
		}
	}

	if m := affectsEarlierRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1]), Source: "description_regex"}
	}
	if m := plainEarlierRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1]), Source: "description_regex"}
	}
	return Constraints{}
}

var (
	jsonlEarlierRe = regexp.MustCompile(`(?i)([\d][\w.]*)\s+and\s+earlier`)
	jsonlBeforeRe  = regexp.MustCompile(`(?i)before\s+([\d][\w.]*)`)
	jsonlThroughRe = regexp.MustCompile(`(?i)through\s+([\d][\w.]*)`)
	jsonlPlainRe   = regexp.MustCompile(`^[\d][\w.]*$`)
	hintWordsRe    = regexp.MustCompile(`(?i)earlier|prior|before|through`)
)

// ParseVersionHint, `cve_affected.version` alanındaki serbest metni okur.
// İkinci dönen değer "yalnızca düz bir sürüm" ipucudur; tek başına sınır
// sayılmaz, yalnızca açıklamada üst sınır dili varsa kullanılır.
func ParseVersionHint(raw string) (Constraints, string) {
	text := strings.TrimSpace(raw)
	low := strings.ToLower(text)
	if text == "" || low == "n/a" || low == "unknown" {
		return Constraints{}, ""
	}
	if parts := ParseVersionField(text); len(parts) == 1 {
		p := parts[0]
		if p.HasBounds() {
			p.Source = "jsonl_field"
			return p, ""
		}
	}
	if m := jsonlEarlierRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1]), Source: "jsonl_field"}, ""
	}
	if m := jsonlBeforeRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThan: normVer(m[1]), Source: "jsonl_field"}, ""
	}
	if m := jsonlThroughRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1]), Source: "jsonl_field"}, ""
	}
	if jsonlPlainRe.MatchString(text) {
		return Constraints{}, normVer(text)
	}
	return Constraints{}, ""
}

// ParseVersionField, `version` metnini SIFIR YA DA DAHA ÇOK kısıta çevirir.
// Bir CNA aynı alanda birden çok bakım dalı sayabiliyor.
func ParseVersionField(raw string) []Constraints {
	text := strings.TrimSpace(raw)
	low := strings.ToLower(text)
	if text == "" || low == "n/a" || low == "unknown" || low == "unspecified" ||
		text == "*" || text == "-" {
		return nil
	}
	// Operatörlü ifade TEK bir kısıttır: ">= 0.2.0, < 0.39.0" virgülden
	// bölünürse "< 0.39.0" tek başına 0.1.0'ı da etkilenmiş gösterirdi.
	if whole := parseOperatorExpression(text); whole.HasBounds() {
		return []Constraints{whole}
	}
	out := []Constraints{}
	for _, seg := range regexp.MustCompile(`\s*[,;]\s*`).Split(text, -1) {
		if c := parseVersionSegment(seg); c.HasBounds() {
			out = append(out, c)
		}
		if len(out) >= 48 {
			break
		}
	}
	return out
}

var (
	operatorRe = regexp.MustCompile(`(>=|<=|>|<|=)\s*[vV]?([\d][\w.\-]*)`)
	leadingConjRe = regexp.MustCompile(`(?i)^(and|or)\s+`)
	// Sürüm tokenı sözcük sınırıyla başlamalı, yoksa "S7x and prior" içindeki
	// "7x" sürüm sanılır.
	andBelowRe = regexp.MustCompile(`(?i)\b([\d][\w.\-]*)\s+(?:and|or)\s+(?:below|earlier|prior|lower|older)`)
	priorToRe  = regexp.MustCompile(`(?i)(?:prior\s+to|before)\s+[vV]?([\d][\w.\-]*)`)
	upToRe     = regexp.MustCompile(`(?i)(?:up\s+to\s+and\s+including|up\s+to|through)\s+[vV]?([\d][\w.\-]*)`)
	// En az bir nokta şart — "12" gibi tek sayılar bakım DALI olabilir.
	exactRe = regexp.MustCompile(`^(?:[A-Za-z][\w./\-]*\s+)*[vV]?(\d+(?:\.\d+)+[\w.\-]*)$`)
)

func parseOperatorExpression(raw string) Constraints {
	c := Constraints{}
	for _, m := range operatorRe.FindAllStringSubmatch(raw, -1) {
		v := normVer(m[2])
		if v == "" {
			continue
		}
		switch m[1] {
		case "<":
			if c.LessThan == "" {
				c.LessThan = v
			}
		case "<=":
			if c.LessThanOrEqual == "" {
				c.LessThanOrEqual = v
			}
		case ">=":
			if c.GreaterEqual == "" {
				c.GreaterEqual = v
			}
			// ">" için alan yok: alt sınır olarak saklamak müşteriyi aralığın
			// içinde göstermek olurdu (yanlış tehdit).
		}
	}
	return c
}

func parseVersionSegment(segment string) Constraints {
	text := leadingConjRe.ReplaceAllString(strings.TrimSpace(segment), "")
	if text == "" || len(text) > 120 {
		return Constraints{}
	}
	if c := parseOperatorExpression(text); c.HasBounds() {
		return c
	}
	if m := andBelowRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1])}
	}
	if m := priorToRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThan: normVer(m[1])}
	}
	if m := upToRe.FindStringSubmatch(text); m != nil {
		return Constraints{LessThanOrEqual: normVer(m[1])}
	}
	if m := exactRe.FindStringSubmatch(text); m != nil {
		return Constraints{AppVersion: normVer(m[1])}
	}
	return Constraints{}
}

// MergeConstraints, öncelik sırasıyla kısıtları tamamlar:
// MEVCUT (model çıktısı) > açıklama regex'i > version alanı ipucu.
//
// Sıra önemli: model bir sınır verdiyse ona dokunulmaz. Regex katmanı yalnızca
// BOŞLUĞU doldurur; ikisini karıştırmak modelin doğru bulduğu sınırı
// zayıf bir metin eşleşmesiyle ezerdi.
func MergeConstraints(base Constraints, description, versionHint string, customerMajor int) Constraints {
	out := base
	if !out.HasBounds() {
		if fromDesc := ParseDescriptionConstraints(description, customerMajor); fromDesc.HasBounds() {
			out = fillFrom(out, fromDesc)
			out.Source = fromDesc.Source
		}
	}
	if !out.HasBounds() {
		fromHint, plain := ParseVersionHint(versionHint)
		if fromHint.HasBounds() {
			out = fillFrom(out, fromHint)
			out.Source = fromHint.Source
		} else if plain != "" && hintWordsRe.MatchString(description) {
			// Tek sürüm ipucu: yalnızca açıklamada üst sınır dili varsa
			// üst sınır olarak kabul edilir (muhafazakâr).
			out.LessThanOrEqual = plain
			out.Source = "jsonl_hint"
		}
	}
	return out
}

func fillFrom(dst, src Constraints) Constraints {
	if dst.LessThan == "" {
		dst.LessThan = src.LessThan
	}
	if dst.LessThanOrEqual == "" {
		dst.LessThanOrEqual = src.LessThanOrEqual
	}
	if dst.GreaterEqual == "" {
		dst.GreaterEqual = src.GreaterEqual
	}
	if dst.AppVersion == "" {
		dst.AppVersion = src.AppVersion
	}
	return dst
}
