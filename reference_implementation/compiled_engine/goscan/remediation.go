// Düzeltme önerisi ve ürün destek durumu.
//
// Python karşılığı: üretimdeki düzeltme ve destek-durumu modülleri (bu pakette yok).
//
// "Açık var" cevabının devamı "ne yapmalıyım". Cevabın büyük kısmı elimizdeki
// veride duruyor: düzeltilmiş sürüm, kararı veren aralığın ÜST SINIRIdır.
package main

import (
	"context"
	"sort"
	"strings"
)

// Remediation, bir açık için "ne yapmalıyım" cevabı.
//
// `FixedVersion` ile `AfterVersion` bilerek AYRI: birincisi "bu sürüme çıkın"
// demektir, ikincisi yalnızca "bu sürüm hâlâ etkileniyor" bilgisidir. CVE
// `<= X` diyorsa düzeltmenin X+1 olduğunu VARSAYAMAYIZ — dal terk edilmiş
// olabilir — ve uydurulmuş bir hedef müşteriyi hâlâ açık bir sürüme yönlendirir.
type Remediation struct {
	Action       string            `json:"action"`
	SummaryTR    string            `json:"summary_tr"`
	FixedVersion string            `json:"fixed_version,omitempty"`
	AfterVersion string            `json:"after_version,omitempty"`
	FixSource    string            `json:"fix_source,omitempty"`
	Solution     string            `json:"solution,omitempty"`
	Links        []RemediationLink `json:"links,omitempty"`
}

type RemediationLink struct {
	URL  string `json:"url"`
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

// RecommendedUpgrade, açıkları kapatan hedef sürüm(ler).
//
// İki hedef ayrı verilir çünkü farklı büyüklükte kararlar: `TargetVersion`
// müşterinin bakım dalında kalır (düşük riskli yama), `LatestVersion` dal
// değiştirerek daha çoğunu kapatır. Tomcat gibi çok dallı üründe 9.0.90
// kullanana tek başına "11.0.14'e çıkın" demek yanlış yönlendirmedir.
type RecommendedUpgrade struct {
	TargetVersion string `json:"target_version"`
	Closes        int    `json:"closes"`
	Unresolved    int    `json:"unresolved"`
	SummaryTR     string `json:"summary_tr"`
	LatestVersion string `json:"latest_version,omitempty"`
	LatestCloses  int    `json:"latest_closes,omitempty"`
}

// SupportStatus, sürümün bulunduğu bakım dalı hâlâ destekleniyor mu?
//
// `Supported` ÜÇ değerlidir: `false` destek bitti, `true` sürüyor, `nil`
// satıcı bildirmemiş. Sonuncuyu `true` saymak biten desteği görünmez kılardı.
type SupportStatus struct {
	Cycle         string `json:"cycle"`
	Supported     *bool  `json:"supported"`
	EOLDate       string `json:"eol_date,omitempty"`
	LatestInCycle string `json:"latest_in_cycle,omitempty"`
	LTS           bool   `json:"lts"`
	SummaryTR     string `json:"summary_tr"`
}

// fixedVersionFromBounds, müşterinin sürümünü kapsayan aralığın üst sınırından
// düzeltmeyi çıkarır.
//
// Kaynaklar aynı CVE için ÇELİŞEBİLİR: NVD hem [7.0.0, 7.0.9) hem [7.0.0, 7.0.8)
// satırı taşıyabilir, CNA ise "7.0.8 dahil etkileniyor" diyebilir. En düşük
// adayı körlemesine seçmek kullanıcıyı HÂLÂ AÇIK olan 7.0.8'e yönlendirir. Bu yüzden "hâlâ etkileniyor" sınırları bir TAVAN oluşturur
// ve onu aşmayan adaylar elenir.
func fixedVersionFromBounds(version string, ranges []Bound) (fixed, after string) {
	pv := ParseVersion(version)
	if pv == nil {
		return "", ""
	}
	type cand struct {
		v   *Version
		raw string
	}
	candidates := []cand{}
	var ceiling *Version
	ceilingText := ""

	for _, b := range ranges {
		lower := CleanBound(b.GreaterEqual)
		if pl := ParseVersion(lower); pl != nil && pv.Less(pl) {
			continue // aralık müşteriyi kapsamıyor
		}
		if lt := CleanBound(b.LessThan); lt != "" {
			if plt := ParseVersion(lt); plt != nil && pv.Less(plt) {
				candidates = append(candidates, cand{plt, lt})
			}
			continue
		}
		if lte := CleanBound(b.LessThanOrEqual); lte != "" {
			if plte := ParseVersion(lte); plte != nil && pv.LessEq(plte) {
				if ceiling == nil || plte.Compare(ceiling) > 0 {
					ceiling, ceilingText = plte, lte
				}
			}
		}
	}

	var best *cand
	for i := range candidates {
		if ceiling != nil && candidates[i].v.Compare(ceiling) <= 0 {
			continue
		}
		if best == nil || candidates[i].v.Less(best.v) {
			best = &candidates[i]
		}
	}
	if best != nil {
		return best.raw, ""
	}
	if ceiling != nil {
		return "", ceilingText
	}
	return "", ""
}

// fixedVersionFromOSV, OSV'nin (dal_başlangıcı, düzeltilmiş_sürüm) çiftlerinden
// müşterinin dalını KAPSAYAN düzeltmeyi seçer: `introduced <= v < fixed`.
//
// Sınırlardan türetmeye göre üstünlüğü: düzeltilmiş sürüm doğrudan yazılı,
// tahmin yok.
func fixedVersionFromOSV(version string, fixes []Fix) string {
	pv := ParseVersion(version)
	if pv == nil {
		return ""
	}
	best := ""
	var bestV *Version
	for _, f := range fixes {
		pf := ParseVersion(f.Fixed)
		if pf == nil || pv.Compare(pf) >= 0 {
			continue
		}
		if f.Introduced != "" && f.Introduced != "0" {
			if pi := ParseVersion(f.Introduced); pi != nil && pv.Less(pi) {
				continue // dal müşteriden sonra açılmış
			}
		}
		if bestV == nil || pf.Less(bestV) {
			best, bestV = f.Fixed, pf
		}
	}
	return best
}

// buildRemediation, tek bir tehdit için düzeltme bloğu. Hiçbir şey bilinmiyorsa
// nil döner — boş bir blok yanıtta "düzeltme yok" gibi okunuyordu.
func buildRemediation(version string, ranges []Bound, fixes []Fix, extra *RemediationExtra) *Remediation {
	out := &Remediation{}

	// OSV önce: düzeltilmiş sürümü DOĞRUDAN yazıyor.
	if v := fixedVersionFromOSV(version, fixes); v != "" {
		out.FixedVersion, out.FixSource = v, "osv"
	}
	fixed, after := fixedVersionFromBounds(version, ranges)

	// OSV hedefi sınırlarla çelişebilir: sınırlar "X dahil hâlâ etkileniyor"
	// diyorsa X'e yükseltmek müşteriyi açık bırakır. Çelişkide sınırlar kazanır.
	if out.FixedVersion != "" && after != "" {
		pf, pc := ParseVersion(out.FixedVersion), ParseVersion(after)
		if pf != nil && pc != nil && pf.LessEq(pc) {
			out.FixedVersion, out.FixSource = "", ""
		}
	}
	if out.FixedVersion == "" {
		out.FixedVersion, out.AfterVersion = fixed, after
	}

	if extra != nil {
		out.Links = extra.Links
		out.Solution = extra.Solution
	}
	if out.FixedVersion == "" && out.AfterVersion == "" &&
		len(out.Links) == 0 && out.Solution == "" {
		return nil
	}

	switch {
	case out.FixedVersion != "":
		out.Action = "upgrade"
		out.SummaryTR = version + " → " + out.FixedVersion + " sürümüne yükseltin."
	case out.AfterVersion != "":
		out.Action = "upgrade_unknown_target"
		// Kesin hedef bilinmiyor; uydurmak yerine bilinen sınır söyleniyor.
		out.SummaryTR = out.AfterVersion + " sürümü hâlâ etkileniyor; satıcının " +
			out.AfterVersion + " sonrası sürümüne geçin."
	case out.Solution != "":
		out.Action = "apply_vendor_solution"
		out.SummaryTR = "Satıcının bildirdiği çözümü uygulayın."
	default:
		out.Action = "consult_advisory"
		out.SummaryTR = "Satıcı bültenine bakın; bu kayıtta düzeltilmiş sürüm belirtilmemiş."
	}
	return out
}

// buildRecommendedUpgrade, tüm açıkları kapatan hedef sürümü hesaplar.
//
// Kapatılamayanlar `Unresolved` ile AYRICA bildirilir — "şu sürüme çıkın" deyip
// geri kalanı sessizce yutmak, kapanmadığı hâlde kapandı sanılan açık üretir.
func buildRecommendedUpgrade(threats []Finding, version string) *RecommendedUpgrade {
	pv := ParseVersion(version)
	if pv == nil || len(threats) == 0 {
		return nil
	}
	type fx struct {
		v   *Version
		raw string
	}
	fixes := []fx{}
	unresolved := 0
	for _, t := range threats {
		if t.Remediation == nil || t.Remediation.FixedVersion == "" {
			unresolved++
			continue
		}
		if pf := ParseVersion(t.Remediation.FixedVersion); pf != nil {
			fixes = append(fixes, fx{pf, t.Remediation.FixedVersion})
		} else {
			unresolved++
		}
	}
	if len(fixes) == 0 {
		return nil
	}
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].v.Less(fixes[j].v) })
	latest := fixes[len(fixes)-1]

	var inBranch *fx
	for i := range fixes {
		if fixes[i].v.Major() == pv.Major() {
			inBranch = &fixes[i]
		}
	}

	out := &RecommendedUpgrade{Unresolved: unresolved}
	if inBranch != nil {
		closes := 0
		for _, f := range fixes {
			if f.v.LessEq(inBranch.v) {
				closes++
			}
		}
		out.TargetVersion, out.Closes = inBranch.raw, closes
		out.SummaryTR = version + " → " + inBranch.raw + " sürümü " +
			itoa(closes) + " açığı kapatıyor."
	} else {
		out.TargetVersion, out.Closes = latest.raw, len(fixes)
		out.SummaryTR = version + " → " + latest.raw + " sürümü " +
			itoa(len(fixes)) + " açığı kapatıyor (bu bir bakım dalı değişikliğidir)."
	}
	if latest.raw != out.TargetVersion && len(fixes) > out.Closes {
		out.LatestVersion, out.LatestCloses = latest.raw, len(fixes)
		out.SummaryTR += " " + latest.raw + " sürümüne geçilirse " +
			itoa(len(fixes)) + " açık kapanır, ama bu bir bakım dalı değişikliğidir."
	}
	if unresolved > 0 {
		out.SummaryTR += " Ayrıca " + itoa(unresolved) +
			" açık için düzeltilmiş sürüm bilinmiyor; satıcı bültenine bakılmalı."
	}
	return out
}

// buildSupportStatus, müşterinin sürümü hâlâ desteklenen bir dalda mı?
//
// Müşterinin dalı, sürümünün ön eki olan EN UZUN `cycle` ile bulunur: "9.0.90"
// hem "9" hem "9.0" ile başlıyor ve doğru olan spesifik olanıdır. Eşleşme nokta
// sınırında olmalı, yoksa "9.0" döngüsü "9.05.1" sürümüne de uyar.
func buildSupportStatus(cycles []LifecycleCycle, version string, today string) *SupportStatus {
	version = strings.TrimSpace(version)
	if version == "" || len(cycles) == 0 {
		return nil
	}
	var match *LifecycleCycle
	for i := range cycles {
		c := cycles[i].Cycle
		if c == "" {
			continue
		}
		if version == c || strings.HasPrefix(version, c+".") {
			if match == nil || len(c) > len(match.Cycle) {
				match = &cycles[i]
			}
		}
	}
	if match == nil {
		return nil
	}
	out := &SupportStatus{Cycle: match.Cycle, LatestInCycle: match.Latest,
		LTS: match.LTS, EOLDate: match.EOLDate}
	yes, no := true, false
	switch {
	case match.EOLDate != "" && match.EOLDate <= today:
		out.Supported = &no
		out.SummaryTR = match.Cycle + " bakım dalının desteği " + match.EOLDate +
			" tarihinde bitti; bu dala artık güvenlik yaması gelmiyor. Açıkların " +
			"kapanması için desteklenen bir dala geçilmesi gerekiyor."
	case match.EOLDate != "":
		out.Supported = &yes
		out.SummaryTR = match.Cycle + " dalı " + match.EOLDate + " tarihine kadar destekleniyor."
	case match.EOLKnown:
		out.Supported = &yes
		out.SummaryTR = match.Cycle + " dalı hâlâ destekleniyor."
	default:
		// Satıcı bildirmemiş; "destekleniyor" demek uydurma olur.
		out.SummaryTR = match.Cycle + " dalının destek durumu bildirilmemiş."
	}
	return out
}

// AttachRemediation, tehdit satırlarına düzeltme bloğunu ekler.
//
// Düzeltilmiş SÜRÜM her satıra eklenir (birkaç bayt). Bağlantılar ve çözüm
// metni yalnızca ilk `maxDetailed` satıra: yüksek CVE sayılı bir ürün binlerce
// tehdit döndürebilir ve satır başına 4 URL yanıtı megabaytlara taşır.
func (e *Engine) AttachRemediation(ctx context.Context, results []Result, maxDetailed int) error {
	ids := map[string]bool{}
	for i := range results {
		for _, t := range results[i].Threats {
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
	sort.Strings(list) // kesin sıralama

	extras, err := e.db.RemediationFor(ctx, list)
	if err != nil {
		return err
	}

	for i := range results {
		r := &results[i]
		fixes, err := e.db.FixesFor(ctx, cveIDsOf(r.Threats), r.productNorm)
		if err != nil {
			return err
		}
		for j := range r.Threats {
			t := &r.Threats[j]
			var extra *RemediationExtra
			if j < maxDetailed || maxDetailed <= 0 {
				extra = extras[t.CVEID]
			}
			t.Remediation = buildRemediation(r.Version, r.bounds[t.CVEID], fixes[t.CVEID], extra)
		}
		r.RecommendedUpgrade = buildRecommendedUpgrade(r.Threats, r.Version)
	}
	return nil
}

func cveIDsOf(threats []Finding) []string {
	out := make([]string, 0, len(threats))
	for _, t := range threats {
		out = append(out, t.CVEID)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
