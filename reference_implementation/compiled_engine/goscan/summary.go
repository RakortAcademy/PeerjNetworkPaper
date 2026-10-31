// Karar özeti — Python `refimpl/rationale.py::build_product_decision_summary` karşılığı.
//
// Panel bu alanın `summary_tr` anahtarını gösteriyor ve API sözleşmesinde
// `decision_summary` var; Go bunu üretmediği sürece istekleri Go'ya çevirmek
// panelde boş bir kutu bırakırdı.
//
// Metinler Python'daki ile aynı: tek dilli bir hat için İngilizce yazılmışlar ve
// `summary_tr` anahtarı geriye dönük uyumluluk için korunuyor.
package main

import (
	"fmt"
	"sort"
	"strings"
)

// DecisionSummary, ürün bazlı nihai karar özeti + referans CVE listesi.
type DecisionSummary struct {
	Status        string         `json:"status"`
	Summary       string         `json:"summary"`
	SummaryTR     string         `json:"summary_tr"`
	ReferenceCVEs []ReferenceCVE `json:"reference_cves"`
	HowToVerify   string         `json:"how_to_verify"`
}

// ReferenceCVE, özetin dayandığı CVE ve metninden bir kesit.
type ReferenceCVE struct {
	CVEID              string `json:"cve_id"`
	DescriptionExcerpt string `json:"description_excerpt"`
	Role               string `json:"role"`
}

const howToVerify = "To verify the decision, compare the CVE ID in decision_explanation and the " +
	"reference_cve_description text against the official NVD/CVE record."

// plainSummary, referanssız kısa özet (erken çıkışlar için).
func plainSummary(status, text string) *DecisionSummary {
	return &DecisionSummary{Status: status, Summary: text, SummaryTR: text,
		ReferenceCVEs: []ReferenceCVE{}, HowToVerify: howToVerify}
}

// truncateDescription, metni sınıra kısaltır. Sınır RUNE cinsindendir: byte
// saymak Türkçe/UTF-8 metinleri karakter ortasından kesip bozuk çıktı verir.
func truncateDescription(text string, limit int) string {
	t := strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	r := []rune(t)
	if len(r) <= limit {
		return t
	}
	return strings.TrimSpace(string(r[:limit])) + "…"
}

// Açıklama metninden kaba şiddet sırası. CVE satırlarında CVSS alanı her zaman
// yok; bu liste Python `_SEVERITY_KEYWORDS` ile BİREBİR aynı olmalı, yoksa iki
// motor aynı taramada farklı CVE'yi "baş referans" gösterir.
var severityKeywords = []struct {
	score int
	words []string
}{
	{100, []string{"remote code execution", "arbitrary code", "execute code", "code execution", "rce"}},
	{80, []string{"deserialization", "sql injection", "command injection", "authentication bypass",
		"privilege escalation", "use after free", "buffer overflow"}},
	{60, []string{"cross-site scripting", "xss", "server-side request forgery", "ssrf",
		"path traversal", "directory traversal", "xml external entity", "xxe",
		"information disclosure", "sensitive information"}},
	{40, []string{"denial of service", "uncontrolled recursion", "infinite loop", "resource exhaustion"}},
	{30, []string{"man-in-the-middle", "man in the middle", "interception", "hostname verification",
		"improper certificate"}},
}

func severityRank(text string) int {
	t := strings.ToLower(text)
	for _, g := range severityKeywords {
		for _, w := range g.words {
			if strings.Contains(t, w) {
				return g.score
			}
		}
	}
	return 10
}

// leadSortKey: önce en yüksek şiddet, eşitlikte CVE kimliği artan (eski/dönüm
// noktası CVE'ler öne gelir). Python `_lead_sort_key` ile aynı.
func leadSortKey(f Finding) (int, string) {
	return -severityRank(f.Description), f.CVEID
}

// BuildDecisionSummary, sonucun karar özetini üretir.
func BuildDecisionSummary(r *Result) *DecisionSummary {
	refs := []ReferenceCVE{}
	product, version := r.Product, r.Version
	var summary string

	switch {
	case r.Status == "THREAT" && len(r.Threats) > 0:
		// Baş referans ilk taranan değil EN KRİTİK CVE olmalı; müşteri özeti
		// okuyup hangi açığın acil olduğunu anlıyor.
		ordered := make([]Finding, len(r.Threats))
		copy(ordered, r.Threats)
		sort.SliceStable(ordered, func(i, j int) bool {
			as, aid := leadSortKey(ordered[i])
			bs, bid := leadSortKey(ordered[j])
			if as != bs {
				return as < bs
			}
			return aid < bid
		})
		lead := ordered[0]
		refs = append(refs, ReferenceCVE{lead.CVEID,
			truncateDescription(lead.Description, 800), "primary_threat"})
		summary = fmt.Sprintf(
			"Result THREAT: %d CVE match(es) found for %s v%s. "+
				"Primary reference: %s — based on the version constraint in this CVE, "+
				"your version is affected (%s). CVE summary: «%s»",
			len(r.Threats), product, version, lead.CVEID, lead.Reason,
			truncateDescription(lead.Description, 400))
		for i := 1; i < len(ordered) && i < 5; i++ {
			refs = append(refs, ReferenceCVE{ordered[i].CVEID,
				truncateDescription(ordered[i].Description, 400), "additional_threat"})
		}

	case r.Status == "SAFE" && len(r.SafeReasons) > 0:
		// Gerçekten uygulanabilir bir SAFE kaydı örnek gösterilir; "farklı ürün"
		// kaydına ancak başka seçenek yoksa düşülür — alakasız bir CVE'yi
		// referans diye sergilemek güveni aşındırıyor.
		lead := r.SafeReasons[0]
		for _, s := range r.SafeReasons {
			if !s.NotApplicable {
				lead = s
				break
			}
		}
		refs = append(refs, ReferenceCVE{lead.CVEID,
			truncateDescription(lead.Description, 800), "primary_safe"})
		summary = fmt.Sprintf(
			"Result SAFE: for %s v%s, your version does not fall within the threat "+
				"range among the scanned CVEs. Example reference: %s — per the CVE "+
				"description: %s. CVE summary: «%s»",
			product, version, lead.CVEID, lead.Reason,
			truncateDescription(lead.Description, 400))
		if len(r.SafeReasons) > 1 {
			n := 3
			if len(r.SafeReasons) < n {
				n = len(r.SafeReasons)
			}
			summary += fmt.Sprintf(
				" (%d CVEs deemed safe; %d sample(s) shown in the report.)",
				len(r.SafeReasons), n)
		}

	case r.Status == "UNCERTAIN":
		if len(r.UncertainRow) > 0 {
			lead := r.UncertainRow[0]
			refs = append(refs, ReferenceCVE{lead.CVEID,
				truncateDescription(lead.Description, 800), "uncertain_sample"})
			summary = fmt.Sprintf(
				"Result UNCERTAIN: %s v%s — for %d CVE(s) the product matched but the "+
					"version constraint could not be clearly derived from the CVE "+
					"description, or the comparison could not be made. Example: %s: %s. "+
					"CVE text: «%s»",
				product, version, r.Uncertain, lead.CVEID, lead.UncertainReason,
				truncateDescription(lead.Description, 400))
		} else {
			summary = fmt.Sprintf(
				"Result UNCERTAIN: %s v%s — a reliable version constraint could not be derived.",
				product, version)
		}

	case r.Status == "NOT_FOUND":
		na := 0
		for _, s := range r.SafeReasons {
			if s.NotApplicable {
				na++
			}
		}
		if na > 0 {
			summary = fmt.Sprintf(
				"Result NOT_FOUND: no CVE in the reference database applies to %s v%s. "+
					"%d nearby CVE(s) matched only by keyword and reference different "+
					"products/vendors, so they were excluded.", product, version, na)
		} else {
			summary = fmt.Sprintf(
				"Result NOT_FOUND: no product match for %s v%s in the reference CVE database.",
				product, version)
		}

	default:
		summary = fmt.Sprintf("Result %s: %s v%s.", r.Status, product, version)
	}

	return &DecisionSummary{Status: r.Status, Summary: summary, SummaryTR: summary,
		ReferenceCVEs: refs, HowToVerify: howToVerify}
}
