// Önceliklendirme — Python tarafındaki `refimpl/prioritization.py` karşılığı.
//
// Üç sinyal birbirinin yerine geçmez ve tek sayıya indirgenmez: KEV bir GÖZLEM
// ("sömürülüyor"), EPSS bir TAHMİN ("sömürülebilir"), CVSS ise ŞİDDET
// ("sömürülürse ne olur"). CVSS 9.8 olup hiç sömürülmeyen açıklar da var,
// CVSS 4.3 olup EPSS'i %84 olanlar da.
package main

// %10 EPSS eşiğinin amacı yüzlerce tehditlik bir listeyi bir günde
// bitirilebilecek boyuta indirmektir.
const (
	epssHigh   = 0.10
	epssMedium = 0.01
	cvssHigh   = 9.0
	cvssMedium = 7.0
)

var priorityOrder = map[string]int{"acil": 0, "yüksek": 1, "orta": 2, "düşük": 3}

// PriorityFor, tek bir tehdidin öncelik sınıfı.
//
// KEV her şeyin önünde: tahmin değil gözlem. Veri YOKLUĞU yüksek risk demek
// değildir — abartmak listeyi yine okunamaz hâle getirir.
func PriorityFor(r *Risk) string {
	if r == nil {
		return "düşük"
	}
	if r.KEV {
		return "acil"
	}
	epss, cvss := 0.0, 0.0
	if r.EPSS != nil {
		epss = *r.EPSS
	}
	if r.CVSS != nil {
		cvss = *r.CVSS
	}
	switch {
	case epss >= epssHigh || cvss >= cvssHigh:
		return "yüksek"
	case epss >= epssMedium || cvss >= cvssMedium:
		return "orta"
	default:
		return "düşük"
	}
}

func priorityRank(r *Risk) int {
	if r == nil {
		return 99
	}
	if v, ok := priorityOrder[r.Priority]; ok {
		return v
	}
	return 99
}

func epssOf(r *Risk) float64 {
	if r == nil || r.EPSS == nil {
		return 0
	}
	return *r.EPSS
}

// RiskSummary, ürün düzeyinde tek bakışta özet.
type RiskSummary struct {
	Total      int            `json:"total"`
	Counts     map[string]int `json:"counts"`
	KEV        int            `json:"kev"`
	Ransomware int            `json:"ransomware"`
	TopCVEs    []string       `json:"top_cves,omitempty"`
}

func Summarize(threats []Finding) *RiskSummary {
	if len(threats) == 0 {
		return nil
	}
	s := &RiskSummary{Total: len(threats), Counts: map[string]int{}}
	for _, t := range threats {
		p := "düşük"
		if t.Risk != nil && t.Risk.Priority != "" {
			p = t.Risk.Priority
		}
		s.Counts[p]++
		if t.Risk != nil && t.Risk.KEV {
			s.KEV++
			if t.Risk.Ransomware {
				s.Ransomware++
			}
		}
	}
	for i, t := range threats {
		if i >= 5 {
			break
		}
		s.TopCVEs = append(s.TopCVEs, t.CVEID)
	}
	return s
}
