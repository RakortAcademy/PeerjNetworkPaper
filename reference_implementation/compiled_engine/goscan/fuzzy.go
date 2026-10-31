// Bulanık ad eşleme — Python `refimpl/fuzzy/matcher.py` karşılığı.
//
// Neden gerekli: CVE kataloğundaki ürün adı envanterdekiyle aynı yazılmıyor.
// Quill++ CVE'leri katalogda `quill-plus-plus` adıyla duruyor; envanterde
// `Quill++`. Katalog eşleşmesi başarısız olunca MODELİN metinden çıkardığı
// ada düşülür — model orada "Quill++" yazıyor ve eşleşme oradan geliyor.
//
// Bu yol olmadan böyle bir ürünün tehditlerinin çoğu kaçar.
// Ürün kimliği kararlarının %3,8'i bu yoldan geliyor.
package main

import (
	"regexp"
	"strings"
)

const fuzzyThreshold = 0.8

var (
	segmentSplitRe  = regexp.MustCompile(`(?i),|\s+and\s+`)
	genericMatchTokens = set("runtime", "application", "software", "program", "app",
		"based", "chromium")
)

// FuzzyResult, eşleşme kararı ve puanı.
type FuzzyResult struct {
	Matched bool
	Score   float64
	Method  string
}

// FuzzyMatch, iki ürün adının aynı ürünü gösterip göstermediğine karar verir.
//
// Yöntemler sırayla denenir; ilk eşleşen kazanır. Sıra ucuzdan pahalıya:
// tam eşitlik → token örtüşmesi → alt dize → uzunluk kapısı → difflib →
// Levenshtein.
func FuzzyMatch(cveProduct, inventoryProduct string) FuzzyResult {
	cve := NormalizeProductName(cveProduct)
	inv := NormalizeProductName(inventoryProduct)
	if cve == "" || inv == "" {
		return FuzzyResult{false, 0, "null"}
	}
	if cve == inv {
		return FuzzyResult{true, 1.0, "exact"}
	}

	// Token örtüşmesi (Jaccard) — "chromium based" gibi ek kelimelere dayanıklı.
	cveTok := tokenSet(cve)
	invTok := tokenSet(inv)
	tokenScore := 0.0
	if len(cveTok) > 0 && len(invTok) > 0 {
		inter := 0
		for t := range cveTok {
			if invTok[t] {
				inter++
			}
		}
		union := len(cveTok) + len(invTok) - inter
		if union > 0 {
			tokenScore = float64(inter) / float64(union)
		}
		if inter >= 2 && tokenScore >= fuzzyThreshold*0.75 {
			return FuzzyResult{true, tokenScore, "token_overlap"}
		}
	}

	if strings.Contains(inv, cve) || strings.Contains(cve, inv) {
		short, long := len(cve), len(inv)
		if short > long {
			short, long = long, short
		}
		score := float64(short) / float64(long)
		if score >= fuzzyThreshold {
			return FuzzyResult{true, score, "substring"}
		}
	}

	// Uzunluk kapısı — pahalı iki yöntemden ÖNCE.
	// Her iki ölçüt de uzunluk farkıyla sınırlıdır:
	//   levenshtein: 1 - dist/max ≤ 1 - |la-lb|/max
	//   difflib    : 2M/(la+lb) ≤ 2·min/(la+lb)
	// İkisi de eşiğin altındaysa hesaplamaya gerek yok.
	la, lb := len(cve), len(inv)
	maxLen := la
	minLen := lb
	if lb > la {
		maxLen, minLen = lb, la
	}
	levCeiling := 1 - float64(maxLen-minLen)/float64(maxLen)
	seqCeiling := 2 * float64(minLen) / float64(la+lb)
	if levCeiling < fuzzyThreshold && seqCeiling < fuzzyThreshold {
		best := tokenScore
		if seqCeiling > best {
			best = seqCeiling
		}
		return FuzzyResult{false, best, "length_gate"}
	}

	seq := seqRatio(cve, inv)
	if seq >= fuzzyThreshold {
		return FuzzyResult{true, seq, "sequence_matcher"}
	}
	lev := 0.0
	if levCeiling >= fuzzyThreshold {
		lev = 1 - float64(levenshtein(cve, inv))/float64(maxLen)
		if lev >= fuzzyThreshold {
			return FuzzyResult{true, lev, "levenshtein"}
		}
	}
	best := tokenScore
	for _, v := range []float64{seq, lev} {
		if v > best {
			best = v
		}
	}
	return FuzzyResult{false, best, "none"}
}

func tokenSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.Fields(s) {
		if !genericMatchTokens[t] {
			out[t] = true
		}
	}
	return out
}

// seqRatio, difflib.SequenceMatcher.ratio() karşılığı: 2*M/T, M = eşleşen
// karakter sayısı (en uzun ortak alt dizilerin toplamı).
func seqRatio(a, b string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	m := matchingBlocks(a, b)
	return 2 * float64(m) / float64(len(a)+len(b))
}

// matchingBlocks, difflib'in özyinelemeli "en uzun ortak blok" sayımı.
func matchingBlocks(a, b string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	bi, bj, size := longestMatch(a, b)
	if size == 0 {
		return 0
	}
	return size + matchingBlocks(a[:bi], b[:bj]) +
		matchingBlocks(a[bi+size:], b[bj+size:])
}

func longestMatch(a, b string) (int, int, int) {
	bestI, bestJ, bestSize := 0, 0, 0
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				cur[j] = prev[j-1] + 1
				if cur[j] > bestSize {
					bestSize = cur[j]
					bestI, bestJ = i-cur[j], j-cur[j]
				}
			} else {
				cur[j] = 0
			}
		}
		prev, cur = cur, prev
		for k := range cur {
			cur[k] = 0
		}
	}
	return bestI, bestJ, bestSize
}

func levenshtein(a, b string) int {
	if len(a) < len(b) {
		a, b = b, a
	}
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	cur := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}

// MatchExtractedName, MODELİN metinden çıkardığı ada karşı eşleme yapar.
//
// `app_name` çok ürünlü olabiliyor ("A, B and C"); her parça ayrı denenir ve
// en iyi puan alınır. Katalog eşleşmesi başarısız olduğunda son şans budur —
// Quill++ örneğinde katalogda `quill-plus-plus` yazarken model metinden
// "Quill++" çıkarıyor ve eşleşme oradan geliyor.
func MatchExtractedName(appName, target string) (bool, float64) {
	raw := strings.TrimSpace(appName)
	if raw == "" {
		return false, 0
	}
	segments := segmentSplitRe.Split(raw, -1)
	if len(segments) == 0 {
		segments = []string{raw}
	}
	best := 0.0
	found := false
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		low := strings.ToLower(seg)
		if seg == "" || low == "n/a" {
			continue
		}
		if norm := NormalizeProductName(seg); len(norm) < 3 {
			continue
		}
		if r := FuzzyMatch(seg, target); r.Matched && r.Score > best {
			best, found = r.Score, true
		}
	}
	return found, best
}
