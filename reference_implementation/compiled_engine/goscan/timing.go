// Faz zamanlaması — "yavaş" demek yerine NEREDE yavaş olduğunu göstermek için.
//
// Bu projede ölçüm defalarca sezgiyi yanlışladı; darboğazı tahmin etmek yerine
// sayıyı üretmek kuralı burada da geçerli. Zamanlayıcılar atomik toplayıcı
// olduğu için paralel goroutine'lerden güvenle çağrılır ve kapalıyken maliyeti
// tek bir atomik toplamadır.
package main

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var timingOn = os.Getenv("GOSCAN_TIMING") != ""

type phaseStat struct {
	nanos atomic.Int64
	calls atomic.Int64
	items atomic.Int64 // faza giren birim (CVE, kalem) — varsa
}

var (
	phaseMu sync.Mutex
	phases  = map[string]*phaseStat{}
)

func phaseOf(name string) *phaseStat {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	s, ok := phases[name]
	if !ok {
		s = &phaseStat{}
		phases[name] = s
	}
	return s
}

// track, bir fazın süresini ölçer. `n` faza giren birim sayısıdır (yoksa 0).
//
// Kullanım: defer track("bounds", len(ids))()
func track(name string, n int) func() {
	if !timingOn {
		return func() {}
	}
	s := phaseOf(name)
	start := time.Now()
	return func() {
		s.nanos.Add(int64(time.Since(start)))
		s.calls.Add(1)
		s.items.Add(int64(n))
	}
}

// ResetTiming, ölçümler arasında sayaçları sıfırlar.
func ResetTiming() {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	phases = map[string]*phaseStat{}
}

// TimingReport, toplanan süreleri okunur biçimde döndürür.
//
// Süreler goroutine'ler boyunca TOPLANIR; paralel çalıştıkları için toplam
// duvar saatinden büyük olabilir. Amaç oran görmek: hangi faz işin kaçta
// kaçını yiyor.
func TimingReport() string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	if len(phases) == 0 {
		return ""
	}
	type row struct {
		name              string
		nanos, calls, itm int64
	}
	rows := []row{}
	var total int64
	for name, s := range phases {
		r := row{name, s.nanos.Load(), s.calls.Load(), s.items.Load()}
		rows = append(rows, r)
		total += r.nanos
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].nanos > rows[j].nanos })
	out := "\nfaz                 toplam sn     %   çağrı      birim   sn/1000 birim\n"
	for _, r := range rows {
		sec := float64(r.nanos) / 1e9
		per := 0.0
		if r.itm > 0 {
			per = sec * 1000 / float64(r.itm)
		}
		out += fmt.Sprintf("%-18s %10.2f %5.1f %7d %10d %14.3f\n",
			r.name, sec, 100*float64(r.nanos)/float64(total), r.calls, r.itm, per)
	}
	return out
}
