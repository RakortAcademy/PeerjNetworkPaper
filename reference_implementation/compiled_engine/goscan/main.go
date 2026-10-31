// goscan — CVE tarama motorunun paralel çalışan hızlı yolu.
//
// Neden ayrı bir servis: tarama sırasında çekirdeklerin çoğu boş kalıyordu.
// Darboğaz donanım değil Python'ın GIL'iydi — iş parçacığı eklemek
// hızlandırmıyordu, süreç eklemek hızlandırıyordu.
// Go'da aynı iş tek süreçte gerçek paralellikte koşuyor.
//
// Model çıkarımı ONNX üzerinden burada çalışır (bkz. model.go) ve PyTorch ile
// token token aynı sonucu veriyor. Çıkarım CVE metnine bağlı, sürüme değil;
// `cve_extractions` tablosunda saklanıyor, yalnızca eksikler hesaplanıyor.
// Model verilmezse tarama düşmez, eksikler `needs_model` ile bildirilir.
//
// Kullanım:
//
//	goscan -serve -addr 127.0.0.1:8390   HTTP servisi
//	goscan -bench -n 30              yerel ölçüm
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
)

// Bağlantı ve çözüm metni taşıyacak satır sayısı. Yüksek CVE sayılı bir ürün
// binlerce tehdit döndürebilir; satır başına 4 URL yanıtı megabaytlara taşır.
const maxDetailRows = 300

type scanRequest struct {
	Items   []Item `json:"items"`
	Workers int    `json:"workers,omitempty"`
}

type scanResponse struct {
	Results   []Result `json:"results"`
	ElapsedMS int64    `json:"elapsed_ms"`
	Workers   int      `json:"workers"`
}

func main() {
	var (
		serve   = flag.Bool("serve", false, "HTTP servisi olarak çalış")
		addr    = flag.String("addr", "127.0.0.1:8390", "dinlenecek adres")
		bench   = flag.Bool("bench", false, "yerel ölçüm çalıştır")
		benchN  = flag.Int("n", 30, "ölçümde kaç ürün")
		workers = flag.Int("workers", runtime.NumCPU(), "paralel goroutine")
		model   = flag.String("model-version", os.Getenv("MODEL_VERSION"),
			"çıkarım önbelleğinin model damgası")
		maxConn  = flag.Int("max-conn", 0, "PostgreSQL havuzu (0 = workers+4)")
		modelDir = flag.String("model-dir", os.Getenv("GOSCAN_MODEL_DIR"),
			"ONNX dışa aktarım dizini (boşsa çıkarım kapalı)")
		extract = flag.String("extract", "", "eşitlik sınaması: JSON metin listesi dosyası")
	)
	flag.Parse()

	if *maxConn == 0 {
		// Havuz goroutine sayısından büyük olmalı; yoksa paralellik bağlantı
		// beklemesine dönüşür ve kazanç yok olur.
		*maxConn = *workers + 4
	}

	// Eşitlik sınaması veritabanı istemez; modeli yükleyip çıkıp gider.
	if *extract != "" {
		runExtract(*modelDir, *extract)
		return
	}

	ctx := context.Background()
	db, err := OpenDB(ctx, int32(*maxConn))
	if err != nil {
		log.Fatalf("veritabanına bağlanılamadı: %v", err)
	}
	defer db.Close()

	if *model == "" {
		log.Fatal("model damgası gerekli: -model-version ya da MODEL_VERSION")
	}
	engine := NewEngine(db, *model)
	ex, err := NewExtractor(*modelDir)
	if err != nil {
		log.Fatalf("model yüklenemedi: %v", err)
	}
	if ex != nil {
		defer ex.Close()
		engine = engine.WithExtractor(ex)
		log.Printf("model çıkarımı AÇIK: %s", *modelDir)
	} else {
		log.Print("model çıkarımı kapalı — eksik çıkarımlar needs_model ile bildirilecek")
	}
	log.Printf("goscan hazır — %d çekirdek, %d goroutine, havuz %d, model %s",
		runtime.NumCPU(), *workers, *maxConn, *model)

	switch {
	case *bench:
		runBench(ctx, engine, *benchN, *workers)
	case *serve:
		runServer(ctx, engine, *addr, *workers)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

// runExtract, verilen metinlerde çıkarımı çalıştırıp JSON basar. Python
// tarafıyla token token karşılaştırmak için var.
func runExtract(modelDir, path string) {
	ex, err := NewExtractor(modelDir)
	if err != nil {
		log.Fatalf("model yüklenemedi: %v", err)
	}
	if ex == nil {
		log.Fatalf("model bulunamadı: %s", modelDir)
	}
	defer ex.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("girdi okunamadı: %v", err)
	}
	var texts []string
	if err := json.Unmarshal(raw, &texts); err != nil {
		log.Fatalf("girdi ayrıştırılamadı: %v", err)
	}
	start := time.Now()
	preds, err := ex.ExtractBatch(texts)
	if err != nil {
		log.Fatalf("çıkarım başarısız: %v", err)
	}
	dt := time.Since(start)
	out := make([]map[string]any, len(preds))
	for i, p := range preds {
		out[i] = map[string]any{"product": p.Product, "version": p.Version, "labels": p.Labels}
	}
	json.NewEncoder(os.Stdout).Encode(out)
	log.Printf("%d metin %.2f sn (%.1f ms/metin)", len(texts), dt.Seconds(),
		dt.Seconds()*1000/float64(len(texts)))
}

func runServer(ctx context.Context, engine *Engine, addr string, defWorkers int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST bekleniyor", http.StatusMethodNotAllowed)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "gövde okunamadı: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Items) == 0 {
			http.Error(w, "'items' boş", http.StatusUnprocessableEntity)
			return
		}
		workers := req.Workers
		if workers <= 0 {
			workers = defWorkers
		}
		start := time.Now()
		results := engine.ScanBatch(r.Context(), req.Items, workers)
		// Zenginleştirme başarısız olursa tarama DÜŞMEZ: kararlar zaten hazır,
		// yalnızca öncelik/düzeltme/destek alanları eksik kalır.
		if err := engine.Enrich(r.Context(), results, maxDetailRows); err != nil {
			log.Printf("zenginleştirme başarısız: %v", err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(scanResponse{
			Results: results, ElapsedMS: time.Since(start).Milliseconds(), Workers: workers,
		})
	})
	// /health yalnızca ayaktalık değil SÜRÜM de bildirir. Python tarafındaki
	// tarama önbelleğinin anahtarı buradan geliyor: karar mantığı artık Go'da,
	// yani Python kaynak dosyalarının özetini anahtar yapmak yanlış olurdu — goscan yeniden
	// derlendiğinde eski kararlar geçersizleşmezdi.
	engineHash := binaryVersion()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"model_version":  engine.modelVersion,
			"engine_version": engineHash,
			"model_loaded":   engine.extractor != nil,
		})
	})
	log.Printf("dinleniyor: %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// binaryVersion, çalışan ikilinin içeriğinden kısa bir damga üretir.
//
// Karar mantığının sürümü budur: kaynak dosyaları çalışma anında okumak yerine
// derlenmiş ikiliyi özetlemek hem kesin (kaynak ağacı olmadan da çalışır) hem
// de tam istediğimiz şeyi ölçer — davranışı belirleyen ikilinin kendisi.
// Okunamazsa önbelleği tamamen kapatmak yerine sabit bir damgaya düşülür.
func binaryVersion() string {
	path, err := os.Executable()
	if err != nil {
		log.Printf("ikili yolu okunamadı, sürüm damgası sabit: %v", err)
		return "unknown"
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("ikili okunamadı, sürüm damgası sabit: %v", err)
		return "unknown"
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Printf("ikili özetlenemedi, sürüm damgası sabit: %v", err)
		return "unknown"
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}

func runBench(ctx context.Context, engine *Engine, n, workers int) {
	items := loadBenchItems(n)
	if len(items) == 0 {
		log.Fatal("ölçüm için kalem bulunamadı")
	}
	// Kaç goroutine denensin: varsayılan yalnızca istenen sayı. Karşılaştırmalı
	// tarama (1/4/8) BİLEREK opsiyonel — seri geçiş tek başına toplam sürenin
	// yarısından fazlasını yiyor ve her ölçümde ödenmesi gerekmiyor.
	passes := []int{workers}
	if os.Getenv("GOSCAN_SWEEP") != "" {
		passes = []int{1, 4, 8, workers}
	}
	for _, w := range passes {
		start := time.Now()
		results := engine.ScanBatch(ctx, items, w)
		dt := time.Since(start)
		threats, missing := 0, 0
		for _, r := range results {
			if r.Status == "THREAT" {
				threats++
			}
			missing += len(r.Missing)
		}
		fmt.Printf("goroutine=%-3d %7.1f sn  %5.2f sn/ürün  THREAT=%d  model gereken CVE=%d\n",
			w, dt.Seconds(), dt.Seconds()/float64(len(items)), threats, missing)
		if r := TimingReport(); r != "" {
			fmt.Print(r)
			ResetTiming()
		}
	}
}

func loadBenchItems(n int) []Item {
	path := os.Getenv("BENCH_ITEMS")
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("ölçüm girdisi okunamadı: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		log.Fatalf("ölçüm girdisi ayrıştırılamadı: %v", err)
	}
	seen := map[string]bool{}
	items := []Item{}
	for _, r := range rows {
		name, _ := r["name"].(string)
		version, _ := r["version"].(string)
		if name == "" || version == "" || seen[name] {
			continue
		}
		seen[name] = true
		vendor, _ := r["vendor"].(string)
		osName, _ := r["os"].(string)
		items = append(items, Item{
			Product: name, Version: version, Vendor: vendor,
			OperatingSystem: normalizeOS(osName),
		})
		if len(items) >= n {
			break
		}
	}
	return items
}

func normalizeOS(s string) string {
	low := ""
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r += 32
		}
		low += string(r)
	}
	switch {
	case contains(low, "mac"):
		return "macOS"
	case contains(low, "windows"):
		return "Windows"
	case contains(low, "linux"):
		return "Linux"
	}
	return ""
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		})()
}
