// Model çıkarımı — Python `refimpl/extraction/` karşılığı, PyTorch olmadan.
//
// Ağ ONNX olarak dışa aktarılır (`refimpl/export/export_onnx.py`), CRF çözümlemesi
// burada yazılır. Neden ikiye bölündü: `torchcrf.decode()` veriye bağlı döngü
// içerir ve ONNX'e temiz çıkmaz. Gerek de yok — CRF üç küçük tensörden ibaret
// (6 başlangıç, 6 bitiş, 6x6 geçiş) ve Viterbi deterministik.
//
// Eşitlik doğrulandı: 300 gerçek CVE metninde PyTorch-CUDA ile bu yol AYNI
// etiket dizisini üretti (14.180 token'da 0 fark).
//
// ONNX Runtime paylaşımlı kütüphanesi çalışma anında yüklenir; yolu
// ONNXRUNTIME_LIB ile verilir. Kütüphane ya da model dosyaları yoksa çıkarım
// KAPALI olur ve tarama düşmez — eksik CVE'ler `needs_model` ile bildirilir.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	ort "github.com/yalue/onnxruntime_go"
)

// Extractor, CVE metninden ürün ve sürüm adı çıkarır.
type Extractor struct {
	session    *ort.DynamicAdvancedSession
	token2idx  map[string]int64
	char2idx   map[string]int64
	unkToken   int64
	unkChar    int64
	padChar    int64
	maxLen     int
	maxWordLen int
	tagset     int
	idx2label  []string

	// CRF geçiş ağırlıkları.
	start []float32
	end   []float32
	trans [][]float32

	// ONNX oturumu iş parçacığı güvenli değil sayılır; toplu çağrılar zaten
	// seyrek olduğu için tek kilit yeterli.
	mu sync.Mutex
}

type crfWeights struct {
	Start       []float32   `json:"start"`
	End         []float32   `json:"end"`
	Transitions [][]float32 `json:"transitions"`
}

type modelMeta struct {
	MaxLen       int            `json:"max_len"`
	MaxWordLen   int            `json:"max_word_len"`
	TagsetSize   int            `json:"tagset_size"`
	Label2Idx    map[string]int `json:"label2idx"`
	ModelVersion string         `json:"model_version"`
}

// NewExtractor, `dir` altındaki dışa aktarımı yükler. Model isteğe bağlıdır:
// dosyalar ya da ONNX kütüphanesi yoksa (nil, nil) döner ve çağıran çıkarımsız
// çalışır.
func NewExtractor(dir string) (*Extractor, error) {
	if dir == "" {
		return nil, nil
	}
	onnxPath := filepath.Join(dir, "emissions.onnx")
	if _, err := os.Stat(onnxPath); err != nil {
		return nil, nil
	}

	var meta modelMeta
	if err := readJSON(filepath.Join(dir, "meta.json"), &meta); err != nil {
		return nil, err
	}
	var crf crfWeights
	if err := readJSON(filepath.Join(dir, "crf.json"), &crf); err != nil {
		return nil, err
	}
	tok := map[string]int64{}
	if err := readJSON(filepath.Join(dir, "token2idx.json"), &tok); err != nil {
		return nil, err
	}
	ch := map[string]int64{}
	if err := readJSON(filepath.Join(dir, "char2idx.json"), &ch); err != nil {
		return nil, err
	}

	if lib := os.Getenv("ONNXRUNTIME_LIB"); lib != "" {
		ort.SetSharedLibraryPath(lib)
	}
	if !ort.IsInitialized() {
		if err := ort.InitializeEnvironment(); err != nil {
			return nil, fmt.Errorf("onnxruntime başlatılamadı: %w", err)
		}
	}
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, err
	}
	defer opts.Destroy()
	// Ölçümde ONNX-CPU, PyTorch-CUDA'dan hızlı çıktı: model 8,8M parametreyle
	// küçük ve GPU'da çekirdek başlatma yükü
	// baskın geliyor. Bu yüzden GPU sağlayıcısı BİLEREK istenmiyor.
	_ = opts.SetIntraOpNumThreads(4)

	sess, err := ort.NewDynamicAdvancedSession(onnxPath,
		[]string{"words", "chars"}, []string{"emissions"}, opts)
	if err != nil {
		return nil, fmt.Errorf("onnx oturumu açılamadı: %w", err)
	}

	idx2label := make([]string, meta.TagsetSize)
	for name, i := range meta.Label2Idx {
		if i >= 0 && i < len(idx2label) {
			idx2label[i] = name
		}
	}
	e := &Extractor{
		session: sess, token2idx: tok, char2idx: ch,
		unkToken: tok["UNK"], unkChar: ch["UNK"], padChar: ch["PAD"],
		maxLen: meta.MaxLen, maxWordLen: meta.MaxWordLen,
		tagset: meta.TagsetSize, idx2label: idx2label,
		start: crf.Start, end: crf.End, trans: crf.Transitions,
	}
	if e.maxLen == 0 {
		e.maxLen, e.maxWordLen = 200, 20
	}
	return e, nil
}

func readJSON(path string, into any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (e *Extractor) Close() {
	if e != nil && e.session != nil {
		e.session.Destroy()
	}
}

// Prediction, tek metin için model çıktısı.
type Prediction struct {
	Product string
	Version string
	Tokens  []string
	Labels  []string
}

// ExtractBatch, birden çok CVE metnini TEK ileri geçişte çözümler.
//
// Girdiyle aynı sırada döner. Boş metinler modele GİRMEZ: maskeleri tümüyle
// false olur ve CRF ilk adımda maske gerektirir.
func (e *Extractor) ExtractBatch(texts []string) ([]Prediction, error) {
	out := make([]Prediction, len(texts))
	if e == nil || len(texts) == 0 {
		return out, nil
	}

	tokenized := make([][]string, len(texts))
	usable := []int{}
	for i, t := range texts {
		tokenized[i] = strings.Fields(t)
		if len(tokenized[i]) > 0 {
			usable = append(usable, i)
		}
	}
	if len(usable) == 0 {
		return out, nil
	}

	// Yığın parçalara bölünür: karakter tensörü (yığın × 200 × 20) hızla
	// büyür ve aday sayısı üst sınırı kaldırıldığından tek çağrıda binlerce
	// CVE gelebiliyor; binlerce adaylı bir ürün parçalama olmadan taşırır.
	const chunk = 256
	for from := 0; from < len(usable); from += chunk {
		to := from + chunk
		if to > len(usable) {
			to = len(usable)
		}
		if err := e.runChunk(tokenized, usable[from:to], out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (e *Extractor) runChunk(tokenized [][]string, slots []int, out []Prediction) error {
	b, L, W := len(slots), e.maxLen, e.maxWordLen
	words := make([]int64, b*L)
	chars := make([]int64, b*L*W)
	// Karakter dolgusu PAD ile başlar; sıfır olmayan bir PAD indeksi olabilir.
	for i := range chars {
		chars[i] = e.padChar
	}

	lengths := make([]int, b)
	for r, slot := range slots {
		toks := tokenized[slot]
		n := len(toks)
		if n > L {
			n = L // sondan kırpma; Python `pad_sequences(truncating='post')`
		}
		lengths[r] = n
		for c := 0; c < n; c++ {
			// Kelime araması KÜÇÜK HARFLE yapılır; karakterler ise ham hâliyle
			// kodlanır — büyük/küçük harf bilgisi karakter katmanının işi.
			id, ok := e.token2idx[strings.ToLower(toks[c])]
			if !ok {
				id = e.unkToken
			}
			words[r*L+c] = id
			base := (r*L + c) * W
			k := 0
			for _, ru := range toks[c] {
				if k >= W {
					break
				}
				cid, ok := e.char2idx[string(ru)]
				if !ok {
					cid = e.unkChar
				}
				chars[base+k] = cid
				k++
			}
		}
	}

	wt, err := ort.NewTensor(ort.NewShape(int64(b), int64(L)), words)
	if err != nil {
		return err
	}
	defer wt.Destroy()
	ct, err := ort.NewTensor(ort.NewShape(int64(b), int64(L), int64(W)), chars)
	if err != nil {
		return err
	}
	defer ct.Destroy()
	em, err := ort.NewEmptyTensor[float32](ort.NewShape(int64(b), int64(L), int64(e.tagset)))
	if err != nil {
		return err
	}
	defer em.Destroy()

	e.mu.Lock()
	err = e.session.Run([]ort.Value{wt, ct}, []ort.Value{em})
	e.mu.Unlock()
	if err != nil {
		return fmt.Errorf("çıkarım başarısız: %w", err)
	}

	data := em.GetData()
	for r, slot := range slots {
		n := lengths[r]
		if n == 0 {
			continue
		}
		emis := data[r*L*e.tagset : (r*L+n)*e.tagset]
		tags := e.viterbi(emis, n)
		out[slot] = e.decodeLabels(tokenized[slot], tags)
	}
	return nil
}

// viterbi, CRF'in en olası etiket dizisini bulur.
//
// `torchcrf.decode()` ile birebir aynı: başlangıç geçişleri ilk adıma, bitiş
// geçişleri son adıma eklenir; maske dışı adımlar zaten dizide yok.
func (e *Extractor) viterbi(emissions []float32, n int) []int {
	T := e.tagset
	score := make([]float32, T)
	backptr := make([][]int, n)
	for t := 0; t < T; t++ {
		score[t] = e.start[t] + emissions[t]
	}
	for i := 1; i < n; i++ {
		next := make([]float32, T)
		back := make([]int, T)
		for cur := 0; cur < T; cur++ {
			best := float32(math.Inf(-1))
			bestPrev := 0
			for prev := 0; prev < T; prev++ {
				s := score[prev] + e.trans[prev][cur]
				if s > best {
					best, bestPrev = s, prev
				}
			}
			next[cur] = best + emissions[i*T+cur]
			back[cur] = bestPrev
		}
		backptr[i] = back
		score = next
	}
	bestLast, bestScore := 0, float32(math.Inf(-1))
	for t := 0; t < T; t++ {
		if s := score[t] + e.end[t]; s > bestScore {
			bestScore, bestLast = s, t
		}
	}
	tags := make([]int, n)
	tags[n-1] = bestLast
	for i := n - 1; i > 0; i-- {
		tags[i-1] = backptr[i][tags[i]]
	}
	return tags
}

// decodeLabels, etiket dizisinden ürün ve sürüm parçalarını toplar.
func (e *Extractor) decodeLabels(tokens []string, tags []int) Prediction {
	p := Prediction{Tokens: tokens, Labels: make([]string, 0, len(tags))}
	product, version := []string{}, []string{}
	for i, tag := range tags {
		if i >= len(tokens) {
			break
		}
		label := "O"
		if tag >= 0 && tag < len(e.idx2label) && e.idx2label[tag] != "" {
			label = e.idx2label[tag]
		}
		p.Labels = append(p.Labels, label)
		switch label {
		case "B-PRODUCT", "I-PRODUCT":
			product = append(product, tokens[i])
		case "B-VERSION", "I-VERSION":
			version = append(version, tokens[i])
		}
	}
	p.Product = strings.Join(product, " ")
	p.Version = strings.Join(version, " ")
	return p
}
