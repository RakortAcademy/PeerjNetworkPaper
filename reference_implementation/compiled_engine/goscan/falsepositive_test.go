package main

import "testing"

// Yanlış tehdit SINIFLARI — bağımsız tasarlanmış sentetik vakalar. Her satır
// bir sınıfı (OS'un kendisine ait CVE, yaygın kelime kimliği, bilinen ayrı
// ürün çifti, eklenti önek muafiyeti, katalog spesifikliği) bu paket için
// yazılmış kurgusal ürün adları, sürümler ve bülten cümleleriyle kurar;
// hiçbiri bir envanterden, olay kaydından ya da önceki bir vaka listesinin
// yeniden adlandırılmasından türetilmemiştir. İşletim sistemi ve büyük satıcı
// adları kuralların sözlüğü olduğu için gerçektir. Aynı vakalar Python'da
// (`tests/test_false_positives.py`) da kilitli.
func TestOlculenYanlisPozitifler(t *testing.T) {
	cases := []struct {
		name, cveProduct, cveVendor, cveText, inventory, endpointOS string
	}{
		// İşletim sisteminin KENDİSİ ≠ üzerinde çalışan uygulama.
		{"Android OS ≠ Android uygulaması", "Google Android", "Google",
			"In Android before 2099-11-02 a local app could read clipboard contents",
			"Android Photo Courier", "macOS"},
		{"Windows Server OS ≠ Windows Snip Studio", "Microsoft Windows Server 2022", "Microsoft",
			"Windows Server Remote Desktop Elevation of Privilege", "Windows Snip Studio", "Windows"},

		// Yaygın kelime tek başına kimlik kanıtı değil. "IBM Secure Gateway"
		// satıcı atılınca {secure, gateway}'e iner.
		{"IBM Secure Gateway ≠ Kestrel Secure Gateway", "IBM Secure Gateway", "IBM",
			"IBM Secure Gateway 3.8.0 and earlier", "Kestrel Secure Gateway", "Windows"},
		{"Weather Monitor ≠ Brightfield Weather Monitor", "Weather Monitor", "Proseware",
			"Improper input validation in Weather Monitor", "Brightfield Weather Monitor", "Windows"},

		// Bilinen ayrı ürün çiftleri (kurgusal bilgi tabanı).
		{"Ravenmail Server ≠ Ravenmail istemcisi", "ravenmail server", "ravenmail",
			"Ravenmail Server before 2099.3.1", "Ravenmail", "macOS"},
		{"Pinecrest ≠ Pinecrest Studio", "Pinecrest", "",
			"The export dialog in Pinecrest before 4.7.2", "Pinecrest Studio", "Windows"},
		{"OrchardSync Enterprise ≠ OrchardSync", "OrchardSync Enterprise", "Fabrikam",
			"OrchardSync Enterprise before 12.4 allows SSRF", "OrchardSync", "Linux"},
		{"Glasswing Publisher ≠ Glasswing Reader", "Glasswing Publisher", "Litware",
			"An issue was discovered in Glasswing Publisher 5.0.1", "Glasswing Reader", "macOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if g := ApplyGates(c.cveProduct, c.cveVendor, c.cveText, c.inventory, "", c.endpointOS); g == nil {
				t.Errorf("ApplyGates(%q, %q) kapı yakmadı — bu bir yanlış tehdit",
					c.cveProduct, c.inventory)
			}
		})
	}
}

// Kapıların ELEMEMESİ gereken gerçek eşleşmeler. Her kural, muafiyeti olmadan
// bunları da eler.
func TestGercekEslesmelerElenmemeli(t *testing.T) {
	cases := []struct {
		name, cveProduct, cveVendor, cveText, inventory, endpointOS string
	}{
		// Bitişik aile: token düzeyinde kapsamıyor, aile kuralıyla geçiyor.
		{"BrightwaveLinux ↔ Brightwave Agent", "Woodgrove BrightwaveLinux", "Woodgrove",
			"A vulnerability in Brightwave for Linux", "Brightwave Agent", "Linux"},
		// Platform tokenı ürün kimliğinin parçası değil.
		{"Driftguard For Mac", "Proseware Driftguard Backup, Proseware Driftguard Cloud", "Proseware",
			"Proseware Driftguard Backup allows local privilege escalation",
			"Proseware Driftguard Backup For Mac", "macOS"},
		// Satıcı öneki atılabilmeli.
		{"Litware Inkwell Notes ↔ Inkwell Notes", "Litware Inkwell Notes", "Litware",
			"A memory corruption issue was addressed in Inkwell Notes 9.3", "Inkwell Notes", "macOS"},
		// Ad birebir aynıysa yaygın kelime kuralı işlememeli.
		{"Weather ↔ Weather", "Weather", "Contoso",
			"An issue in the Weather app", "Weather", "macOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if g := ApplyGates(c.cveProduct, c.cveVendor, c.cveText, c.inventory, "", c.endpointOS); g != nil {
				t.Errorf("ApplyGates(%q, %q) eledi (%s: %s) — gerçek eşleşme kaybı",
					c.cveProduct, c.inventory, g.Kind, g.Reason)
			}
		})
	}
}

// Eklenti kapısının muafiyeti ÖZDEŞLİK ister, önek değil. Önek ölçütüyle
// "Recipe Box" adı "Recipe Box Importer"ın önekini oluşturur ve aynı adlı
// masaüstü uygulaması WordPress eklentisi CVE'leri alır.
func TestEklentiMuafiyetiOzdeslikIster(t *testing.T) {
	if !IsWebCMSPlugin("Recipe Box Importer",
		"The Recipe Box Importer WordPress plugin before 3.0.4", "", "Recipe Box") {
		t.Error("WordPress eklentisi masaüstü uygulamasına uygulanamaz")
	}
	if !IsWebCMSPlugin("Weather Widget Deluxe",
		"The Weather Widget Deluxe plugin for WordPress", "", "Weather") {
		t.Error("WordPress eklentisi hava durumu uygulamasına uygulanamaz")
	}
	// Envanterdeki ürün eklentinin TA KENDİSİyse kapı yanmamalı.
	if IsWebCMSPlugin("Formcrafter", "The Formcrafter WordPress plugin before 1.9.0", "", "Formcrafter 1.8.7") {
		t.Error("eklentinin kendisi taranıyorsa kapı yanmamalı")
	}
}

// Katalog ürünü KENDİ adıyla tanıyorsa CVE en az o kadar spesifik adlandırmalı.
// Bu kural kapıda değil karar akışında: katalogda ürünün tam adının bulunup
// bulunmadığı veritabanı sorusudur.
func TestKatalogSpesifikligi(t *testing.T) {
	// Katalogda "inkwell notes" ayrı bir ürün olarak var; daha genel ad
	// kullanan CVE o ürünü kastetmiyor.
	if identityCovers("Litware Inkwell 2024 version 9.1", "Inkwell Notes") {
		t.Error("Inkwell, Inkwell Notes kadar spesifik değil")
	}
	if identityCovers("Litware Thermal Sensor drivers", "Proseware Thermal Sensor Driver") {
		t.Error("bir satıcının sürücüsü başka satıcının sürücüsünü kapsamamalı")
	}
	// Bunlar KAPSAMALI — aksi hâlde gerçek tehdit kaybı.
	if !identityCovers("Litware Inkwell Notes", "Inkwell Notes") {
		t.Error("aynı ürün kapsamalı")
	}
	if !identityCovers("Proseware Driftguard Backup, Proseware Driftguard Cloud", "Proseware Driftguard Backup For Mac") {
		t.Error("platform tokenı ('mac') kimlik şartı olmamalı")
	}
	if !identityCovers("Litware Inkwell Notes", "Inkwell Notes 9") {
		t.Error("satıcı öneki kapsamayı bozmamalı")
	}
}

// CVE'nin ürün alanı tek başına kimlik taşımıyorsa satıcı öne eklenmeli:
// bazı kayıtlarda alan yalnızca "server" yazar (satıcı ayrı sütunda).
func TestKimliksizUrunAlani(t *testing.T) {
	if len(IdentityTokens("server")) != 0 {
		t.Errorf("'server' kimlik tokenı taşımamalı: %v", IdentityTokens("server"))
	}
	if DistinctProductPair("ravenmail server", "Ravenmail") == "" {
		t.Error("satıcı eklendikten sonra çift kuralı yanmalı")
	}
}

// Çapraz ürün metni ve yabancı sürüm sınırı (knownCrossProduct, foreignMarkers)
// — Python `TestCaprazUrunMetni` / `TestYabanciSurumSiniri` ile aynı girdiler.
func TestCaprazUrunVeYabanciSinir(t *testing.T) {
	v := AssessThreatIdentity("brindle",
		"An SSRF in the Brindle Cloud Console allows tenant data exposure.", "3.2.0", "< 5.0", "")
	if v.Confirmed || v.Method != "rejected" {
		t.Errorf("çapraz ürün metni reddedilmeli: %+v", v)
	}
	v = AssessThreatIdentity("brindle", "A crafted project file crashes Brindle before 3.4.", "3.2.0", "< 3.4", "catalog")
	if !v.Confirmed {
		t.Errorf("metin yalnızca envanterdeki ürünü anıyorsa geçmeli: %+v", v)
	}
	text := "Quillon desktop editor embeds quillon-py; quillon-py before 0.9.4 allows code execution through crafted notebooks."
	v = AssessThreatIdentity("quillon", text, "4.2.1", "< 0.9.4", "")
	if v.Confirmed || v.Method != "rejected" {
		t.Errorf("yabancı ürünün sınırı reddedilmeli: %+v", v)
	}
	if r := foreignVersionBinding("quillon-py", "0.9.1", "< 0.9.4", text); r != "" {
		t.Errorf("envanterin kendisi o paketse kural işlememeli: %s", r)
	}
}
