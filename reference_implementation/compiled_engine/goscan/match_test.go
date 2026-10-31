package main

import "testing"

// Yanlış eşleşme sınıfları (kurgusal adlarla). Üçü de Python'da reddediliyor;
// Go tarafı da reddetmeli, yoksa iki motor sessizce ayrışır.
func TestKnownFalseMatches(t *testing.T) {
	cases := []struct {
		name, cveProduct, inventory string
	}{
		// Model metinden "Halcyon Studio Suite" çıkarıyor; envanter satıcının
		// kurulum yardımcısı. Ortak olan yalnızca satıcı adı.
		{"Halcyon Studio ≠ Setup Assistant", "Halcyon Studio Suite (HSS)", "Halcyon Setup Assistant"},
		// "Fabrikam Edge HMI" ile "Orbital Edge" yalnızca "edge" paylaşıyor.
		// CoversProduct iki yönlü olsaydı bu eşleşirdi.
		{"Fabrikam Edge ≠ Orbital Edge", "Fabrikam Edge HMI", "Orbital Edge"},
		// Normalizasyon "Redistributable" ve "2015" tokenlarını atınca ad
		// "microsoft visual"a iniyor ve Visual Studio ile eşleşiyordu.
		{"Visual Studio ≠ VC++ Redist", "Microsoft Visual Studio",
			"Microsoft Visual C++ 2015-2022 Redistributable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if CoversProduct(c.cveProduct, c.inventory) {
				t.Errorf("CoversProduct(%q, %q) = true, olmamalı", c.cveProduct, c.inventory)
			}
			if ok, score := MatchExtractedName(c.cveProduct, c.inventory); ok {
				t.Errorf("MatchExtractedName(%q, %q) = true (%.3f), olmamalı",
					c.cveProduct, c.inventory, score)
			}
		})
	}
}

// Normalizasyon KİMLİK çıkarımından farklı bir token kümesi kullanır. İkisini
// karıştırmak "Visual C++ 2015-2022 Redistributable"ı "microsoft visual"a
// indiriyordu; "2015" bir yıl işareti değil, ürünü ayırt eden bilgidir.
func TestNormalizeKeepsDistinguishingTokens(t *testing.T) {
	got := NormalizeProductName("Microsoft Visual C++ 2015-2022 Redistributable")
	for _, want := range []string{"2015", "2022", "redistributable"} {
		if !contains(got, want) {
			t.Errorf("normalize %q → %q, %q korunmalıydı",
				"Microsoft Visual C++ 2015-2022 Redistributable", got, want)
		}
	}
}

// CoversProduct YÖNLÜdür: CVE daha genel adlandırma kullanabilir, ters yön
// bir bileşenin açığını tüm ürüne yayardı.
func TestCoversProductIsDirectional(t *testing.T) {
	// CVE tür kelimesi ekleyebilir ("Server" kimlik dışıdır) → kapsar.
	if !CoversProduct("MySQL Server", "MySQL") {
		t.Error("CVE daha genel ad kullanabilmeli: MySQL Server ⊆ MySQL")
	}
	// CVE daha SPESİFİK bir ürün adlandırıyorsa kapsamaz: MySQL Cluster'ın
	// açığını MySQL kurulumuna yaymak yanlış pozitiftir.
	if CoversProduct("MySQL Cluster", "MySQL") {
		t.Error("CVE daha spesifikse kapsamamalı: bileşenin açığı ürüne yayılır")
	}
}

// Bitişik ürün aileleri: ortak kökten sonrası yalnızca platform eki olmalı.
func TestCompoundFamily(t *testing.T) {
	cases := []struct {
		cve, inv string
		same     bool
	}{
		{"BrightwaveLinux", "Brightwave Agent", true},
		{"Woodgrove BrightwaveLinux", "Brightwave", true},
		{"BrightwaveOS", "BrightwaveRouter", false}, // kalan "os"/"router" platform eki değil
		{"ChromeOS", "Chrome", false},               // biri tarayıcı, öteki işletim sistemi
		{"BrightwaveConsole", "Brightwave", false},  // yönetim konsolu ayrı ürün
	}
	for _, c := range cases {
		if got := SameCompoundFamily(c.cve, c.inv); got != c.same {
			t.Errorf("SameCompoundFamily(%q, %q) = %v, beklenen %v",
				c.cve, c.inv, got, c.same)
		}
	}
}

// Satıcı alanı ürün adının kendisiyse bilgi taşımaz (CNA vendor="Glimmerpost").
// Ölçüt ÖRTÜŞME değil ÖZDEŞLİK: "Fabrikam" ile "Fabrikam Calendar" token
// paylaşır ama satıcı alanı orada gerçek bilgidir.
func TestVendorGate(t *testing.T) {
	if VendorNotApplicable("Glimmerpost", "Ines Calder", "Glimmerpost") {
		t.Error("satıcı alanı ürün adıysa veto etmemeli")
	}
	if !VendorNotApplicable("Fabrikam", "Contoso", "Fabrikam Calendar") {
		t.Error("gerçek satıcı çelişkisi veto etmeli")
	}
	if VendorNotApplicable("Woodgrove", "Woodgrove Systems Ltd", "BrightwaveLinux") {
		t.Error("kurumsal ek çelişki sayılmamalı")
	}
}

// OS kapısı: başka bir OS ailesine özgü CVE uç noktaya uygulanmaz.
func TestOSGate(t *testing.T) {
	g := ApplyGates("Chrome", "Google", "Google Chrome on Android prior to 148.0",
		"Google Chrome", "", "Windows")
	if g == nil || g.Kind != "os" {
		t.Errorf("Android'e özgü CVE Windows uç noktasında elenmeliydi, sonuç: %+v", g)
	}
	if g := ApplyGates("Chrome", "Google", "Google Chrome prior to 148.0",
		"Google Chrome", "", "Windows"); g != nil {
		t.Errorf("platform belirtmeyen CVE elenmemeliydi: %+v", g)
	}
	// İşletim sistemi bilinmiyorsa kapı çalışmaz — bilinmeyenden çelişki çıkmaz.
	if g := ApplyGates("Chrome", "Google", "Chrome on Android", "Google Chrome", "", ""); g != nil {
		t.Errorf("OS bilinmiyorken kapı yanmamalı: %+v", g)
	}
}

// `IdentityTokens` ile `StripEditionTokens` FARKLI bölme kullanır.
//
// Kimlik çıkarımı tire ve noktadan DA böler; edisyon ayıklama bölmez (orada
// "14.40.33810" tek parça kalmalı). İkisini aynı sanmak "relaydesk-client"ı tek
// kimlik tokenı yapar ve "relaydesk-client Relaydesk Client" ile "Relaydesk"
// eşleşmez; o ürünün tehditleri kaçar.
func TestIdentityTokensSplitOnHyphen(t *testing.T) {
	ids := IdentityTokens("rustdesk-client RustDesk Client")
	if len(ids) != 1 || !ids["rustdesk"] {
		t.Errorf("identity = %v, beklenen tek token {rustdesk}", ids)
	}
	if !CoversProduct("rustdesk-client RustDesk Client", "RustDesk") {
		t.Error("satıcı öneki ve tür kelimesi ayıklanınca kapsamalı")
	}
	// Edisyon ayıklama tireden BÖLMEMELİ; sürüm parçaları bütün kalmalı.
	if got := StripEditionTokens("app 14.40.33810-x"); len(got) == 0 {
		t.Errorf("strip = %v", got)
	}
}
