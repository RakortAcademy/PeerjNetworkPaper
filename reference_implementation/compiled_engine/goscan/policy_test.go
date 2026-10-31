package main

import "testing"

// Geniş aralık kuralı: alt sınır 0/1 ise "her sürüm etkilenmiş" demektir ve bu
// neredeyse her zaman hatalı çıkarımdır.
//
// Kural ilk yazımda Python'ın METİN biçimini ("1 .. 10.0.0") arıyordu; Go
// aralığı "[1, 10.0.0)" olarak yazdığı için hiç yanmaz ve 9.0.90 gibi bir
// sürüme 9.0.0.M1–9.0.37 aralığındaki bir CVE tehdit olarak yazılır. Ölçüt
// artık alt sınırın KENDİSİ.
func TestGenisAralikHerIkiBicimdeYakalanir(t *testing.T) {
	broad := []string{
		"[1, 10.0.0)", "(1, 10.0.0)", "[0, 5.2)", "1 .. 10.0.0",
		"1.0 .. 3.4", "0.0 .. 2.1", "1 <= x < 10",
	}
	for _, c := range broad {
		if !IsSuspectBroadRange("range", c) {
			t.Errorf("geniş aralık yakalanmadı: %q", c)
		}
	}

	// Gerçek aralıklar elenmemeli; aksi hâlde kural tehdit kaçırır.
	real := []string{
		"[9.0.0, 9.0.38)", "[2.4, 3.0)", "9.0.0.m1 .. 9.0.37", "[1.5, 2.0)",
	}
	for _, c := range real {
		if IsSuspectBroadRange("range", c) {
			t.Errorf("gerçek aralık yanlışlıkla elendi: %q", c)
		}
	}

	if IsSuspectBroadRange("lt", "[1, 10.0.0)") {
		t.Error("tür 'range' değilse kural yanmamalı")
	}
}
