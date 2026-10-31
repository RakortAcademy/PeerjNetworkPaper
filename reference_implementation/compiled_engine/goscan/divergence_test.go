package main

import "testing"

// Known divergence between the two released engines (added 2026-10-30 for the
// research reference implementation; see MAPPING.md, "Known engine divergence").
//
// The Python reference engine has a language-binding gate
// (refimpl/applicability.py, is_language_binding_mismatch): an advisory for a
// Perl/Python/Ruby binding or wrapper is not applicable to the underlying
// library. The Go source of this snapshot has no such gate, so ApplyGates lets
// these pairs through and the decision falls to matching and version logic.
// This test pins that state so that the released engines are never described
// as being in full parity on such inputs; if the gate is ported, this test
// fails and the documentation must be updated with it.
func TestKnownDivergenceNoLanguageBindingGate(t *testing.T) {
	cases := []struct{ cveProduct, cveText, customer string }{
		{"Crypt::OpenSSL::PKCS12", "module for Perl", "OpenSSL"}, // Python: binding mismatch (namespace rule)
		{"Net::SSLeay", "Perl module", "OpenSSL"},                // Python: binding mismatch (namespace rule)
	}
	for _, c := range cases {
		if r := ApplyGates(c.cveProduct, "", c.cveText, c.customer, "", ""); r != nil {
			t.Errorf("ApplyGates(%q, %q) = %s gate; the snapshot has no language-binding gate — update MAPPING.md if one was added",
				c.cveProduct, c.customer, r.Kind)
		}
	}
}
