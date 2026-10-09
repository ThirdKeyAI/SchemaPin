package domain

import "testing"

// FuzzValidateDomain asserts the validator never panics and is idempotent on
// its own output.
func FuzzValidateDomain(f *testing.F) {
	for _, seed := range []string{"example.com", "Example.COM", "../x", "10.0.0.1", "a@b.c", "", "xn--bcher-kva.example"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		normalized, err := ValidateDomain(s)
		if err != nil {
			return
		}
		again, err := ValidateDomain(normalized)
		if err != nil || again != normalized {
			t.Fatalf("not idempotent: %q -> %q (%v)", normalized, again, err)
		}
	})
}
