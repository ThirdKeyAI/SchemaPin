package dns

import "testing"

// FuzzParseTxtRecord asserts the TXT parser never panics on arbitrary input.
func FuzzParseTxtRecord(f *testing.F) {
	for _, seed := range []string{
		"v=schemapin1; fp=sha256:abc", "v=schemapin1;kid=x;fp=SHA256:ABC", "fp=sha256:abc", "v=;", "=", ";;;", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rec, err := ParseTxtRecord(s)
		if err == nil && rec.Fingerprint == "" {
			t.Fatal("accepted record without fingerprint")
		}
	})
}
