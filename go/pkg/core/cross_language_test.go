package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// corpusDir resolves tests/cross-language/canonicalization relative to the
// repository root by walking up from the package directory.
func corpusDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "tests", "cross-language", "canonicalization")
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate tests/cross-language/canonicalization")
	return ""
}

type canonVector struct {
	Name              string `json:"name"`
	Input             string `json:"input"`
	Reject            bool   `json:"reject"`
	ExpectedCanonical string `json:"expected_canonical"`
	ExpectedSHA256    string `json:"expected_sha256"`
}

// TestCrossLanguageCanonicalizationCorpus asserts every shared vector. The same
// corpus is asserted by the Python, JavaScript and Rust suites.
func TestCrossLanguageCanonicalizationCorpus(t *testing.T) {
	dir := corpusDir(t)
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no vectors found in %s", dir)
	}
	sort.Strings(files)
	for _, path := range files {
		raw, err := os.ReadFile(path) // #nosec G304 -- test fixture path
		if err != nil {
			t.Fatal(err)
		}
		var v canonVector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		t.Run(v.Name, func(t *testing.T) {
			parsed, err := ParseSchemaJSON([]byte(v.Input))
			var canonical string
			if err == nil {
				canonical, err = CanonicalizeValue(parsed)
			}
			if v.Reject {
				if err == nil {
					t.Fatalf("expected rejection, got %q", canonical)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if canonical != v.ExpectedCanonical {
				t.Fatalf("canonical mismatch\n got: %q\nwant: %q", canonical, v.ExpectedCanonical)
			}
			sum := sha256.Sum256([]byte(canonical))
			if got := hex.EncodeToString(sum[:]); got != v.ExpectedSHA256 {
				t.Fatalf("sha256 mismatch: %s != %s", got, v.ExpectedSHA256)
			}
			again, err := ParseSchemaJSON([]byte(canonical))
			if err != nil {
				t.Fatal(err)
			}
			if c2, _ := CanonicalizeValue(again); c2 != canonical {
				t.Fatalf("canonicalization is not idempotent: %q != %q", c2, canonical)
			}
		})
	}
}
