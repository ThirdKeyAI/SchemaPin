package core

import (
	"encoding/json"
	"testing"
)

// FuzzParseSchemaJSON asserts the strict parser never panics and that its
// output canonicalizes idempotently.
func FuzzParseSchemaJSON(f *testing.F) {
	for _, seed := range []string{
		`{"a":1}`, `[1,2.5,"x",null,true]`, `{"b":{"a":[1e-7,0.1]}," ":"<>&"}`,
		`{"a":1,"a":2}`, `{"a":NaN}`, `{"a":"\ud800"}`, `{"a":9007199254740993}`, `{"__proto__":1}`,
		"", "{", "\xff", `"\u0000"`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := ParseSchemaJSON(data)
		if err != nil {
			return
		}
		c1, err := CanonicalizeValue(v)
		if err != nil {
			t.Fatalf("parsed value failed to canonicalize: %v", err)
		}
		v2, err := ParseSchemaJSON([]byte(c1))
		if err != nil {
			t.Fatalf("canonical output does not re-parse: %v", err)
		}
		c2, _ := CanonicalizeValue(v2)
		if c1 != c2 {
			t.Fatalf("not idempotent: %q vs %q", c1, c2)
		}
		if !json.Valid([]byte(c1)) {
			t.Fatalf("canonical output is not valid JSON: %q", c1)
		}
	})
}
