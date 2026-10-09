package pinning

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

const (
	pemA = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
	pemB = "-----BEGIN PUBLIC KEY-----\nBBBB\n-----END PUBLIC KEY-----"
)

// TestPinsAreBoundToDomain is the SP-15 regression: a pin recorded for one
// domain must never satisfy a lookup for another.
func TestPinsAreBoundToDomain(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pins.db")
	store, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if err := store.PinKey("calculator", pemA, "evil.com", ""); err != nil {
		t.Fatal(err)
	}
	if key, _ := store.GetPinnedKeyForDomain("calculator", "good.com"); key != "" {
		t.Fatal("evil.com pin must not satisfy good.com")
	}
	if store.IsKeyPinnedForDomain("calculator", "good.com") {
		t.Fatal("IsKeyPinnedForDomain must be false for another domain")
	}
	if key, _ := store.GetPinnedKeyForDomain("calculator", "evil.com"); key != pemA {
		t.Fatalf("expected evil.com pin, got %q", key)
	}
	if err := store.PinKey("calculator", pemB, "good.com", ""); err != nil {
		t.Fatal(err)
	}
	if key, _ := store.GetPinnedKeyForDomain("calculator", "good.com"); key != pemB {
		t.Fatalf("expected good.com pin, got %q", key)
	}
	// The deprecated domain-less lookup refuses to guess between domains.
	if key, _ := store.GetPinnedKey("calculator"); key != "" {
		t.Fatalf("ambiguous lookup must return nothing, got %q", key)
	}
	if err := store.RemovePinnedKeyForDomain("calculator", "evil.com"); err != nil {
		t.Fatal(err)
	}
	if key, _ := store.GetPinnedKey("calculator"); key != pemB {
		t.Fatalf("single remaining pin must resolve, got %q", key)
	}
}

// TestLegacyKeysAreMigrated opens a store written in the pre-1.4 layout
// (bucket keyed by bare tool id) and expects composite keys afterwards.
func TestLegacyKeysAreMigrated(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(pinnedKeysBucket)
		if err != nil {
			return err
		}
		data, _ := json.Marshal(PinnedKeyInfo{ToolID: "calc", PublicKeyPEM: pemA, Domain: "example.com", PinnedAt: time.Now()})
		return b.Put([]byte("calc"), data)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	store, err := NewKeyPinning(dbPath, PinningModeAutomatic, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if key, _ := store.GetPinnedKeyForDomain("calc", "example.com"); key != pemA {
		t.Fatalf("migrated pin missing, got %q", key)
	}
	err = store.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(pinnedKeysBucket)
		if b.Get([]byte("calc")) != nil {
			t.Error("legacy key must be removed after migration")
		}
		if b.Get([]byte("calc@example.com")) == nil {
			t.Error("composite key must exist after migration")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dbPath); err == nil && st.Mode().Perm()&0o077 != 0 {
		t.Errorf("store must be owner-only, got %o", st.Mode().Perm())
	}
}
