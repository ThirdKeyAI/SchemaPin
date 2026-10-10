package crypto

import "testing"

// FuzzLoadPublicKeyPEM asserts the PEM loader never panics and only yields
// P-256 keys.
func FuzzLoadPublicKeyPEM(f *testing.F) {
	km := NewKeyManager()
	priv, _ := km.GenerateKeypair()
	pem, _ := km.ExportPublicKeyPEM(&priv.PublicKey)
	f.Add(pem)
	f.Add("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		key, err := km.LoadPublicKeyPEM(s)
		if err == nil && key.Curve.Params().Name != "P-256" {
			t.Fatalf("accepted non-P-256 key %s", key.Curve.Params().Name)
		}
		_ = NewSignatureManager().VerifySignature([]byte("x"), s, &priv.PublicKey)
	})
}
