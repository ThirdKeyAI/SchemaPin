package bundle

import "testing"

// FuzzParseTrustBundle asserts bundle parsing and verification never panic.
func FuzzParseTrustBundle(f *testing.F) {
	f.Add(`{"schemapin_bundle_version":"1.2","created_at":"x","documents":[],"revocations":[]}`)
	f.Add(`{"schemapin_bundle_version":"1.4","created_at":"x","documents":[{"domain":"a"},{"domain":"a"}],"revocations":[],"bundle_authority":{"kid":"k","public_key_pem":"bad"},"signature":"AAAA"}`)
	f.Add(`[]`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, doc string) {
		b, err := ParseTrustBundle(doc)
		if err != nil {
			return
		}
		_, _ = VerifyTrustBundleWithOptions(b, NewAuthorityPinStore(), BundleVerifyOptions{AllowFirstUse: true})
		_ = MergeTrustBundles([]*SchemaPinTrustBundle{b, b})
	})
}
