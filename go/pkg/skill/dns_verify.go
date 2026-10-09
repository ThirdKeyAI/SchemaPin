// Skill verification with optional DNS TXT cross-check (v1.4-alpha).

package skill

import (
	"github.com/ThirdKeyAi/schemapin/go/pkg/discovery"
	"github.com/ThirdKeyAi/schemapin/go/pkg/dns"
	"github.com/ThirdKeyAi/schemapin/go/pkg/revocation"
	"github.com/ThirdKeyAi/schemapin/go/pkg/verification"
)

// VerifySkillOfflineWithDNS performs the standard offline verification flow
// and then -- when dnsTxt is non-nil -- cross-checks the DNS TXT record's
// fingerprint against the discovery key.
//
// Behaviour mirrors the Rust verify_skill_offline_with_dns:
//   - dnsTxt == nil               -> identical to VerifySkillOffline
//   - underlying verification fails -> returned as-is, no DNS check
//   - DNS fingerprint matches      -> result returned unchanged
//   - DNS fingerprint mismatches   -> failed result with ErrDomainMismatch
//
// DNS TXT cross-verification is an optional, additive trust signal: an
// absent record never causes a failure, but a present-and-mismatched record
// is a hard failure (the second-channel check exists precisely to catch
// HTTPS-side compromise).
func VerifySkillOfflineWithDNS(
	skillDir string,
	disc *discovery.WellKnownResponse,
	sig *SkillSignature,
	rev *revocation.RevocationDocument,
	pinStore *verification.KeyPinStore,
	toolID string,
	dnsTxt *dns.DnsTxtRecord,
) *verification.VerificationResult {
	return VerifySkillOfflineWithDNSOptions(skillDir, disc, sig, rev, pinStore, dnsTxt, VerifyOptions{ToolID: toolID})
}

// VerifySkillOfflineWithDNSOptions is VerifySkillOfflineWithDNS with explicit
// policy knobs. The DNS cross-check runs before verification so that a
// mismatching key is never pinned.
func VerifySkillOfflineWithDNSOptions(
	skillDir string,
	disc *discovery.WellKnownResponse,
	sig *SkillSignature,
	rev *revocation.RevocationDocument,
	pinStore *verification.KeyPinStore,
	dnsTxt *dns.DnsTxtRecord,
	opts VerifyOptions,
) *verification.VerificationResult {
	if dnsTxt != nil {
		if err := dns.VerifyDnsMatch(disc, dnsTxt); err != nil {
			return &verification.VerificationResult{
				Valid:        false,
				Domain:       opts.Domain,
				ErrorCode:    verification.ErrDomainMismatch,
				ErrorMessage: err.Error(),
			}
		}
	}
	return VerifySkillOfflineWithOptions(skillDir, disc, sig, rev, pinStore, opts)
}
