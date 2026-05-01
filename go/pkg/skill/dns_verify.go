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
	result := VerifySkillOffline(skillDir, disc, sig, rev, pinStore, toolID)
	if !result.Valid || dnsTxt == nil {
		return result
	}
	if err := dns.VerifyDnsMatch(disc, dnsTxt); err != nil {
		return &verification.VerificationResult{
			Valid:        false,
			Domain:       result.Domain,
			ErrorCode:    verification.ErrDomainMismatch,
			ErrorMessage: err.Error(),
		}
	}
	return result
}
