// Package revocation provides standalone revocation documents for SchemaPin v1.2.
package revocation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ThirdKeyAi/schemapin/go/pkg/transport"
)

// RevocationReason represents why a key was revoked.
type RevocationReason string

const (
	ReasonKeyCompromise        RevocationReason = "key_compromise"
	ReasonSuperseded           RevocationReason = "superseded"
	ReasonCessationOfOperation RevocationReason = "cessation_of_operation"
	ReasonPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
)

// RevokedKey represents a single revoked key entry.
type RevokedKey struct {
	Fingerprint string           `json:"fingerprint"`
	RevokedAt   string           `json:"revoked_at"`
	Reason      RevocationReason `json:"reason"`
}

// RevocationDocument represents a standalone revocation document.
type RevocationDocument struct {
	SchemapinVersion string       `json:"schemapin_version"`
	Domain           string       `json:"domain"`
	UpdatedAt        string       `json:"updated_at"`
	RevokedKeys      []RevokedKey `json:"revoked_keys"`
}

// BuildRevocationDocument creates an empty revocation document for a domain.
func BuildRevocationDocument(domain string) *RevocationDocument {
	return &RevocationDocument{
		SchemapinVersion: "1.2",
		Domain:           domain,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339),
		RevokedKeys:      []RevokedKey{},
	}
}

// AddRevokedKey adds a revoked key entry to the document.
func AddRevokedKey(doc *RevocationDocument, fingerprint string, reason RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedKeys = append(doc.RevokedKeys, RevokedKey{
		Fingerprint: fingerprint,
		RevokedAt:   now,
		Reason:      reason,
	})
	doc.UpdatedAt = now
}

// CheckRevocation checks if a fingerprint is revoked in the standalone document.
func CheckRevocation(doc *RevocationDocument, fingerprint string) error {
	for _, key := range doc.RevokedKeys {
		if key.Fingerprint == fingerprint {
			return fmt.Errorf("key %s is revoked: %s", fingerprint, key.Reason)
		}
	}
	return nil
}

// CheckRevocationCombined checks revocation against both simple list and standalone document.
func CheckRevocationCombined(simpleRevoked []string, doc *RevocationDocument, fingerprint string) error {
	for _, revoked := range simpleRevoked {
		if revoked == fingerprint {
			return fmt.Errorf("key %s is in simple revocation list", fingerprint)
		}
	}

	if doc != nil {
		return CheckRevocation(doc, fingerprint)
	}

	return nil
}

// FetchRevocationDocument fetches a standalone revocation document from an
// https:// URL. Redirects are not followed, the body is capped and the URL
// must use https. Any failure is returned as an error so callers fail closed;
// it never silently yields "no revocations".
func FetchRevocationDocument(ctx context.Context, url string) (*RevocationDocument, error) {
	return FetchRevocationDocumentWithClient(ctx, nil, url)
}

// FetchRevocationDocumentWithClient is FetchRevocationDocument with an explicit
// client (nil means a hardened default with a 10s timeout).
func FetchRevocationDocumentWithClient(ctx context.Context, client *http.Client, url string) (*RevocationDocument, error) {
	if client == nil {
		client = transport.NewClient(10 * time.Second)
	}
	var doc RevocationDocument
	if err := transport.FetchJSON(ctx, client, url, &doc); err != nil {
		return nil, fmt.Errorf("failed to fetch revocation document: %w", err)
	}
	if doc.Domain == "" {
		return nil, fmt.Errorf("failed to fetch revocation document: missing domain")
	}
	return &doc, nil
}
