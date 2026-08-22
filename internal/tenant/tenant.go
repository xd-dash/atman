// Package tenant resolves an inbound request to the GCP service account
// it's allowed to mint tokens for, and authenticates it. Loaded once at
// cold start from a single env var (TENANTS_JSON, set by
// terraform/token-minter from its `tenants` variable) so a request never
// needs to reach outside the function to figure out who it's talking
// to - this is what keeps a tenant's coupling to this project down to
// exactly one map entry.
package tenant

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
)

// Record is one tenant's configuration.
type Record struct {
	// ServiceAccountEmail is the GCP service account this tenant's Cloud
	// Function(s) run as. The token-minter service account must hold
	// roles/iam.serviceAccountTokenCreator on it (terraform/token-minter
	// sets this up per-tenant) for minting to succeed.
	ServiceAccountEmail string `json:"service_account_email"`

	// APIKey is the shared secret this tenant's caller must present (as
	// the X-API-Key header) to mint a token on this tenant's behalf.
	APIKey string `json:"api_key"`
}

// Registry looks up tenants by ID.
type Registry map[string]Record

// Load parses TENANTS_JSON into a Registry. An unset/empty env var
// yields an empty (rather than nil) Registry, so every tenant lookup
// simply misses instead of the handler needing a separate nil check.
func Load() (Registry, error) {
	raw := os.Getenv("TENANTS_JSON")
	if raw == "" {
		return Registry{}, nil
	}

	var reg Registry
	if err := json.Unmarshal([]byte(raw), &reg); err != nil {
		return nil, fmt.Errorf("tenant: parse TENANTS_JSON: %w", err)
	}

	return reg, nil
}

// Authenticate looks up id and compares apiKey against its stored key in
// constant time, returning the tenant's Record only when both the
// tenant exists and the key matches. A missing/empty apiKey never
// matches, even for a tenant record with an empty APIKey.
func (r Registry) Authenticate(id, apiKey string) (Record, bool) {
	rec, ok := r[id]
	if !ok || apiKey == "" || rec.APIKey == "" {
		return Record{}, false
	}

	if subtle.ConstantTimeCompare([]byte(rec.APIKey), []byte(apiKey)) != 1 {
		return Record{}, false
	}

	return rec, true
}
