// Package handler is the token-minter's HTTP surface: a health check and
// a single POST endpoint tenants call to mint a token for their own
// service account. It never talks to the IAM Credentials API directly -
// it goes through the Minter interface, which internal/mint's real
// implementation satisfies - so tests can substitute a fake instead of
// making live GCP calls.
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xd-dash/atman/internal/mint"
	"github.com/xd-dash/atman/internal/tenant"
)

const (
	// defaultAccessTokenLifetime bounds how long a minted access token is
	// valid for when the caller doesn't ask for a shorter one. Kept short
	// since a tenant is expected to mint one right before use, not cache
	// it for later.
	defaultAccessTokenLifetime = 10 * time.Minute

	// defaultScope is used when a caller requests an access token without
	// specifying scopes - broad enough to be generically useful, narrow
	// enough that it's still the tenant's own service account's IAM
	// grants (not this function's) that ultimately bound what it can do.
	defaultScope = "https://www.googleapis.com/auth/cloud-platform"
)

// Minter is the subset of internal/mint this handler needs.
type Minter interface {
	AccessToken(ctx context.Context, targetServiceAccount string, scopes []string, lifetime time.Duration, delegates ...string) (string, time.Time, error)
	IDToken(ctx context.Context, targetServiceAccount, audience string, includeEmail bool, delegates ...string) (string, error)
}

// liveMinter calls the real IAM Credentials API via internal/mint. The
// deployed function always runs as the token-minter service account
// itself (terraform/token-minter sets service_config.service_account_email
// to it), so it mints directly against a tenant's service account with
// no delegate chain - unlike cmd/mint-token, which typically runs as a
// different identity that has to delegate through the minter.
type liveMinter struct{}

func (liveMinter) AccessToken(ctx context.Context, sa string, scopes []string, lifetime time.Duration, delegates ...string) (string, time.Time, error) {
	return mint.AccessToken(ctx, sa, scopes, lifetime, delegates...)
}

func (liveMinter) IDToken(ctx context.Context, sa, audience string, includeEmail bool, delegates ...string) (string, error) {
	return mint.IDToken(ctx, sa, audience, includeEmail, delegates...)
}

type tokenRequest struct {
	TenantID     string   `json:"tenant_id"`
	Kind         string   `json:"kind"` // "access" (default) or "id"
	Scopes       []string `json:"scopes"`
	Audience     string   `json:"audience"`
	IncludeEmail bool     `json:"include_email"`
}

type tokenResponse struct {
	Token          string    `json:"token"`
	Kind           string    `json:"kind"`
	ServiceAccount string    `json:"service_account"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// New builds the token-minter's http.Handler, wired to the real IAM
// Credentials API and the tenant registry loaded from TENANTS_JSON.
func New() http.Handler {
	reg, err := tenant.Load()
	if err != nil {
		// A malformed TENANTS_JSON is a deploy-time configuration error,
		// not a per-request one - fail loudly at cold start rather than
		// serve a handler that can never authenticate any tenant.
		panic(err)
	}

	return newMux(reg, liveMinter{})
}

func newMux(reg tenant.Registry, m Minter) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /v1/token", mintTokenHandler(reg, m))

	return mux
}

func mintTokenHandler(reg tenant.Registry, m Minter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		rec, ok := reg.Authenticate(req.TenantID, r.Header.Get("X-API-Key"))
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		switch req.Kind {
		case "", "access":
			scopes := req.Scopes
			if len(scopes) == 0 {
				scopes = []string{defaultScope}
			}

			token, expiresAt, err := m.AccessToken(r.Context(), rec.ServiceAccountEmail, scopes, defaultAccessTokenLifetime)
			if err != nil {
				http.Error(w, "mint failed", http.StatusBadGateway)
				return
			}

			writeJSON(w, tokenResponse{
				Token:          token,
				Kind:           "access",
				ServiceAccount: rec.ServiceAccountEmail,
				ExpiresAt:      expiresAt,
			})

		case "id":
			if req.Audience == "" {
				http.Error(w, `"audience" is required when kind is "id"`, http.StatusBadRequest)
				return
			}

			token, err := m.IDToken(r.Context(), rec.ServiceAccountEmail, req.Audience, req.IncludeEmail)
			if err != nil {
				http.Error(w, "mint failed", http.StatusBadGateway)
				return
			}

			writeJSON(w, tokenResponse{
				Token:          token,
				Kind:           "id",
				ServiceAccount: rec.ServiceAccountEmail,
			})

		default:
			http.Error(w, `"kind" must be "access" or "id"`, http.StatusBadRequest)
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
