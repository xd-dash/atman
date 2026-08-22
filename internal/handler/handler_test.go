package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xd-dash/atman/internal/tenant"
)

type fakeMinter struct {
	accessToken string
	expiresAt   time.Time
	idToken     string
	err         error

	gotTarget    string
	gotDelegates []string
}

func (f *fakeMinter) AccessToken(_ context.Context, target string, _ []string, _ time.Duration, delegates ...string) (string, time.Time, error) {
	f.gotTarget = target
	f.gotDelegates = delegates
	return f.accessToken, f.expiresAt, f.err
}

func (f *fakeMinter) IDToken(_ context.Context, target string, _ string, _ bool, delegates ...string) (string, error) {
	f.gotTarget = target
	f.gotDelegates = delegates
	return f.idToken, f.err
}

func testRegistry() tenant.Registry {
	return tenant.Registry{
		"acme": tenant.Record{ServiceAccountEmail: "acme-fn@proj.iam.gserviceaccount.com", APIKey: "acme-secret"},
	}
}

func TestMintTokenHandler_WrongAPIKey(t *testing.T) {
	mux := newMux(testRegistry(), &fakeMinter{})

	body := strings.NewReader(`{"tenant_id":"acme"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/token", body)
	req.Header.Set("X-API-Key", "not-the-right-key")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMintTokenHandler_UnknownTenant(t *testing.T) {
	mux := newMux(testRegistry(), &fakeMinter{})

	body := strings.NewReader(`{"tenant_id":"nobody"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/token", body)
	req.Header.Set("X-API-Key", "anything")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMintTokenHandler_AccessToken(t *testing.T) {
	expires := time.Now().Add(10 * time.Minute).UTC()
	fm := &fakeMinter{accessToken: "minted-token", expiresAt: expires}
	mux := newMux(testRegistry(), fm)

	body := strings.NewReader(`{"tenant_id":"acme"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/token", body)
	req.Header.Set("X-API-Key", "acme-secret")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if fm.gotTarget != "acme-fn@proj.iam.gserviceaccount.com" {
		t.Fatalf("minted for %q, want the tenant's own service account", fm.gotTarget)
	}

	if len(fm.gotDelegates) != 0 {
		t.Fatalf("gotDelegates = %v, want none (the deployed function runs as the minter itself)", fm.gotDelegates)
	}

	var resp tokenResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Token != "minted-token" || resp.Kind != "access" {
		t.Fatalf("resp = %+v, want token=minted-token kind=access", resp)
	}
}

func TestMintTokenHandler_IDTokenRequiresAudience(t *testing.T) {
	mux := newMux(testRegistry(), &fakeMinter{})

	body := strings.NewReader(`{"tenant_id":"acme","kind":"id"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/token", body)
	req.Header.Set("X-API-Key", "acme-secret")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestHealthz(t *testing.T) {
	mux := newMux(testRegistry(), &fakeMinter{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q, want 200 ok", rec.Code, rec.Body.String())
	}
}
