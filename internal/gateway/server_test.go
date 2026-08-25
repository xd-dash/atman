package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeVerifier struct {
	payload *Payload
	err     error
}

func (v fakeVerifier) Validate(context.Context, string, string) (*Payload, error) {
	return v.payload, v.err
}

type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte("encrypted:"), value...), nil
}
func (fakeKMS) Decrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte("decrypted:"), value...), nil
}
func (fakeKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return []byte("plain"), []byte("wrapped"), nil
}
func (fakeKMS) Ping(context.Context) error { return nil }

func newTestHandler(t *testing.T, verifier Verifier) http.Handler {
	t.Helper()
	handler, err := New(Config{
		Audience:              "https://atman.example",
		AllowedServiceAccount: "tenant@example.iam.gserviceaccount.com",
		MaxBodyBytes:          1024,
	}, verifier, fakeKMS{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func request(t *testing.T, handler http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAuthorization(t *testing.T) {
	allowed := fakeVerifier{payload: &Payload{Claims: map[string]any{
		"email":          "tenant@example.iam.gserviceaccount.com",
		"email_verified": true,
	}}}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`
	if got := request(t, newTestHandler(t, allowed), http.MethodPost, "/v1/keys/key-1/encrypt", "token", body); got.Code != http.StatusOK {
		t.Fatalf("allowed request status=%d body=%s", got.Code, got.Body.String())
	}

	tests := []struct {
		name     string
		verifier Verifier
		token    string
		status   int
	}{
		{"missing token", allowed, "", http.StatusUnauthorized},
		{"invalid token", fakeVerifier{err: errors.New("invalid")}, "bad", http.StatusUnauthorized},
		{"wrong service account", fakeVerifier{payload: &Payload{Claims: map[string]any{
			"email": "other@example.iam.gserviceaccount.com", "email_verified": true,
		}}}, "token", http.StatusForbidden},
		{"unverified email", fakeVerifier{payload: &Payload{Claims: map[string]any{
			"email": "tenant@example.iam.gserviceaccount.com", "email_verified": false,
		}}}, "token", http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := request(t, newTestHandler(t, test.verifier), http.MethodPost, "/v1/keys/key-1/encrypt", test.token, body)
			if got.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", got.Code, test.status, got.Body.String())
			}
		})
	}
}

func TestRequestValidation(t *testing.T) {
	allowed := fakeVerifier{payload: &Payload{Claims: map[string]any{
		"email": "tenant@example.iam.gserviceaccount.com", "email_verified": true,
	}}}
	handler := newTestHandler(t, allowed)
	for _, body := range []string{`{"data":"%%%"}`, `{"data":"YQ==","extra":true}`, `{}`, `not-json`} {
		got := request(t, handler, http.MethodPost, "/v1/keys/key/encrypt", "token", body)
		if got.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d response=%s", body, got.Code, got.Body.String())
		}
	}
}

func TestGenerateDataKey(t *testing.T) {
	allowed := fakeVerifier{payload: &Payload{Claims: map[string]any{
		"email": "tenant@example.iam.gserviceaccount.com", "email_verified": true,
	}}}
	got := request(t, newTestHandler(t, allowed), http.MethodPost, "/v1/keys/key/generate-data-key", "token", "")
	if got.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", got.Code, got.Body.String())
	}
}
