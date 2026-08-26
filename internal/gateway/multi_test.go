package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

type audienceVerifier struct {
	claimsByAudience map[string]map[string]any
}

func (v audienceVerifier) Validate(_ context.Context, _ string, audience string) (*Payload, error) {
	claims, ok := v.claimsByAudience[audience]
	if !ok {
		return nil, context.Canceled
	}
	return &Payload{Claims: claims}, nil
}

type markingKMS struct{ marker string }

func (m markingKMS) Encrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte(m.marker+":"), value...), nil
}
func (m markingKMS) Decrypt(_ context.Context, _ string, value []byte) ([]byte, error) {
	return append([]byte(m.marker+":"), value...), nil
}
func (m markingKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	return []byte(m.marker), []byte("wrapped"), nil
}
func (markingKMS) Ping(context.Context) error { return nil }

func unsignedJWT(t *testing.T, audience string) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]any{"alg": "none"}) + "." + encode(map[string]any{"aud": audience}) + ".x"
}

func TestMultiTenantRoutingUsesIdentityClaims(t *testing.T) {
	verifier := audienceVerifier{claimsByAudience: map[string]map[string]any{
		"https://security.internal/logma": {
			"email": "logma@dashxd.iam.gserviceaccount.com", "email_verified": true,
		},
		"https://security.internal/agni": {
			"email": "agni@dashxd.iam.gserviceaccount.com", "email_verified": true,
		},
	}}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{
			{TenantID: "logma", Audiences: []string{"https://security.internal/logma"}, Callers: []string{"logma@dashxd.iam.gserviceaccount.com"}, KMS: markingKMS{marker: "logma"}},
			{TenantID: "agni", Audiences: []string{"https://security.internal/agni"}, Callers: []string{"agni@dashxd.iam.gserviceaccount.com"}, KMS: markingKMS{marker: "agni"}},
		},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`
	for _, test := range []struct {
		audience string
		marker   string
	}{
		{"https://security.internal/logma", "logma:secret"},
		{"https://security.internal/agni", "agni:secret"},
	} {
		got := request(t, handler, http.MethodPost, "/v1/keys/key/encrypt", unsignedJWT(t, test.audience), body)
		if got.Code != http.StatusOK {
			t.Fatalf("audience=%s status=%d body=%s", test.audience, got.Code, got.Body.String())
		}
		want := base64.StdEncoding.EncodeToString([]byte(test.marker))
		if !containsString(got.Body.String(), want) {
			t.Fatalf("audience=%s response=%s want encoded marker=%s", test.audience, got.Body.String(), want)
		}
	}
}

func TestMultiTenantCannotSelectTenantByPath(t *testing.T) {
	verifier := audienceVerifier{claimsByAudience: map[string]map[string]any{
		"https://security.internal/logma": {
			"email": "other@dashxd.iam.gserviceaccount.com", "email_verified": true,
		},
	}}
	handler, err := NewMulti(MultiConfig{
		MaxBodyBytes: 1024,
		Routes: []TenantRoute{{
			TenantID: "logma",
			Audiences: []string{"https://security.internal/logma"},
			Callers: []string{"logma@dashxd.iam.gserviceaccount.com"},
			KMS: markingKMS{marker: "logma"},
		}},
	}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"data":"YQ=="}`
	got := request(t, handler, http.MethodPost, "/v1/tenants/logma/keys/key/encrypt", unsignedJWT(t, "https://security.internal/logma"), body)
	if got.Code != http.StatusNotFound {
		t.Fatalf("tenant-selecting path must not exist: status=%d body=%s", got.Code, got.Body.String())
	}
}

func containsString(value, target string) bool {
	for i := 0; i+len(target) <= len(value); i++ {
		if value[i:i+len(target)] == target {
			return true
		}
	}
	return false
}
