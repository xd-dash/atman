package tenantregistry

import "testing"

func TestResolve(t *testing.T) {
	r := &Registry{Tenants: map[string]Tenant{
		"logma": {
			Audiences: []string{"https://security.internal/logma"},
			Callers:   []string{"logma@dashxd.iam.gserviceaccount.com"},
			Marai: MaraiConfig{
				Socket:       "/run/marai/logma/redis.sock",
				User:         "marai-app",
				PasswordFile: "/run/marai/logma/app.password",
			},
		},
	}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	resolved, ok := r.Resolve("https://security.internal/logma", "logma@dashxd.iam.gserviceaccount.com")
	if !ok || resolved.TenantID != "logma" {
		t.Fatalf("unexpected resolution: %#v ok=%v", resolved, ok)
	}
	if _, ok := r.Resolve("https://security.internal/logma", "other@dashxd.iam.gserviceaccount.com"); ok {
		t.Fatal("unexpected resolution for unauthorized caller")
	}
}

func TestRejectAmbiguousMapping(t *testing.T) {
	marai := MaraiConfig{Socket: "/run/marai/redis.sock", User: "marai-app", PasswordFile: "/run/marai/app.password"}
	r := &Registry{Tenants: map[string]Tenant{
		"a": {Audiences: []string{"aud"}, Callers: []string{"caller"}, Marai: marai},
		"b": {Audiences: []string{"aud"}, Callers: []string{"caller"}, Marai: marai},
	}}
	if err := r.Validate(); err == nil {
		t.Fatal("expected ambiguous registry to fail validation")
	}
}
