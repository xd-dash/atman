package tenant

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("TENANTS_JSON", `{"acme":{"service_account_email":"acme-fn@proj.iam.gserviceaccount.com","api_key":"secret"}}`)

	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if got := reg["acme"].ServiceAccountEmail; got != "acme-fn@proj.iam.gserviceaccount.com" {
		t.Fatalf("service account = %q", got)
	}
}

func TestLoad_Empty(t *testing.T) {
	os.Unsetenv("TENANTS_JSON")

	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(reg) != 0 {
		t.Fatalf("reg = %v, want empty", reg)
	}
}

func TestAuthenticate(t *testing.T) {
	reg := Registry{
		"acme": Record{ServiceAccountEmail: "acme-fn@proj.iam.gserviceaccount.com", APIKey: "secret"},
	}

	if _, ok := reg.Authenticate("acme", "wrong"); ok {
		t.Fatal("wrong key authenticated")
	}

	if _, ok := reg.Authenticate("nobody", "secret"); ok {
		t.Fatal("unknown tenant authenticated")
	}

	if _, ok := reg.Authenticate("acme", ""); ok {
		t.Fatal("empty key authenticated")
	}

	rec, ok := reg.Authenticate("acme", "secret")
	if !ok || rec.ServiceAccountEmail != "acme-fn@proj.iam.gserviceaccount.com" {
		t.Fatalf("Authenticate = %+v, %v", rec, ok)
	}
}
