package tenantregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

type MaraiConfig struct {
	Socket       string `json:"socket"`
	User         string `json:"user"`
	PasswordFile string `json:"password_file"`
}

type Tenant struct {
	Audiences []string    `json:"audiences"`
	Callers   []string    `json:"callers"`
	Marai     MaraiConfig `json:"marai"`
}

type Registry struct {
	Tenants map[string]Tenant `json:"tenants"`
}

type Resolved struct {
	TenantID string
	Tenant   Tenant
}

func Load(path string) (*Registry, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("tenant registry path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read tenant registry: %w", err)
	}
	var registry Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("decode tenant registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return nil, err
	}
	return &registry, nil
}

func (r *Registry) Validate() error {
	if r == nil || len(r.Tenants) == 0 {
		return errors.New("tenant registry has no tenants")
	}
	seen := make(map[string]string)
	ids := make([]string, 0, len(r.Tenants))
	for id := range r.Tenants {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		tenant := r.Tenants[id]
		if strings.TrimSpace(id) == "" {
			return errors.New("tenant id is empty")
		}
		if len(tenant.Audiences) == 0 || len(tenant.Callers) == 0 {
			return fmt.Errorf("tenant %q must configure at least one audience and caller", id)
		}
		if strings.TrimSpace(tenant.Marai.Socket) == "" || strings.TrimSpace(tenant.Marai.User) == "" || strings.TrimSpace(tenant.Marai.PasswordFile) == "" {
			return fmt.Errorf("tenant %q has incomplete marai configuration", id)
		}
		for _, audience := range tenant.Audiences {
			if strings.TrimSpace(audience) == "" {
				return fmt.Errorf("tenant %q has an empty audience", id)
			}
			for _, caller := range tenant.Callers {
				if strings.TrimSpace(caller) == "" {
					return fmt.Errorf("tenant %q has an empty caller", id)
				}
				key := audience + "\x00" + caller
				if existing, ok := seen[key]; ok && existing != id {
					return fmt.Errorf("ambiguous tenant mapping for audience %q and caller %q: %q and %q", audience, caller, existing, id)
				}
				seen[key] = id
			}
		}
	}
	return nil
}

func (r *Registry) Resolve(audience, caller string) (Resolved, bool) {
	if r == nil {
		return Resolved{}, false
	}
	for id, tenant := range r.Tenants {
		if contains(tenant.Audiences, audience) && contains(tenant.Callers, caller) {
			return Resolved{TenantID: id, Tenant: tenant}, true
		}
	}
	return Resolved{}, false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
